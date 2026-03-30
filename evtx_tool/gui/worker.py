"""
ParseWorker + AnalysisWorker — two-phase pipeline for responsive GUI.

Architecture:
  Main thread (Qt event loop)
      ├── ParseWorker(QThread)          ← Phase 1: parse + sort + ATT&CK
      │       └── engine.run()          ← blocks, uses ProcessPoolExecutor
      │       → events appear in table IMMEDIATELY
      │
      └── AnalysisWorker(QThread)       ← Phase 2: IOC + Correlate + Metadata
              → tabs update when done

Signals are emitted from QThreads and automatically queued to the main
thread by Qt's signal/slot mechanism — 100% thread-safe, GUI stays responsive.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

from PySide6.QtCore import QThread, Signal


class ParseWorker(QThread):
    """
    Phase 1: Parse files + sort + ATT&CK enrichment.

    Emits events as soon as they are ready for display.
    IOC / Correlation / Metadata are handled by AnalysisWorker.

    Signals
    -------
    progress(state_dict)
        Emitted after each file completes.
    finished(events, attack_summary, do_ioc, do_correlate, search_cache)
        Emitted when parse + ATT&CK are done. Events ready for display.
    error(message)
        Emitted on unrecoverable exception.
    """

    progress = Signal(object)
    finished = Signal(object, object, object, object, object)
    error    = Signal(str)

    def __init__(
        self,
        files:          list[str],
        filter_config:  dict,
        do_attack:      bool = True,
        do_ioc:         bool = False,
        do_correlate:   bool = False,
        max_workers:    int | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._files         = files
        self._filter_config = filter_config
        self._do_attack     = do_attack
        self._do_ioc        = do_ioc
        self._do_correlate  = do_correlate
        self._max_workers   = max_workers
        self._stop_event    = threading.Event()
        self._engine        = None

    def run(self) -> None:
        try:
            self._run_pipeline()
        except Exception as exc:
            self.error.emit(str(exc))

    def _run_pipeline(self) -> None:
        pkg_root = str(Path(__file__).resolve().parents[2])
        if pkg_root not in sys.path:
            sys.path.insert(0, pkg_root)

        from evtx_tool.core.engine import ProcessingEngine

        engine = ProcessingEngine(max_workers=self._max_workers)
        self._engine = engine

        def _on_progress(state):
            if not self._stop_event.is_set():
                self.progress.emit(state.snapshot() if hasattr(state, "snapshot") else state)

        engine._on_progress = _on_progress

        # ── 1. Parse ──────────────────────────────────────────────────────────
        events: list[dict] = engine.run(self._files, self._filter_config)

        if self._stop_event.is_set():
            self.finished.emit(events, None, False, False, [])
            return

        # ── 2. Sort by timestamp ──────────────────────────────────────────────
        if events:
            events.sort(key=lambda e: e.get("timestamp", ""))

        # ── 3. ATT&CK enrichment (fast O(n), mutates events in-place) ────────
        # FINDING-16: use enrich_and_summarize() — single O(n) pass that both
        # adds attack_tags to each event AND builds the summary dict, replacing
        # the old two-call pattern (enrich_with_attack + build_attack_summary).
        attack_summary = None
        if self._do_attack and not self._stop_event.is_set():
            try:
                from evtx_tool.analysis.attack_mapping import enrich_and_summarize
                attack_summary = enrich_and_summarize(events)
            except Exception:
                pass

        # ── 4.5. Semantic normalization (non-destructive _desc keys) ─────────
        # Translates raw hex/int codes to human-readable descriptions.
        # Runs AFTER ATT&CK so correlation rules see the same raw values they
        # were written against.  Adds only new *_desc keys — never mutates raw.
        if events and not self._stop_event.is_set():
            try:
                from evtx_tool.analysis.normalizer import SemanticNormalizer
                SemanticNormalizer.get().enrich_events(events)
            except Exception:
                pass

        # ── 5. Build search cache (runs in THIS thread, not GUI thread) ──────
        # Perf: building 400K search strings takes ~5s. Doing it here keeps
        # the GUI responsive. The cache is passed to set_events().
        search_cache: list[str] = []
        if events and not self._stop_event.is_set():
            from evtx_tool.gui.models import EventTableModel
            search_cache = [EventTableModel._build_search_str(ev) for ev in events]

        # Emit immediately — events are ready for display!
        # Pass flags so MainWindow knows whether to launch AnalysisWorker.
        self.finished.emit(
            events, attack_summary,
            self._do_ioc, self._do_correlate,
            search_cache,
        )

    def request_stop(self) -> None:
        """Signal the worker to abort as soon as possible."""
        self._stop_event.set()
        if self._engine is not None:
            try:
                self._engine.stop_event.set()
            except AttributeError:
                pass


class AnalysisWorker(QThread):
    """
    Phase 2: Run heavy analysis (IOC, Correlation, Metadata) in background.

    Events are already displayed in the table — this populates the
    analysis tabs when done.

    Signals
    -------
    progress(step_name)
        Emitted when starting each analysis step.
    finished(iocs, chains, metadata)
        Emitted when all analysis is complete.
    error(message)
        Emitted on unrecoverable exception.
    """

    progress = Signal(str)                       # step name
    finished = Signal(object, object, object)    # iocs, chains, metadata
    error    = Signal(str)

    def __init__(
        self,
        events:       list[dict],
        do_ioc:       bool = False,
        do_correlate: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._events       = events
        self._do_ioc       = do_ioc
        self._do_correlate = do_correlate
        self._stop_event   = threading.Event()

    def run(self) -> None:
        try:
            self._run_analysis()
        except Exception as exc:
            self.error.emit(str(exc))

    def _run_analysis(self) -> None:
        pkg_root = str(Path(__file__).resolve().parents[2])
        if pkg_root not in sys.path:
            sys.path.insert(0, pkg_root)

        iocs:     dict | None = None
        chains:   list        = []
        metadata: dict        = {}

        # ── Metadata (fast, needed for column filter dropdowns) ───────────────
        if not self._stop_event.is_set():
            self.progress.emit("Building metadata…")
            try:
                from evtx_tool.gui.metadata import build_metadata
                metadata = build_metadata(self._events)
            except Exception:
                pass

        # ── IOC Extraction ────────────────────────────────────────────────────
        if self._do_ioc and not self._stop_event.is_set():
            self.progress.emit("Extracting IOCs…")
            try:
                from evtx_tool.analysis.ioc_extractor import extract_iocs
                iocs = extract_iocs(self._events)
            except Exception:
                pass

        # ── Correlation ───────────────────────────────────────────────────────
        if self._do_correlate and not self._stop_event.is_set():
            self.progress.emit("Running correlation rules…")
            try:
                from evtx_tool.analysis.correlator import correlate
                chains = correlate(self._events)
            except Exception:
                pass

        if not self._stop_event.is_set():
            self.finished.emit(iocs, chains, metadata)

    def request_stop(self) -> None:
        """Signal the analysis worker to abort."""
        self._stop_event.set()
