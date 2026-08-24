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

import logging
import os
import sys
import threading
import time
import traceback
from pathlib import Path

from PySide6.QtCore import QThread, Signal

logger = logging.getLogger(__name__)


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
        self.parse_warnings: list[str] = []   # engine integrity warnings (read after finished)
        # Subset of parse_warnings the engine tagged as NOT evidence loss
        # (throttling / RAM / Ctrl+C).  Everything else must reach the examiner.
        self.parse_benign_warnings: list[str] = []
        self.parse_errors: list[str] = []     # engine fatal errors (surfaced via error signal)

    def run(self) -> None:
        try:
            self._run_pipeline()
        except Exception:
            tb = traceback.format_exc()
            logger.exception("ParseWorker pipeline failed")
            self.error.emit(tb)

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
        try:
            self.parse_warnings = list(engine.state.warnings)
        except Exception:
            self.parse_warnings = []
        try:
            self.parse_benign_warnings = list(
                getattr(engine.state, "benign_warnings", []) or [])
        except Exception:
            # Fail LOUD: if the benign list cannot be read, classify nothing as
            # benign so every warning is shown rather than silently filtered.
            self.parse_benign_warnings = []
        try:
            self.parse_errors = list(engine.state.errors)
        except Exception:
            self.parse_errors = []

        if self._stop_event.is_set():
            self.finished.emit(events, None, False, False, [])
            return

        # ── Hard engine failure → surface it, don't emit an empty result ─────
        # The engine reports a fatal condition (e.g. "ProcessPool permanently
        # broken" — seen when the app is launched via a windowed pythonw.exe
        # with no console and the normal-mode ProcessPoolExecutor can't spawn
        # workers) by populating state.errors and returning []. Previously the
        # worker forwarded only state.warnings and emitted finished([]), so a
        # failed parse was indistinguishable from "0 matching events": no
        # dialog, no crash, nothing — exactly the silent failure users hit on a
        # single small file (the first time the normal-mode path is exercised).
        # Route real errors to error() so _on_parse_error shows a dialog.
        if self.parse_errors and not events:
            self.error.emit(
                "Parsing failed — no events were produced.\n\n"
                + "\n".join(self.parse_errors[:15])
                + ("\n…" if len(self.parse_errors) > 15 else "")
                + "\n\nSee eventhawk_gui.log for details."
            )
            return

        # ── 2. Sort by timestamp ──────────────────────────────────────────────
        if events:
            # Multi-key: timestamp, then source_file, then record_id — makes
            # same-timestamp ordering deterministic and reproducible across runs
            # (worker completion order previously leaked into display order).
            events.sort(
                key=lambda e: (
                    e.get("timestamp", "") or "",
                    e.get("source_file", "") or "",
                    e.get("record_id", 0) or 0,
                )
            )

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
                logger.warning("ATT&CK enrichment failed", exc_info=True)

        # ── 4.5. Semantic normalization (non-destructive _desc keys) ─────────
        # Translates raw hex/int codes to human-readable descriptions.
        # Runs AFTER ATT&CK so correlation rules see the same raw values they
        # were written against.  Adds only new *_desc keys — never mutates raw.
        if events and not self._stop_event.is_set():
            try:
                from evtx_tool.analysis.normalizer import SemanticNormalizer
                SemanticNormalizer.get().enrich_events(events)
            except Exception:
                logger.warning("Semantic normalization failed", exc_info=True)

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
        except Exception:
            tb = traceback.format_exc()
            logger.exception("AnalysisWorker pipeline failed")
            self.error.emit(tb)

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
                logger.warning("Metadata build failed", exc_info=True)

        # ── IOC Extraction ────────────────────────────────────────────────────
        if self._do_ioc and not self._stop_event.is_set():
            self.progress.emit("Extracting IOCs…")
            try:
                from evtx_tool.analysis.ioc_extractor import extract_iocs
                iocs = extract_iocs(self._events)
            except Exception:
                logger.warning("IOC extraction failed", exc_info=True)

        # ── Correlation ───────────────────────────────────────────────────────
        if self._do_correlate and not self._stop_event.is_set():
            self.progress.emit("Running correlation rules…")
            try:
                from evtx_tool.analysis.correlator import correlate
                chains = correlate(self._events)
            except Exception:
                logger.warning("Correlation failed", exc_info=True)

        if not self._stop_event.is_set():
            self.finished.emit(iocs, chains, metadata)

    def request_stop(self) -> None:
        """Signal the analysis worker to abort."""
        self._stop_event.set()
