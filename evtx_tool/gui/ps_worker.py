"""
PSWorker — Qt QThread wrapper around PSExtractor.

Runs PowerShell forensic extraction in a background thread so the GUI
stays responsive. Emits progress updates and a final summary dict.

L3: Records are streamed directly to PSExtractor via a generator — no
full list is built in memory. Peak RAM is bounded by the PS-relevant
records only (typically <1% of all records in a large EVTX set).
"""

from __future__ import annotations

import logging
import os
import traceback
from pathlib import Path
from typing import Generator

from PySide6.QtCore import QThread, Signal

logger = logging.getLogger(__name__)


class PSWorker(QThread):
    """
    Background worker for PowerShell forensic artifact extraction.

    Signals:
        progress(step: str, pct: float)
            step — human-readable description of current operation
            pct  — 0.0 to 1.0 during extraction; negative during file loading
                   (GUI should show indeterminate indicator when pct < 0)
        extraction_done(summary: dict)
            summary dict from PSExtractor.run() with keys:
              total_scanned, total_ps_events, script_blocks,
              sessions, partial_blocks, safety_net, parse_errors
        extraction_error(traceback_str: str)
            Emitted on any unhandled exception; contains full traceback.

    NOTE: Signal names deliberately avoid ``finished`` and ``error`` to
    prevent shadowing QThread.finished() which Qt emits internally when
    run() returns.  Shadowing it would break thread-lifecycle cleanup.
    """

    progress = Signal(str, float)
    extraction_done = Signal(dict)
    extraction_error = Signal(str)

    def __init__(
        self,
        evtx_files: list[str],
        output_dir: str,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._files = list(evtx_files)
        self._output_dir = Path(output_dir)
        self._cancelled = False

    # ── Cancellation API ──────────────────────────────────────────────────

    def request_cancel(self) -> None:
        """Request graceful cancellation (checked between loop iterations)."""
        self._cancelled = True

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    # ── Thread entry point ────────────────────────────────────────────────

    def run(self) -> None:
        try:
            from evtx import PyEvtxParser  # type: ignore

            from evtx_tool.analysis.ps_extractor.extractor import PSExtractor

            total_files = len(self._files)

            # L3: Build a generator that streams records from all files.
            # This avoids loading all records into a list before processing.
            def _record_stream() -> Generator[dict, None, None]:
                for i, fpath in enumerate(self._files):
                    if self._cancelled:
                        return
                    basename = os.path.basename(fpath)
                    self.progress.emit(
                        f"Reading {basename} ({i + 1}/{total_files})...",
                        -0.05,  # sub-zero = indeterminate progress bar
                    )
                    try:
                        parser = PyEvtxParser(fpath)
                        for rec in parser.records_json():
                            if self._cancelled:
                                return
                            # Tag each record with its source file so the extractor
                            # can track which files actually contained PS events.
                            rec["_source_file"] = fpath
                            yield rec
                    except Exception as exc:
                        logger.warning("Could not read %s: %s", fpath, exc)

            # ── Phase 2: run extraction pipeline ────────────────────────────
            extractor = PSExtractor(
                records=_record_stream(),
                output_dir=self._output_dir,
                source_files=self._files,
                total_hint=0,   # no count known upfront with streaming
            )
            extractor.progress_callback = lambda s, p: self.progress.emit(s, p)
            extractor.cancel_check = lambda: self._cancelled
            summary = extractor.run()

            if self._cancelled and not summary.get("cancelled"):
                summary["cancelled"] = True

            self.extraction_done.emit(summary)

        except Exception:
            tb = traceback.format_exc()
            logger.error("PSWorker unhandled exception:\n%s", tb)
            self.extraction_error.emit(tb)
