"""
HeavyweightParseWorker — QThread wrapper for HeavyweightEngine (Blueprint v2).

Signal interface mirrors the existing ParseWorker so the main window can
reuse the same progress/status bar logic.

Key change vs. SQLite version: finished now emits a parquet_dir string (str),
not a db_path.  The main thread opens its own DuckDB connection from that
directory — eliminating any thread-affinity issues.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import threading

from PySide6.QtCore import QThread, Signal


class HeavyweightParseWorker(QThread):
    """Run HeavyweightEngine on a background thread."""

    progress = Signal(int, int, int, float)   # done_files, total_files, done_events, eps
    finished = Signal(str)                     # parquet_dir path
    error    = Signal(str)

    def __init__(
        self,
        files: list[str],
        filter_config: dict | None = None,
        total_size_mb: int = 0,   # kept for API compatibility, no longer used
        parent=None,
    ):
        super().__init__(parent)
        self._files        = files
        self._filter_config = filter_config
        self._stop_event   = threading.Event()
        self._engine       = None

    def run(self) -> None:
        try:
            from evtx_tool.core.heavyweight.engine import HeavyweightEngine
            import logging as _logging
            _log = _logging.getLogger(__name__)

            # Create a fresh session parquet directory each run.
            # Stale directories from a previous run are removed first.
            pq_dir = os.path.join(tempfile.gettempdir(), "evtx_jm_session")
            if os.path.isdir(pq_dir):
                try:
                    shutil.rmtree(pq_dir)
                except Exception as exc:
                    _log.warning("Could not remove stale session dir %s: %s", pq_dir, exc)

            os.makedirs(pq_dir, exist_ok=True)

            self._engine = HeavyweightEngine(
                parquet_dir=pq_dir,
                on_progress=self._emit_progress,
            )

            result = self._engine.run(self._files, self._filter_config)
            self._engine = None

            # ── Post-run verification ─────────────────────────────────────
            manifest_file = os.path.join(result, "parquet_manifest.json")
            if result and os.path.isdir(result) and os.path.isfile(manifest_file):
                try:
                    import json as _json
                    with open(manifest_file, "r", encoding="utf-8") as _mf:
                        _shards = _json.load(_mf)
                    _log.info(
                        "HeavyweightParseWorker: manifest lists %d shard(s) in %s",
                        len(_shards), result,
                    )
                except Exception as exc:
                    _log.warning("HeavyweightParseWorker: manifest read failed: %s", exc)
            else:
                _log.warning(
                    "HeavyweightParseWorker: engine returned parquet_dir=%r "
                    "but parquet_manifest.json does not exist", result,
                )

            if not self._stop_event.is_set():
                self.finished.emit(result)
        except Exception as exc:
            if self._engine is not None:
                try:
                    self._engine.stop()
                except Exception:
                    pass
                self._engine = None
            self.error.emit(str(exc))

    def _emit_progress(
        self, done_files: int, total_files: int, done_events: int, eps: float
    ) -> None:
        if not self._stop_event.is_set():
            self.progress.emit(done_files, total_files, done_events, eps)

    def request_stop(self) -> None:
        self._stop_event.set()
        if self._engine:
            self._engine.stop()
