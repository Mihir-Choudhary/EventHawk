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


_SESSION_PREFIX = "evtx_jm_session_"


def _remove_orphan_session_dirs() -> None:
    """Remove Juggernaut data folders left by an EventHawk that no longer runs.

    A folder is named evtx_jm_session_<process id>_<random>.  Only a folder
    whose process is gone is removed; without psutil nothing is removed.
    """
    try:
        import psutil
    except ImportError:
        return
    tmp = tempfile.gettempdir()
    try:
        names = os.listdir(tmp)
    except OSError:
        return
    for name in names:
        if not name.startswith(_SESSION_PREFIX):
            continue
        pid = name[len(_SESSION_PREFIX):].split("_", 1)[0]
        if not pid.isdigit() or psutil.pid_exists(int(pid)):
            continue
        shutil.rmtree(os.path.join(tmp, name), ignore_errors=True)


class HeavyweightParseWorker(QThread):
    """Run HeavyweightEngine on a background thread."""

    progress = Signal(int, int, int, float)   # done_files, total_files, done_events, eps
    finished = Signal(str)                     # parquet_dir path
    error    = Signal(str)
    # Emitted instead of finished when the run was stopped.  Without it a
    # stopped parse ended in silence: nothing re-enabled Parse or closed the
    # wait dialog (Codex audit-5b A5B-CANCEL).
    cancelled = Signal()

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
        self.parse_stats: dict = {}   # per-source integrity counters (read after finished)

    def run(self) -> None:
        pq_dir = None
        try:
            from evtx_tool.core.heavyweight.engine import HeavyweightEngine
            import logging as _logging
            _log = _logging.getLogger(__name__)

            # A folder of its own for every parse.  One fixed folder, deleted
            # at the start of each parse, let a second EventHawk window delete
            # the first window's shards and write its own under the same
            # names: the first window then read the other case's events
            # (audit SA-1).  The window deletes the folder when it leaves
            # Juggernaut mode; what a crashed EventHawk left is removed here.
            _remove_orphan_session_dirs()
            pq_dir = tempfile.mkdtemp(prefix=f"{_SESSION_PREFIX}{os.getpid()}_")

            self._engine = HeavyweightEngine(
                parquet_dir=pq_dir,
                on_progress=self._emit_progress,
            )

            result = self._engine.run(self._files, self._filter_config)
            self.parse_stats = getattr(self._engine, "last_parse_stats", {}) or {}
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

            if self._stop_event.is_set():
                # Nobody uses a stopped parse's folder.
                shutil.rmtree(pq_dir, ignore_errors=True)
                self.cancelled.emit()
            else:
                self.finished.emit(result)
        except Exception as exc:
            if pq_dir:
                shutil.rmtree(pq_dir, ignore_errors=True)
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
