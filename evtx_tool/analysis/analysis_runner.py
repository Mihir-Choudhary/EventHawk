"""
AnalysisRunner — GUI-side manager that runs analysis in an isolated subprocess.

Drop-in replacement for ``AnalysisWorker(QThread)``.  Same signals::

    progress(str)                      # step name
    finished(object, object, object)   # iocs, chains, metadata
    error(str)                         # error message

Internals
---------
- Serializes events → ``SharedMemory`` (zero-copy via orjson bytes)
- Spawns ``mp.Process`` targeting ``analysis_worker_proc.run_analysis``
- ``QTimer(100 ms)`` polls progress / result queues (never blocks the GUI)
- Falls back to in-process ``AnalysisWorker(QThread)`` if spawn fails
"""

from __future__ import annotations

import logging
import multiprocessing as mp
from multiprocessing.shared_memory import SharedMemory
from queue import Empty

from PySide6.QtCore import QObject, QTimer, Signal, Slot

logger = logging.getLogger(__name__)

# How often the GUI polls the IPC queues (milliseconds).
_POLL_INTERVAL_MS = 100

# Grace period (seconds) after cancel before force-terminating the worker.
_CANCEL_GRACE_SEC = 5.0

# Watchdog: if no progress for this many seconds, declare the worker hung.
_WATCHDOG_TIMEOUT_SEC = 300.0  # 5 minutes


class AnalysisRunner(QObject):
    """
    Drop-in replacement for ``AnalysisWorker`` — runs analysis in a subprocess.

    The signal interface is identical to ``AnalysisWorker``::

        progress  = Signal(str)                      # step name
        finished  = Signal(object, object, object)   # iocs, chains, metadata
        error     = Signal(str)                      # error message

    Usage from ``main_window.py``::

        runner = AnalysisRunner(parent=self)
        runner.progress.connect(self._on_analysis_progress)
        runner.finished.connect(self._on_analysis_finished)
        runner.error.connect(self._on_analysis_error)
        runner.start(events, do_ioc=True, do_correlate=True)
    """

    progress = Signal(str)
    component_progress = Signal(str, int)  # (component_name, pct)
    finished = Signal(object, object, object)
    error    = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._process: mp.Process | None = None
        self._progress_q: mp.Queue | None = None
        self._result_q: mp.Queue | None = None
        self._cancel_event: mp.Event | None = None
        self._shm: SharedMemory | None = None
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(_POLL_INTERVAL_MS)
        self._poll_timer.timeout.connect(self._poll)
        self._cancel_requested = False
        self._cancel_ts: float = 0.0
        self._last_progress_ts: float = 0.0

        # In-process fallback (kept alive while running)
        self._fallback_worker = None

    # ── Public API ────────────────────────────────────────────────────────

    def start(
        self,
        events: list[dict],
        do_ioc: bool = False,
        do_correlate: bool = False,
        do_hayabusa: bool = False,
        hayabusa_path: str | None = None,
        evtx_paths: list[str] | None = None,
    ) -> None:
        """Serialize events and spawn the worker subprocess."""
        try:
            self._start_subprocess(
                events, do_ioc, do_correlate, do_hayabusa,
                hayabusa_path, evtx_paths,
            )
        except Exception as exc:
            logger.warning(
                "Subprocess spawn failed (%s), falling back to in-process", exc,
            )
            self._start_inprocess_fallback(
                events, do_ioc, do_correlate,
            )

    def request_stop(self) -> None:
        """Request the worker to stop.  Force-terminates after grace period."""
        if self._fallback_worker is not None:
            self._fallback_worker.request_stop()
            return

        if self._cancel_event is not None:
            self._cancel_event.set()

        import time
        self._cancel_requested = True
        self._cancel_ts = time.monotonic()

    def is_running(self) -> bool:
        """Return True if the worker subprocess (or fallback) is still active."""
        if self._fallback_worker is not None:
            return self._fallback_worker.isRunning()
        return self._process is not None and self._process.is_alive()

    # ── Subprocess launch ─────────────────────────────────────────────────

    def _start_subprocess(
        self,
        events: list[dict],
        do_ioc: bool,
        do_correlate: bool,
        do_hayabusa: bool,
        hayabusa_path: str | None,
        evtx_paths: list[str] | None,
    ) -> None:
        """Serialize events → SharedMemory, spawn mp.Process."""
        import time
        from evtx_tool.core._json_compat import fast_dumps_bytes

        # 1. Serialize events to bytes
        data_bytes = fast_dumps_bytes(events)

        # 2. Create SharedMemory and copy data in
        self._shm = SharedMemory(create=True, size=len(data_bytes))
        self._shm.buf[:len(data_bytes)] = data_bytes
        shm_name = self._shm.name
        data_size = len(data_bytes)
        del data_bytes  # Free the temporary copy

        # 3-4. Create IPC + spawn — wrapped so SharedMemory is cleaned up
        #      if Process.start() fails (e.g. resource exhaustion, fork error)
        try:
            self._progress_q = mp.Queue()
            self._result_q = mp.Queue()
            self._cancel_event = mp.Event()

            from evtx_tool.analysis.analysis_worker_proc import run_analysis

            self._process = mp.Process(
                target=run_analysis,
                args=(
                    shm_name, data_size,
                    self._progress_q, self._result_q, self._cancel_event,
                    do_ioc, do_correlate, do_hayabusa,
                    hayabusa_path, evtx_paths,
                ),
                daemon=True,
            )
            self._process.start()
        except Exception:
            self._cleanup()  # Free SharedMemory + queues on failure
            raise

        # 5. Start polling
        self._cancel_requested = False
        self._last_progress_ts = time.monotonic()
        self._poll_timer.start()

    # ── QTimer poll callback ──────────────────────────────────────────────

    @Slot()
    def _poll(self) -> None:
        """
        Called every 100 ms by QTimer.  Non-blocking drain of IPC queues
        + process health check.  Never blocks the Qt event loop.
        """
        import time

        # 1. Drain progress queue (non-blocking)
        while True:
            try:
                msg = self._progress_q.get_nowait()
            except Empty:
                break

            msg_type = msg.get("type", "")
            if msg_type == "progress":
                self._last_progress_ts = time.monotonic()
                step_text = msg.get("step", "")
                pct = msg.get("pct")
                if pct is not None:
                    step_text = f"{step_text}  ({pct}%)"
                self.progress.emit(step_text)
            elif msg_type == "component_progress":
                self._last_progress_ts = time.monotonic()
                comp_name = msg.get("component", "")
                comp_pct = msg.get("pct", 0)
                self.component_progress.emit(comp_name, comp_pct)
            elif msg_type == "data_loaded":
                self._last_progress_ts = time.monotonic()
                self._cleanup_shm()  # Worker has its own copy now
            elif msg_type == "error":
                self._poll_timer.stop()
                self.error.emit(msg.get("message", "Unknown worker error"))
                self._cleanup()
                return

        # 2. Check result queue
        try:
            result = self._result_q.get_nowait()
        except Empty:
            result = None

        if result is not None:
            self._poll_timer.stop()
            self.finished.emit(
                result.get("iocs"),
                result.get("chains", []),
                result.get("metadata", {}),
            )
            self._cleanup()
            return

        # 3. Health check — detect worker crash
        if self._process is not None and not self._process.is_alive():
            exitcode = self._process.exitcode
            self._poll_timer.stop()
            if exitcode == 0:
                # Worker exited cleanly but didn't send a result (cancelled?)
                if not self._cancel_requested:
                    self.error.emit("Worker exited without sending results")
            else:
                self.error.emit(f"Worker crashed (exit code {exitcode})")
            self._cleanup()
            return

        # 4. Cancel + grace period
        if self._cancel_requested:
            elapsed = time.monotonic() - self._cancel_ts
            if elapsed > _CANCEL_GRACE_SEC:
                logger.warning("Worker did not stop within %ss — terminating", _CANCEL_GRACE_SEC)
                if self._process is not None:
                    self._process.terminate()
                self._poll_timer.stop()
                self.error.emit("Analysis cancelled (worker terminated)")
                self._cleanup()
                return

        # 5. Watchdog — detect hung worker
        if not self._cancel_requested:
            idle = time.monotonic() - self._last_progress_ts
            if idle > _WATCHDOG_TIMEOUT_SEC:
                logger.warning("Worker unresponsive for %ss — terminating", _WATCHDOG_TIMEOUT_SEC)
                if self._process is not None:
                    self._process.terminate()
                self._poll_timer.stop()
                self.error.emit("Worker timed out (no progress for 5 minutes)")
                self._cleanup()
                return

    # ── Cleanup ───────────────────────────────────────────────────────────

    def _cleanup_shm(self) -> None:
        """Release SharedMemory (worker has its own copy now)."""
        if self._shm is not None:
            try:
                self._shm.close()
                self._shm.unlink()
            except Exception:
                pass
            self._shm = None

    def _cleanup(self) -> None:
        """Full cleanup: SharedMemory + process + queues."""
        self._poll_timer.stop()
        self._cleanup_shm()

        if self._process is not None:
            try:
                self._process.join(timeout=2.0)
            except Exception:
                pass
            self._process = None

        # Close queues (prevent resource leaks on Windows)
        for q in (self._progress_q, self._result_q):
            if q is not None:
                try:
                    q.close()
                    q.join_thread()
                except Exception:
                    pass
        self._progress_q = None
        self._result_q = None
        self._cancel_event = None

    # ── In-process fallback ───────────────────────────────────────────────

    def _start_inprocess_fallback(
        self,
        events: list[dict],
        do_ioc: bool,
        do_correlate: bool,
    ) -> None:
        """Fall back to the existing AnalysisWorker(QThread) if subprocess fails."""
        from evtx_tool.gui.worker import AnalysisWorker

        self._fallback_worker = AnalysisWorker(
            events=events,
            do_ioc=do_ioc,
            do_correlate=do_correlate,
        )
        self._fallback_worker.progress.connect(self.progress)
        self._fallback_worker.finished.connect(self._on_fallback_finished)
        self._fallback_worker.error.connect(self.error)
        self._fallback_worker.start()

    @Slot(object, object, object)
    def _on_fallback_finished(self, iocs, chains, metadata) -> None:
        """Relay the fallback worker's finished signal."""
        self._fallback_worker = None
        self.finished.emit(iocs, chains, metadata)
