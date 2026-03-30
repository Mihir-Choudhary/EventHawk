"""
Processing engine — orchestrates multi-process EVTX parsing with resource safety.

Architecture:
  - ProcessPoolExecutor (default: CPU-1 workers, user-configurable)
  - Semaphore-based submission backpressure (2x worker count queue depth)
  - ResourceMonitor daemon thread: throttles on CPU>85% for 3 polls
  - Per-file worker: parse + filter inline → returns only matching events
  - BrokenProcessPool recovery: recreate executor and continue
  - Graceful shutdown: Ctrl+C sets stop_event → cancel futures → cleanup

Worker function (_worker_parse_file) is module-level for pickle compatibility.
Uses initializer to set sys.path in each worker process (Windows spawn method).
"""

from __future__ import annotations

import gc
import logging
import os
import signal
import sys
import threading
import time
from concurrent.futures import (
    BrokenExecutor,
    Future,
    ProcessPoolExecutor,
    TimeoutError as FuturesTimeout,
    as_completed,
)
from dataclasses import dataclass, field
from typing import Callable

from .resource_monitor import ResourceMonitor, ResourceStats
from .filters import passes_filter, compile_filter

logger = logging.getLogger(__name__)

# ─── Worker initializer (runs once per subprocess) ─────────────────────────────

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _worker_init(pkg_root: str) -> None:
    """Called once per worker process to make the package importable."""
    if pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)
    # Pre-import heavy modules so they're cached for subsequent calls
    try:
        from evtx_tool.core._json_compat import fast_loads  # noqa: F401 — pre-warm orjson/json
        from evtx import PyEvtxParser  # noqa: F401
    except Exception:
        pass


# ─── Worker function (module-level, picklable) ─────────────────────────────────

def _worker_parse_file(task: dict) -> dict:
    """
    Worker: parse one EVTX file, apply filters inline, return matching events.
    Runs in a separate process. All exceptions caught — never crashes the pool.
    """
    filepath: str = task["filepath"]
    filter_config: dict = task["filter_config"]
    pkg_root: str = task.get("pkg_root", "")

    # Ensure package is importable (in case initializer wasn't used)
    if pkg_root and pkg_root not in sys.path:
        sys.path.insert(0, pkg_root)

    try:
        from evtx_tool.core._json_compat import fast_loads
        from evtx_tool.core.filters import compile_filter as _compile_filter
        from evtx import PyEvtxParser

        parser = PyEvtxParser(filepath)
        matching: list[dict] = []
        total = 0

        # Perf fix #10: compile filter once per file instead of checking
        # fc.get() on every event. The callable embeds only active conditions.
        _passes = _compile_filter(filter_config)

        for record in parser.records_json():
            total += 1
            try:
                data = fast_loads(record["data"])
                event = _extract_event_inline(
                    data, record["event_record_id"], record["timestamp"], filepath
                )
                if _passes(event):
                    matching.append(event)
            except Exception:
                pass  # skip malformed records

        return {
            "filepath": filepath,
            "events": matching,
            "total_records": total,
            "matched_records": len(matching),
            "error": None,
        }

    except Exception as exc:
        return {
            "filepath": filepath,
            "events": [],
            "total_records": 0,
            "matched_records": 0,
            "error": str(exc),
        }


def _extract_event_inline(data: dict, record_id: int, timestamp: str, source_file: str) -> dict:
    """Inline event extraction — no imports from parent package needed."""
    LEVEL_NAMES = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning",
                   4: "Information", 5: "Verbose"}

    event = data.get("Event", {})
    system = event.get("System", {})

    provider_attrs = system.get("Provider", {})
    pname = ""
    provider_guid = ""
    if isinstance(provider_attrs, dict):
        pname         = provider_attrs.get("#attributes", {}).get("Name", "")
        provider_guid = provider_attrs.get("#attributes", {}).get("Guid", "")

    tc = system.get("TimeCreated", {})
    ts_str = timestamp
    if isinstance(tc, dict):
        ts_str = tc.get("#attributes", {}).get("SystemTime", timestamp)

    event_data_raw = event.get("EventData") or event.get("UserData") or {}
    event_data: dict = {}
    if isinstance(event_data_raw, dict):
        event_data = {k: v for k, v in event_data_raw.items() if not k.startswith("#")}

    security = system.get("Security")
    user_id = ""
    if isinstance(security, dict):
        user_id = security.get("#attributes", {}).get("UserID", "")

    level = system.get("Level", 4)
    if not isinstance(level, int):
        try:
            level = int(level)
        except (ValueError, TypeError):
            level = 4

    event_id_raw = system.get("EventID", 0)
    qualifiers = None
    if isinstance(event_id_raw, dict):
        qualifiers   = event_id_raw.get("#attributes", {}).get("Qualifiers")
        event_id_raw = event_id_raw.get("#text", 0) or event_id_raw.get("Value", 0)
    try:
        event_id = int(event_id_raw)
    except (ValueError, TypeError):
        event_id = 0

    execution = system.get("Execution", {})
    exec_attrs = execution.get("#attributes", {}) if isinstance(execution, dict) else {}
    pid = exec_attrs.get("ProcessID")
    tid = exec_attrs.get("ThreadID")

    correlation = system.get("Correlation", {})
    correlation_id = ""
    if isinstance(correlation, dict):
        correlation_id = correlation.get("#attributes", {}).get("ActivityID", "")

    return {
        "record_id":      record_id,
        "event_id":       event_id,
        "qualifiers":     qualifiers,
        "timestamp":      ts_str,
        "channel":        system.get("Channel", ""),
        "provider":       pname,
        "provider_guid":  provider_guid,
        "computer":       system.get("Computer", ""),
        "level":          level,
        "level_name":     LEVEL_NAMES.get(level, str(level)),
        "task":           system.get("Task", 0),
        "opcode":         system.get("Opcode", 0),
        "keywords":       system.get("Keywords", ""),
        "version":        system.get("Version", 0),
        "process_id":     pid,
        "thread_id":      tid,
        "correlation_id": correlation_id,
        "user_id":        user_id,
        "event_data":     event_data,
        "source_file":    source_file,
    }


# ─── Engine state (shared with TUI) ────────────────────────────────────────────

@dataclass
class EngineState:
    """Thread-safe state snapshot updated by the engine, read by the TUI."""
    total_files: int = 0
    done_files: int = 0
    failed_files: int = 0
    total_records_processed: int = 0
    total_events_matched: int = 0
    events_per_sec: float = 0.0
    elapsed_sec: float = 0.0
    active_workers: int = 0
    max_workers: int = 0
    current_files: list[str] = field(default_factory=list)
    recent_events: list[dict] = field(default_factory=list)  # last 20 matches
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    resource_stats: ResourceStats | None = None
    is_running: bool = False
    is_throttling: bool = False
    phase: str = "idle"  # idle | running | throttled | done | error

    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, **kwargs) -> None:
        with self._lock:
            for k, v in kwargs.items():
                if hasattr(self, k):
                    setattr(self, k, v)

    def append_error(self, msg: str) -> None:
        """Append to errors list inside the lock (avoids read-outside-lock race)."""
        with self._lock:
            self.errors = self.errors + [msg]

    def append_warning(self, msg: str) -> None:
        """Append to warnings list inside the lock (avoids read-outside-lock race)."""
        with self._lock:
            self.warnings = self.warnings + [msg]

    def snapshot(self) -> dict:
        """Return a plain dict copy (for TUI reads)."""
        with self._lock:
            return {
                "total_files": self.total_files,
                "done_files": self.done_files,
                "failed_files": self.failed_files,
                "total_records_processed": self.total_records_processed,
                "total_events_matched": self.total_events_matched,
                "events_per_sec": self.events_per_sec,
                "elapsed_sec": self.elapsed_sec,
                "active_workers": self.active_workers,
                "max_workers": self.max_workers,
                "current_files": list(self.current_files),
                "recent_events": list(self.recent_events[-20:]),
                "errors": list(self.errors[-50:]),
                "warnings": list(self.warnings[-20:]),
                "resource_stats": self.resource_stats,
                "is_running": self.is_running,
                "is_throttling": self.is_throttling,
                "phase": self.phase,
            }


# ─── Main engine ───────────────────────────────────────────────────────────────

class ProcessingEngine:
    """
    Orchestrates multi-process EVTX parsing with resource management.

    Parameters
    ----------
    max_workers : int | None
        Maximum worker processes. Defaults to os.cpu_count() - 1.
    cpu_limit : float
        CPU % threshold above which throttling activates (default 85).
    ram_limit : float
        RAM % threshold above which memory pressure activates (default 90).
    file_timeout : float
        Per-file timeout in seconds. Files exceeding this are skipped (default 300).
    on_event : callable | None
        Optional callback(event_dict) called for each matched event (in main thread).
    on_progress : callable | None
        Optional callback(state_snapshot) called after each file completes.
    """

    MAX_QUEUE_DEPTH_FACTOR = 2  # semaphore = max_workers * factor

    def __init__(
        self,
        max_workers: int | None = None,
        cpu_limit: float = 85.0,
        ram_limit: float = 90.0,
        file_timeout: float = 300.0,
        on_event: Callable[[dict], None] | None = None,
        on_progress: Callable[[dict], None] | None = None,
    ):
        if max_workers is None:
            cpu_count = os.cpu_count() or 2
            max_workers = max(1, cpu_count - 1)

        self.max_workers = max_workers
        self.file_timeout = file_timeout
        self._on_event = on_event
        self._on_progress = on_progress

        self.state = EngineState(max_workers=max_workers)
        self._stop_event = threading.Event()
        self._monitor = ResourceMonitor(cpu_limit=cpu_limit, ram_limit=ram_limit)
        self._all_events: list[dict] = []
        self._events_lock = threading.Lock()

        # Register Ctrl+C handler (only valid in the main thread;
        # silently skipped when engine is created inside a worker thread, e.g. GUI)
        try:
            signal.signal(signal.SIGINT, self._sigint_handler)
        except ValueError:
            pass  # "signal only works in main thread" — safe to ignore in GUI mode

    def _sigint_handler(self, sig, frame) -> None:
        logger.warning("SIGINT received — initiating graceful shutdown")
        self.state.append_warning("Ctrl+C detected — stopping...")
        self._stop_event.set()

    # ── Public run method ────────────────────────────────────────────────────────

    def run(
        self,
        files: list[str],
        filter_config: dict,
        result_callback: Callable[[list[dict]], None] | None = None,
    ) -> list[dict]:
        """
        Parse all files, apply filter_config, return matched events.

        Parameters
        ----------
        files          : list of EVTX file paths to process
        filter_config  : dict from filters.py (fully picklable)
        result_callback: optional callback(all_events_list) called on completion

        Returns
        -------
        list of matched event dicts
        """
        if not files:
            return []

        self._stop_event.clear()
        self._all_events.clear()

        self.state.update(
            total_files=len(files),
            done_files=0,
            failed_files=0,
            total_records_processed=0,
            total_events_matched=0,
            events_per_sec=0.0,
            is_running=True,
            phase="running",
            max_workers=self.max_workers,
        )

        self._monitor.start()
        start_time = time.monotonic()

        try:
            self._run_pool(files, filter_config, start_time)
        finally:
            self._monitor.stop()
            elapsed = time.monotonic() - start_time
            matched = len(self._all_events)
            eps = matched / elapsed if elapsed > 0 else 0.0
            self.state.update(
                is_running=False,
                phase="done",
                elapsed_sec=elapsed,
                events_per_sec=eps,
                total_events_matched=matched,
            )
            logger.info(
                "Engine done: %d files, %d matched events, %.1f events/sec, %.1fs elapsed",
                len(files), matched, eps, elapsed,
            )

        if result_callback:
            result_callback(self._all_events)

        return self._all_events

    # ── Pool management ─────────────────────────────────────────────────────────

    def _run_pool(self, files: list[str], filter_config: dict, start_time: float) -> None:
        """Submit files to pool, collect results, handle throttling."""
        workers = self.max_workers
        semaphore = threading.Semaphore(workers * self.MAX_QUEUE_DEPTH_FACTOR)
        active_futures: dict[Future, str] = {}
        active_lock = threading.Lock()
        submitted = 0

        def _make_executor(n_workers: int) -> ProcessPoolExecutor:
            import functools
            return ProcessPoolExecutor(
                max_workers=n_workers,
                initializer=_worker_init,
                initargs=(_PKG_ROOT,),
            )

        def _submit_file(executor: ProcessPoolExecutor, filepath: str) -> Future:
            task = {
                "filepath": filepath,
                "filter_config": filter_config,
                "pkg_root": _PKG_ROOT,
            }
            fut = executor.submit(_worker_parse_file, task)

            def _release_sem(f):
                semaphore.release()
                with active_lock:
                    active_futures.pop(f, None)
                    self.state.update(active_workers=len(active_futures))

            fut.add_done_callback(_release_sem)
            with active_lock:
                active_futures[fut] = filepath
                self.state.update(active_workers=len(active_futures))
            return fut

        executor = _make_executor(workers)
        futures_to_file: dict[Future, str] = {}

        try:
            for filepath in files:
                if self._stop_event.is_set():
                    break

                # Backpressure: block until queue has room
                acquired = False
                while not acquired:
                    if self._stop_event.is_set():
                        break
                    acquired = semaphore.acquire(timeout=0.5)

                if self._stop_event.is_set():
                    if acquired:
                        semaphore.release()
                    break

                # Memory pressure: pause and GC (max 3 retries then proceed anyway)
                if self._monitor.has_memory_pressure():
                    mem_pauses = getattr(self, '_mem_pause_count', 0) + 1
                    self._mem_pause_count = mem_pauses
                    if mem_pauses <= 3:
                        logger.warning("Memory pressure — pausing submissions, collecting garbage (attempt %d/3)", mem_pauses)
                        self.state.update(phase="throttled")
                        gc.collect()
                        time.sleep(2.0)
                        semaphore.release()
                        continue
                    else:
                        # Proceed anyway after max retries — warn but don't block forever
                        if mem_pauses == 4:
                            logger.warning("Memory pressure persists — proceeding anyway to avoid stalling")
                            self.state.append_warning("RAM pressure persists — continuing with reduced throughput")
                        self._mem_pause_count = 0  # reset for next file

                # CPU throttling: reduce workers temporarily
                if self._monitor.is_throttling():
                    reduced = max(1, workers // 2)
                    if reduced < workers:
                        logger.warning("CPU throttle: reducing workers %d → %d", workers, reduced)
                        self.state.update(phase="throttled", is_throttling=True)
                        self.state.append_warning(
                            f"CPU > {self._monitor._cpu_limit:.0f}% — throttled to {reduced} workers"
                        )
                        # Recreate executor with fewer workers (non-blocking to avoid hangs)
                        try:
                            executor.shutdown(wait=False, cancel_futures=True)
                        except Exception:
                            pass
                        workers = reduced
                        executor = _make_executor(workers)
                        # Re-adjust semaphore for new worker count
                        for _ in range(workers * self.MAX_QUEUE_DEPTH_FACTOR):
                            try:
                                semaphore.release()
                            except ValueError:
                                break
                        semaphore.acquire(timeout=0)  # re-consume the one we had
                else:
                    # Restore full worker count if throttle cleared
                    if workers < self.max_workers and not self._monitor.is_throttling():
                        self.state.update(phase="running", is_throttling=False)
                        workers = self.max_workers

                try:
                    fut = _submit_file(executor, filepath)
                    futures_to_file[fut] = filepath
                    submitted += 1
                except BrokenExecutor:
                    logger.error("Executor broken — recreating and retrying %s", filepath)
                    try:
                        executor.shutdown(wait=False, cancel_futures=True)
                    except Exception:
                        pass
                    executor = _make_executor(workers)
                    fut = _submit_file(executor, filepath)
                    futures_to_file[fut] = filepath
                    submitted += 1

            # Collect results from all submitted futures
            for fut in as_completed(futures_to_file.keys()):
                if self._stop_event.is_set():
                    break
                filepath = futures_to_file[fut]
                self._collect_result(fut, filepath, start_time)

        except BrokenExecutor as exc:
            logger.error("ProcessPool permanently broken: %s", exc)
            self.state.update(phase="error")
            self.state.append_error(str(exc))
        finally:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    def _collect_result(self, fut: Future, filepath: str, start_time: float) -> None:
        """Collect and process the result from a completed future."""
        try:
            result: dict = fut.result(timeout=self.file_timeout)
        except FuturesTimeout:
            msg = f"Timeout ({self.file_timeout:.0f}s): {os.path.basename(filepath)}"
            logger.warning(msg)
            self.state.update(
                failed_files=self.state.failed_files + 1,
                done_files=self.state.done_files + 1,
            )
            self.state.append_error(msg)
            return
        except Exception as exc:
            msg = f"Worker exception for {os.path.basename(filepath)}: {exc}"
            logger.error(msg)
            self.state.update(
                failed_files=self.state.failed_files + 1,
                done_files=self.state.done_files + 1,
            )
            self.state.append_error(msg)
            return

        # Process result
        error = result.get("error")
        if error:
            msg = f"Parse error {os.path.basename(filepath)}: {error}"
            logger.warning(msg)
            self.state.update(
                failed_files=self.state.failed_files + 1,
                done_files=self.state.done_files + 1,  # BUG 3 fix: count failed files in progress
            )
            self.state.append_error(msg)

        events: list[dict] = result.get("events", [])
        total_rec: int = result.get("total_records", 0)

        with self._events_lock:
            self._all_events.extend(events)

        # Call per-event callback
        if self._on_event:
            for ev in events:
                try:
                    self._on_event(ev)
                except Exception:
                    pass

        elapsed = time.monotonic() - start_time
        matched_total = len(self._all_events)
        eps = matched_total / elapsed if elapsed > 0 else 0.0

        # Update recent events (keep last 20)
        recent = self.state.recent_events
        recent.extend(events)
        recent = recent[-20:]

        self.state.update(
            done_files=self.state.done_files + 1,
            total_records_processed=self.state.total_records_processed + total_rec,
            total_events_matched=matched_total,
            events_per_sec=eps,
            elapsed_sec=elapsed,
            recent_events=recent,
            resource_stats=self._monitor.get_stats(),
        )

        if self._on_progress:
            try:
                self._on_progress(self.state.snapshot())
            except Exception:
                pass

        logger.debug(
            "Done: %s | %d records | %d matched | total matched: %d",
            os.path.basename(filepath), total_rec, len(events), matched_total,
        )

    def stop(self) -> None:
        """Request graceful shutdown."""
        self._stop_event.set()

    def get_all_events(self) -> list[dict]:
        with self._events_lock:
            return list(self._all_events)
