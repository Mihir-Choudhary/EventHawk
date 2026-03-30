"""
Resource monitor — daemon thread that tracks CPU and RAM usage.

Polling strategy:
  - Every 2 seconds (negligible overhead, ~1-2 ms per call)
  - Maintains rolling 3-sample history for CPU spike detection
  - Triggers throttle_event when sustained CPU > threshold (3 consecutive polls)
  - Triggers memory_event when available RAM < floor_mb

Usage:
    monitor = ResourceMonitor(cpu_limit=85, ram_limit=90)
    monitor.start()
    ...
    stats = monitor.get_stats()  # thread-safe snapshot
    monitor.stop()
"""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field

import psutil

logger = logging.getLogger(__name__)

# ── Stats snapshot ─────────────────────────────────────────────────────────────

@dataclass
class ResourceStats:
    sys_cpu_pct: float = 0.0        # System-wide CPU %
    proc_cpu_pct: float = 0.0       # This process CPU %
    sys_ram_pct: float = 0.0        # System RAM used %
    ram_available_mb: float = 0.0   # Available RAM in MB
    proc_ram_mb: float = 0.0        # This process RSS in MB
    throttle_active: bool = False   # True when CPU throttling is in effect
    memory_pressure: bool = False   # True when RAM is low
    cpu_limit: float = 85.0
    ram_limit: float = 90.0


# ── Monitor thread ─────────────────────────────────────────────────────────────

class ResourceMonitor(threading.Thread):
    """Daemon thread that monitors system resources and signals throttling."""

    POLL_INTERVAL = 2.0          # seconds between polls
    SUSTAINED_POLLS = 3          # consecutive overages before throttle activates
    RAM_FLOOR_MB   = 200.0       # hard floor for available RAM (lowered for 6-8GB machines)

    def __init__(self, cpu_limit: float = 85.0, ram_limit: float = 90.0):
        super().__init__(daemon=True, name="ResourceMonitor")
        self._cpu_limit = cpu_limit
        self._ram_limit = ram_limit
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._stats = ResourceStats(cpu_limit=cpu_limit, ram_limit=ram_limit)
        self._cpu_history: deque[float] = deque(maxlen=self.SUSTAINED_POLLS)
        self._proc = psutil.Process(os.getpid())

        # FINDING-13: track previous pressure state so we only log on transitions
        # (entering or leaving the pressure state), not on every 2-second poll.
        self._prev_memory_pressure: bool = False
        self._prev_throttle: bool = False

        # External consumers can wait() on these events
        self.throttle_event = threading.Event()   # set when throttle needed
        self.memory_event = threading.Event()     # set when RAM low

        # Seed the first cpu_percent call (always returns 0.0)
        try:
            self._proc.cpu_percent(interval=None)
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

    # ── Main loop ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        logger.debug("ResourceMonitor started (cpu_limit=%.0f%%, ram_limit=%.0f%%)",
                     self._cpu_limit, self._ram_limit)
        while not self._stop_event.is_set():
            try:
                self._poll()
            except Exception as exc:
                logger.warning("ResourceMonitor poll error: %s", exc)
            self._stop_event.wait(timeout=self.POLL_INTERVAL)

    def _poll(self) -> None:
        try:
            sys_cpu   = psutil.cpu_percent(interval=None)
            proc_cpu  = self._proc.cpu_percent(interval=None)
            mem       = psutil.virtual_memory()
            proc_mem  = self._proc.memory_info()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            logger.debug("psutil error: %s", exc)
            return

        sys_ram_pct       = mem.percent
        ram_available_mb  = mem.available / 1024 / 1024
        proc_ram_mb       = proc_mem.rss / 1024 / 1024

        # CPU history for sustained-overload detection
        self._cpu_history.append(sys_cpu)
        throttle = (
            len(self._cpu_history) >= self.SUSTAINED_POLLS
            and all(c > self._cpu_limit for c in self._cpu_history)
        )

        memory_pressure = (
            sys_ram_pct > self._ram_limit
            or ram_available_mb < self.RAM_FLOOR_MB
        )

        with self._lock:
            self._stats = ResourceStats(
                sys_cpu_pct=sys_cpu,
                proc_cpu_pct=proc_cpu,
                sys_ram_pct=sys_ram_pct,
                ram_available_mb=ram_available_mb,
                proc_ram_mb=proc_ram_mb,
                throttle_active=throttle,
                memory_pressure=memory_pressure,
                cpu_limit=self._cpu_limit,
                ram_limit=self._ram_limit,
            )

        # Signal events (set/clear)
        if throttle:
            self.throttle_event.set()
        else:
            self.throttle_event.clear()

        if memory_pressure:
            self.memory_event.set()
        else:
            self.memory_event.clear()

        # FINDING-13: only log warnings on state *transitions* — not every poll
        # tick.  With 2-second polling and sustained high memory, the old code
        # produced hundreds of identical "Memory pressure" lines in the log.
        if memory_pressure != self._prev_memory_pressure:
            if memory_pressure:
                logger.warning(
                    "Memory pressure detected: RAM %.1f%% (avail %.0f MB) — "
                    "limit %.0f%%, floor %.0f MB",
                    sys_ram_pct, ram_available_mb,
                    self._ram_limit, self.RAM_FLOOR_MB,
                )
            else:
                logger.info("Memory pressure cleared: avail %.0f MB", ram_available_mb)
            self._prev_memory_pressure = memory_pressure

        if throttle != self._prev_throttle:
            if throttle:
                logger.warning("CPU throttle activated: %.1f%% (limit %.0f%%)",
                               sys_cpu, self._cpu_limit)
            else:
                logger.info("CPU throttle cleared: %.1f%%", sys_cpu)
            self._prev_throttle = throttle

        logger.debug("CPU %.1f%% (proc %.1f%%) | RAM %.1f%% avail %.0f MB | throttle=%s mem_pressure=%s",
                     sys_cpu, proc_cpu, sys_ram_pct, ram_available_mb, throttle, memory_pressure)

    # ── Public API ─────────────────────────────────────────────────────────────

    def get_stats(self) -> ResourceStats:
        """Thread-safe snapshot of current resource stats."""
        with self._lock:
            return self._stats

    def update_limits(self, cpu_limit: float | None = None, ram_limit: float | None = None) -> None:
        """Adjust thresholds at runtime."""
        if cpu_limit is not None:
            self._cpu_limit = cpu_limit
        if ram_limit is not None:
            self._ram_limit = ram_limit

    def stop(self) -> None:
        """Signal the monitor thread to stop and wait for it to finish."""
        self._stop_event.set()
        self.join(timeout=5.0)
        logger.debug("ResourceMonitor stopped")

    def is_throttling(self) -> bool:
        return self.throttle_event.is_set()

    def has_memory_pressure(self) -> bool:
        return self.memory_event.is_set()
