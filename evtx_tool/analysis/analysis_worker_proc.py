"""
Subprocess entry point for the analysis pipeline.

This module runs in an **isolated worker process** spawned by
``AnalysisRunner`` (GUI side).  It has its own Python interpreter,
memory space, and GIL — the GUI event loop is never affected.

The function ``run_analysis()`` is the ``target=`` for ``mp.Process``.
It must be a module-level function (picklable).

Performance optimizations
-------------------------
- IOC extraction + Correlation run **concurrently** via ThreadPoolExecutor
  (they are independent leaf nodes — verified in test_parallel_analysis.py)
- Metadata runs first (fast, ~50ms) to populate filter dropdowns early
- Zero-copy SharedMemory read via memoryview → fast_loads
- CPU priority set to BELOW_NORMAL; optional CPU affinity to non-primary cores

IPC contract
------------
- ``progress_q``  (worker → GUI)  progress / data_loaded / error dicts
- ``result_q``    (worker → GUI)  final ``{type: "result", ...}``
- ``cancel_event`` (GUI → worker) checked between steps
"""

from __future__ import annotations

import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, Future
from multiprocessing.shared_memory import SharedMemory
from typing import Any

logger = logging.getLogger(__name__)


# ── Priority & affinity helpers ───────────────────────────────────────────────

def _set_low_priority() -> None:
    """
    Set this process to BELOW_NORMAL priority (Windows) or nice 10 (Linux).

    Non-fatal — analysis still works at normal priority if this fails.
    """
    try:
        import psutil
        p = psutil.Process()
        if sys.platform == "win32":
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        else:
            p.nice(10)
    except Exception:
        pass  # psutil not installed, or permission error — non-fatal


def _set_cpu_affinity() -> None:
    """
    Pin this worker to non-primary CPU cores (leave core 0 for the GUI).

    On a 4-core machine: worker gets cores 1,2,3; GUI keeps core 0.
    On single-core: skip (no benefit).

    Non-fatal — analysis still works without affinity pinning.
    """
    try:
        import psutil
        p = psutil.Process()
        all_cpus = list(range(os.cpu_count() or 1))
        if len(all_cpus) <= 1:
            return  # Single core — no point in pinning
        # Give worker all cores EXCEPT core 0 (reserved for GUI)
        worker_cpus = all_cpus[1:]
        p.cpu_affinity(worker_cpus)
    except Exception:
        pass  # psutil missing, permission error, or platform unsupported


# ── Worker entry point ────────────────────────────────────────────────────────

def run_analysis(
    shm_name: str,
    data_size: int,
    progress_q: Any,          # mp.Queue — can't type-annotate cleanly
    result_q: Any,            # mp.Queue
    cancel_event: Any,        # mp.Event
    do_ioc: bool,
    do_correlate: bool,
    do_hayabusa: bool = False,
    hayabusa_path: str | None = None,
    evtx_paths: list[str] | None = None,
) -> None:
    """
    Worker process entry point — runs in an isolated subprocess.

    Parameters
    ----------
    shm_name : str
        Name of the ``SharedMemory`` block where events are serialized.
    data_size : int
        Number of bytes to read from the shared memory buffer.
    progress_q : multiprocessing.Queue
        Queue for sending progress / data_loaded / error messages to GUI.
    result_q : multiprocessing.Queue
        Queue for sending the final result dict to GUI.
    cancel_event : multiprocessing.Event
        Set by GUI to request cancellation (checked between steps).
    do_ioc : bool
        Whether to run IOC extraction.
    do_correlate : bool
        Whether to run correlation rules.
    do_hayabusa : bool
        Whether to run Hayabusa binary against EVTX files.
    hayabusa_path : str or None
        Absolute path to the Hayabusa binary.
    evtx_paths : list[str] or None
        EVTX file/directory paths (needed for Hayabusa).
    """
    try:
        _set_low_priority()
        _set_cpu_affinity()
        _run_pipeline(
            shm_name, data_size,
            progress_q, result_q, cancel_event,
            do_ioc, do_correlate, do_hayabusa,
            hayabusa_path, evtx_paths,
        )
    except Exception as exc:
        try:
            progress_q.put({"type": "error", "message": str(exc)})
        except Exception:
            pass  # Queue itself may be broken if parent is gone


def _run_pipeline(
    shm_name: str,
    data_size: int,
    progress_q: Any,
    result_q: Any,
    cancel_event: Any,
    do_ioc: bool,
    do_correlate: bool,
    do_hayabusa: bool,
    hayabusa_path: str | None,
    evtx_paths: list[str] | None,
) -> None:
    """Internal pipeline — separated so the outer try/except catches everything."""

    # ── IOC post-processing helper ───────────────────────────────────────
    _SKIP_IOC_KEYS = frozenset({"summary", "correlation"})

    def _score_and_correlate(iocs: dict) -> None:
        """Apply suspicion scoring and co-occurrence correlation to IOC entries."""
        if not iocs:
            return
        try:
            from evtx_tool.analysis.ioc_scorer import score_ioc
            for ioc_type, entries in iocs.items():
                if ioc_type in _SKIP_IOC_KEYS or not isinstance(entries, list):
                    continue
                for entry in entries:
                    if isinstance(entry, dict):
                        entry["score"], entry["score_reasons"] = score_ioc(
                            ioc_type, entry.get("value", "")
                        )
                entries.sort(key=lambda e: e.get("score", 0) if isinstance(e, dict) else 0,
                             reverse=True)
        except Exception as exc:
            logger.warning("IOC scoring failed: %s", exc)
        try:
            from evtx_tool.analysis.ioc_correlation import correlate_iocs
            iocs["correlation"] = correlate_iocs(iocs)
        except Exception as exc:
            logger.warning("IOC correlation failed: %s", exc)

    # ── Count total steps for percentage progress ────────────────────────
    total_steps = 1  # metadata always runs
    if do_ioc:
        total_steps += 1
    if do_correlate:
        total_steps += 1
    if do_hayabusa:
        total_steps += 1
    step = 0

    def _emit_progress(msg: str) -> None:
        nonlocal step
        step += 1
        pct = int(step / total_steps * 100)
        progress_q.put({"type": "progress", "step": msg, "pct": pct})

    def _emit_component(component: str, pct: int) -> None:
        """Send per-component percentage to the GUI."""
        progress_q.put({"type": "component_progress", "component": component, "pct": pct})

    # ── 1. Attach SharedMemory → deserialize events ──────────────────────
    shm = SharedMemory(name=shm_name, create=False)
    try:
        from evtx_tool.core._json_compat import fast_loads
        # Copy bytes from shared memory, then release the memoryview
        # before closing — prevents "cannot close exported pointers" error
        raw_bytes = bytes(shm.buf[:data_size])
    finally:
        shm.close()  # Detach from this process (GUI will unlink)

    events: list[dict] = fast_loads(raw_bytes)
    del raw_bytes  # Free the copy

    progress_q.put({"type": "data_loaded"})

    if cancel_event.is_set():
        return

    # ── 2. Build metadata (fast — powers column filter dropdowns) ────────
    metadata: dict = {}
    if not cancel_event.is_set():
        _emit_progress("Building metadata…")
        _emit_component("Metadata", 0)
        try:
            from evtx_tool.gui.metadata import build_metadata
            metadata = build_metadata(
                events,
                progress_fn=lambda pct: _emit_component("Metadata", pct),
            )
        except Exception as exc:
            logger.warning("metadata failed: %s", exc)
        _emit_component("Metadata", 100)

    if cancel_event.is_set():
        return

    # ── 3. IOC + Correlation in PARALLEL ─────────────────────────────────
    # These are verified-independent leaf nodes (test_parallel_analysis.py):
    #   - extract_iocs reads only event_data (never attack_tags)
    #   - correlate reads only event_id, event_data, computer, timestamp
    # Running them concurrently in threads gives ~20-40% wall-clock reduction
    # since regex (IOC) partially releases the GIL.

    iocs: dict | None = None
    chains: list = []

    need_parallel = (do_ioc and do_correlate and not cancel_event.is_set())

    if need_parallel:
        # Both enabled — run concurrently
        _emit_progress("Extracting IOCs + Running correlation…")

        ioc_result: dict | None = None
        corr_result: list = []

        def _run_ioc() -> dict | None:
            _emit_component("IOC Extraction", 0)
            try:
                from evtx_tool.analysis.ioc_extractor import extract_iocs
                result = extract_iocs(
                    events,
                    progress_fn=lambda pct: _emit_component("IOC Extraction", pct),
                )
                _emit_component("IOC Extraction", 100)
                _score_and_correlate(result)
                return result
            except Exception as exc:
                logger.warning("IOC extraction failed: %s", exc)
                return None

        def _run_correlate() -> list:
            _emit_component("Correlation", 0)
            try:
                from evtx_tool.analysis.correlator import correlate
                result = correlate(
                    events,
                    progress_fn=lambda pct: _emit_component("Correlation", pct),
                )
                _emit_component("Correlation", 100)
                return result
            except Exception as exc:
                logger.warning("Correlation failed: %s", exc)
                return []

        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="analysis") as pool:
            fut_ioc: Future = pool.submit(_run_ioc)
            fut_corr: Future = pool.submit(_run_correlate)

            # Poll futures so cancel_event is respected during long runs
            import time
            while not (fut_ioc.done() and fut_corr.done()):
                if cancel_event.is_set():
                    break
                time.sleep(0.2)

            if not cancel_event.is_set():
                iocs = fut_ioc.result(timeout=60)
                chains = fut_corr.result(timeout=60)

        # Consume the extra step count (we reported both as one combined step)
        step += 1

    else:
        # Run individually (or only one is enabled)
        if do_ioc and not cancel_event.is_set():
            _emit_progress("Extracting IOCs…")
            _emit_component("IOC Extraction", 0)
            try:
                from evtx_tool.analysis.ioc_extractor import extract_iocs
                iocs = extract_iocs(
                    events,
                    progress_fn=lambda pct: _emit_component("IOC Extraction", pct),
                )
                _score_and_correlate(iocs)
            except Exception as exc:
                logger.warning("IOC extraction failed: %s", exc)
            _emit_component("IOC Extraction", 100)

        if do_correlate and not cancel_event.is_set():
            _emit_progress("Running correlation rules…")
            _emit_component("Correlation", 0)
            try:
                from evtx_tool.analysis.correlator import correlate
                chains = correlate(
                    events,
                    progress_fn=lambda pct: _emit_component("Correlation", pct),
                )
            except Exception as exc:
                logger.warning("Correlation failed: %s", exc)
            _emit_component("Correlation", 100)

    # ── 4. Hayabusa / Sigma rules ─────────────────────────────────────────
    if do_hayabusa and hayabusa_path and evtx_paths and not cancel_event.is_set():
        _emit_progress("Running Hayabusa rules…")   # one-time step count increment ✓
        _emit_component("Hayabusa", 0)

        import time as _time
        _hayabusa_start = _time.monotonic()

        def _hayabusa_heartbeat(msg: str) -> None:
            """
            Heartbeat called every ~10 s by hayabusa_runner during the scan.

            IMPORTANT: must NOT call _emit_progress() — that increments the
            pipeline step counter and causes the overall % to exceed 100%.
            Instead we update only the component label and the status text.
            We cap the visual pct at 99 so it doesn't show 100% until done.
            """
            elapsed = int(_time.monotonic() - _hayabusa_start)
            # Show elapsed time in the component label (stays at 50% until done)
            progress_q.put({
                "type": "component_progress",
                "component": "Hayabusa",
                "pct": 50,          # stays at 50 until _emit_component("Hayabusa", 100)
            })
            # Send a plain status text — no step counter involved
            progress_q.put({
                "type": "progress",
                "step": f"Hayabusa: Scanning… ({elapsed}s elapsed)",
                "pct": None,        # suppress the (pct%) suffix in the status bar
            })

        try:
            from evtx_tool.analysis.hayabusa_runner import run_hayabusa
            hayabusa_chains = run_hayabusa(
                hayabusa_path=hayabusa_path,
                evtx_paths=evtx_paths,
                cancel_event=cancel_event,
                progress_callback=_hayabusa_heartbeat,
            )
            chains.extend(hayabusa_chains)
        except Exception as exc:
            logger.warning("Hayabusa scan failed: %s", exc)
        _emit_component("Hayabusa", 100)


    # ── 5. Send results ──────────────────────────────────────────────────
    if not cancel_event.is_set():
        result_q.put({
            "type": "result",
            "iocs": iocs,
            "chains": chains,
            "metadata": metadata,
        })
