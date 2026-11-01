"""A Normal-mode filter stops the column-popup sweep that its result makes stale.

Found by the dynamic filter-timing run (2026-11-01): on 130,028 real events
every other Advanced Filter apply took 3-4 s instead of 0.8 s.  After each
filter change a background sweep pre-computes every column's popup values
(Python, all events); the next filter overlapped it and both fought for the
interpreter lock while the window was frozen.  That sweep's results are
stale the moment a new filter starts, so starting a filter must stop it.
Synthetic data only.
"""
import os
import sys
import time
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = [T.ev(r"C:\s\Security.evtx", i + 1, f"HOST-{i % 7}", T.T0 + timedelta(seconds=i), 4624 + (i % 5))
           for i in range(60_000)]
    w = mw.MainWindow()
    T.Mode(mw, False).load(w, evs)
    T.pump(200)
    w._start_normal_col_prewarm()
    sweep = getattr(w, "_norm_prewarm_worker", None)
    T.wait_for(lambda: sweep is not None and sweep.isRunning(), 5)
    check("a popup sweep is running", sweep is not None and sweep.isRunning())
    t0 = time.perf_counter()
    with w._normal_filter_busy("test"):
        stopped = not sweep.isRunning()
        waited = time.perf_counter() - t0
    check("starting a filter stops the running sweep", stopped, f"still running: {not stopped}")
    check("...promptly (< 0.5 s)", waited < 0.5, f"{waited:.3f} s")
    T.wait_for(lambda: not sweep.isRunning(), 30)
    w.close()
    T.pump(200)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
