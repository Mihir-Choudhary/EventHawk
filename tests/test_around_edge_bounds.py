"""Around this event at the edge of representable time explains itself.

Codex review-1 F5: an event stamped near the end of year 9999 (unusual or
tampered, but parseable) with a one-day window: window_bounds() overflowed
Python's datetime range and OverflowError escaped the action -- no tab, no
explanation.  Expected: a warning that says why, no tab, no exception, and no
silently clamped window.  Same at the start of year 1.  Synthetic data.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
SEC = r"C:\synthetic\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    evs = [T.ev(SEC, 1, "HOST", "9999-12-31T23:00:00.000000Z"), T.ev(SEC, 2, "HOST", "0001-01-01T01:00:00.000000Z")]
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    m.load(w, evs)
    warnings = []
    w._warn_blocking = lambda title, text, *a, **k: warnings.append(f"{title}: {text}")
    for anchor, label in ((evs[0], "end of year 9999"), (evs[1], "start of year 1")):
        n_tabs = len(w._file_tabs)
        n_warn = len(warnings)
        try:
            w._open_around_tab(dict(anchor), timedelta(days=1), timedelta(days=1), "all")
            err = None
        except Exception as exc:                       # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
        T.pump(100)
        check(f"{tag}: {label} +/- 1 day raises nothing out of the action", err is None, str(err))
        check(f"{tag}: ...says why no tab opened", len(warnings) == n_warn + 1, str(warnings[n_warn:]))
        check(f"{tag}: ...and opens no (clamped) tab", len(w._file_tabs) == n_tabs, f"{len(w._file_tabs)} vs {n_tabs}")
    w.close()
    T.pump(200)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    for jm in (False, True):
        run(mw, jm)
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
