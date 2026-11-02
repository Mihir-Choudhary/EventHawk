"""A relative-time filter ("last N days / hours") with no absolute dates works.

Found by Codex in audit-5 (E5-07): in Normal mode the Advanced Filter's
"Display events for the last ..." without a date range raised
UnboundLocalError ('_tz'), so the filter failed and the view kept every event
(963 shown, 0 expected).  set_advanced_filter re-imported `timezone as _tz`
inside the date-range branch, which made _tz local to the whole function and
unbound whenever that branch did not run.  Juggernaut was correct.
Expected: both modes keep exactly the events inside the window.  Synthetic.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

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
    now = datetime.now(timezone.utc)
    ages = [timedelta(hours=1), timedelta(hours=5), timedelta(days=2), timedelta(days=10), timedelta(days=400)]
    evs = [T.ev(r"C:\c\Security.evtx", i + 1, "HOST", now - a, 4624) for i, a in enumerate(ages)]
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        T.Mode(mw, jm).load(w, evs)

        def apply(cfg):
            if jm:
                w._hw_model.apply_filter(cfg)
                T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30); T.pump(400)
                return w._hw_model.rowCount()
            w._proxy_model.set_advanced_filter(cfg)
            T.pump(50)
            return w._proxy_model.rowCount()
        for cfg, want, label in (
            ({"relative_days": 1}, 2, "last 1 day"),
            ({"relative_hours": 3}, 1, "last 3 hours"),
            ({"relative_days": 30}, 4, "last 30 days"),
            ({"relative_days": 1, "relative_exclude": True}, 3, "last 1 day, Exclude"),
        ):
            got = apply(cfg)
            check(f"{tag}: {label} keeps exactly the events inside the window", got == want, f"{got} vs {want}")
        w.close(); T.pump(50)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
