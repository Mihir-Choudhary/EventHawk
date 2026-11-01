"""Juggernaut: going back to "no filter" reuses the sorted full table instead of rebuilding it.

Found by the dynamic filter-timing run (2026-11-01): on 1,710,518 real events,
removing a filter layer took up to 2.3 s.  Every request with no filter at all
(Clear All, removing the last layer) re-ran a DuckDB ORDER BY over every row and
re-gathered every row: 0.37 s + 0.55 s each time on 1.7M rows.  The unfiltered,
sorted result only changes when the sort does.  Expected: built once per sort,
still complete and in order afterwards.  Synthetic data only.
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


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.heavyweight_model as hm
    import evtx_tool.gui.main_window as mw
    calls = {"unfiltered": 0}
    real = hm._FilterThread._metadata_filter

    def counting(self, con, where_sql, params, sort_col, sort_asc):
        if where_sql == "1=1" and not params:
            calls["unfiltered"] += 1
        return real(self, con, where_sql, params, sort_col, sort_asc)
    hm._FilterThread._metadata_filter = counting

    # out of time order on purpose: the view must still come back sorted
    evs = [T.ev(r"C:\s\S.evtx", i + 1, "HOST-A" if i % 3 else "HOST-B", T.T0 + timedelta(seconds=(i * 7) % 50), 4624)
           for i in range(50)]
    m = T.Mode(mw, True)
    w = mw.MainWindow()
    m.load(w, evs)

    def settle(n):
        T.wait_for(lambda: w._hw_model.rowCount() == n, 30)
        T.pump(200)
        return w._hw_model.rowCount()

    for i in range(3):
        w._apply_quick_filter("computer", "HOST-B", True)
        settle(17)
        w._clear_quick_filters()
        settle(50)
    check("the unfiltered sorted table is built once, not on every clear",
          calls["unfiltered"] <= 1, f"{calls['unfiltered']} builds for 3 clears")
    t = w._hw_model._display_table
    ts = t["timestamp_utc"].to_pylist()
    check("after the clears every event is shown", t.num_rows == 50, str(t.num_rows))
    check("...in time order", ts == sorted(ts), "sorted" if ts == sorted(ts) else "NOT sorted")
    hm._FilterThread._metadata_filter = real
    w.close()
    T.pump(200)

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
