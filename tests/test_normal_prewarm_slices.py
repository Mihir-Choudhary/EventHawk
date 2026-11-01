"""The Normal-mode popup sweep does not re-filter every event once per column on the GUI thread.

Found by the dynamic filter-timing run (2026-11-01): after a Normal-mode filter
change, the column-popup sweep built each column's "visible events" slice on the
GUI thread by re-running the whole filter over every source event, once per
filterable column (15 x 130,028 rows): ~4.5 s of GUI work after every filter
change, although the filter itself had finished in 0.5 s.  A column without its
own quick filter sees exactly the rows already visible.  Expected: no filter
re-evaluation for such columns, and the popup values unchanged.  Synthetic data.
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
    import evtx_tool.gui.main_window as mw
    import evtx_tool.gui.models as M
    evs = [T.ev(r"C:\s\S.evtx", i + 1, f"HOST-{i % 4}", T.T0 + timedelta(seconds=i), 4624 + (i % 3))
           for i in range(3000)]
    w = mw.MainWindow()
    T.Mode(mw, False).load(w, evs)
    w._proxy_model.add_quick_filter("computer", "HOST-1", True)       # one column has its own quick filter
    T.pump(100)
    calls = {"n": 0}
    real = M.EventFilterProxyModel._filterAcceptsRow_impl

    def counting(self, row, parent):
        calls["n"] += 1
        return real(self, row, parent)
    M.EventFilterProxyModel._filterAcceptsRow_impl = counting
    try:
        slices = {ck: w._active_proxy.collect_source_events_for_popup(ck)
                  for ck in ("event_id", "channel", "level_name", "computer")}
    finally:
        M.EventFilterProxyModel._filterAcceptsRow_impl = real
    check("columns without their own quick filter cost no filter re-evaluation (only 'computer' re-filters)",
          calls["n"] <= 3000, f"{calls['n']:,} row evaluations for 4 columns (3,000 events)")
    check("...their slice is exactly the visible rows",
          all(len(slices[c]) == 750 for c in ("event_id", "channel", "level_name")),
          str({c: len(v) for c, v in slices.items()}))
    check("the column with its own quick filter still sees every value of that column",
          len(slices["computer"]) == 3000, str(len(slices["computer"])))
    w.close()
    T.pump(100)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
