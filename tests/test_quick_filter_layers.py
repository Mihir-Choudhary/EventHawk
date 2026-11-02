"""A column-popup filter keeps the tab's other quick filters, whatever set them.

Found by Codex in audit-5 (E5-06): a "filter by this value" from the table's
context menu (Computer include: 38 events) was discarded the moment a column
popup filter was applied on another column (Channel: 963 shown, 38 expected):
the popup handler rebuilt the tab's whole quick-filter list from its own
record of popup filters, which never held context-menu filters.  Expected:
applying, changing or clearing one column's filter touches only that column's
entries; the header marker shows every filtered column.  Synthetic events.
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
    from evtx_tool.gui.main_window import ColumnFilterPopup
    col = {k: i for i, k in ColumnFilterPopup.FILTERABLE.items()}
    evs = []
    for i in range(24):
        e = T.ev(r"C:\c\Security.evtx", i + 1, f"HOST-{i % 3}", T.T0 + timedelta(seconds=i), (4624, 4634)[i % 2])
        e["channel"] = ("Security", "System")[(i // 2) % 2]
        evs.append(e)

    def want(pred):
        return sum(1 for e in evs if pred(e))
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
        T.pump(200)

        def rows():
            if jm:
                T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30); T.pump(300)
                return w._hw_model.rowCount()
            return w._proxy_model.rowCount()
        w._apply_quick_filter("computer", "HOST-1", True)            # context menu
        n1 = want(lambda e: e["computer"] == "HOST-1")
        check(f"{tag}: the context-menu filter applies", rows() == n1, f"{rows()} vs {n1}")
        w._on_col_filter_applied(col["channel"], "include", ["Security"])
        n2 = want(lambda e: e["computer"] == "HOST-1" and e["channel"] == "Security")
        check(f"{tag}: a Channel popup filter keeps the context-menu Computer filter", rows() == n2, f"{rows()} vs {n2}")
        hdr = (w._hw_model if jm else w._event_model)._header_overrides
        check(f"{tag}: both filtered columns carry the header marker",
              col["computer"] in hdr and col["channel"] in hdr, str(sorted(hdr)))
        w._on_col_filter_applied(col["channel"], "exclude", ["Security"])
        n3 = want(lambda e: e["computer"] == "HOST-1" and e["channel"] != "Security")
        check(f"{tag}: changing the Channel filter still keeps the Computer filter", rows() == n3, f"{rows()} vs {n3}")
        w._on_col_filter_applied(col["channel"], "clear", [])
        check(f"{tag}: clearing the Channel filter leaves only the Computer filter", rows() == n1, f"{rows()} vs {n1}")
        w._on_col_filter_applied(col["computer"], "clear", [])
        check(f"{tag}: clearing the Computer column through its popup clears the context-menu filter",
              rows() == len(evs), f"{rows()} vs {len(evs)}")
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
