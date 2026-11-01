"""A column filter applies only to the tab it was set in (spec R-4).

User (2026-11-01): "applying a quick column filter (click column name -> pick
values -> Apply) applies to all open tabs.  That's wrong.  ... the filter
applies only to the tab where it was applied.  Each tab keeps its own
independent filter state.  Clearing or changing a filter in one tab must not
affect other tabs.  No prompt asking which tabs to apply to is needed."
R-4: "Clear All Filters" still resets every tab; a tab's own badge clears only
that tab.  Separate view, Normal and Juggernaut, synthetic events: each tab's
count is checked against a count of its own events.
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
A, B = r"C:\c\A.evtx", r"C:\c\B.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import EventTableModel
    from evtx_tool.gui.main_window import ColumnFilterPopup
    eid_col = next(i for i, k in ColumnFilterPopup.FILTERABLE.items() if k == "event_id")
    prompts = []
    real_dlg = mw._FilterTargetDialog

    class _Spy(real_dlg):
        def __init__(self, *a, **k):
            prompts.append(1)
            super().__init__(*a, **k)

        def exec(self):
            return mw.QDialog.DialogCode.Accepted
    mw._FilterTargetDialog = _Spy

    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        evs = []
        for f in (A, B):
            for eid in (4624, 4624, 7036, 4634):
                evs.append(T.ev(f, len(evs) + 1, "HOST", T.T0 + timedelta(seconds=len(evs)), eid))
        w = mw.MainWindow()
        w._view_mode = "separate"
        T.Mode(mw, jm).load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
            # as _on_hw_finished stages them for the file tree
            w._jm_pending = {f: w._hw_model._full_table for f in (A, B)}
            for f in (A, B):
                w._open_jm_file_tab(f)
        else:
            for f in (A, B):
                es = [e for e in evs if e["source_file"] == f]
                w._per_file_data[f] = {"events": es,
                                       "search_cache": [EventTableModel._build_search_str(e) for e in es]}
                w._create_file_tab(f)
        T.pump(300)

        def go(tab):
            idx = w._events_tab_widget.indexOf(w._table if tab is None else w._file_tabs[tab].table)
            w._events_tab_widget.setCurrentIndex(idx)
            T.pump(150)

        def rows(tab):
            if jm:
                m = w._hw_model if tab is None else w._file_tabs[tab].model
                T.wait_for(lambda: m._filter_thread._q.empty(), 30); T.pump(250)
                return m.rowCount()
            return (w._proxy_model if tab is None else w._file_tabs[tab].proxy).rowCount()

        go(A)
        w._on_col_filter_applied(eid_col, "include", ["4624"])
        check(f"{tag}: the filter narrows the tab it was set in", rows(A) == 2, str(rows(A)))
        check(f"{tag}: ...and no other tab", rows(B) == 4 and rows(None) == 8, f"B {rows(B)}, All {rows(None)}")
        check(f"{tag}: no prompt asked which tabs to filter", not prompts, str(len(prompts)))
        go(B)
        w._on_col_filter_applied(eid_col, "exclude", ["7036"])
        check(f"{tag}: a different filter in another tab", rows(B) == 3 and rows(A) == 2, f"B {rows(B)}, A {rows(A)}")
        check(f"{tag}: each tab marks only its own filtered column",
              (w._file_tabs[B].model if jm else w._file_tabs[B].model)._header_overrides.get(eid_col, "").startswith("\u25bc"))
        w._apply_quick_filter("event_id", "4634", True)       # "filter by this value"
        check(f"{tag}: 'filter by this value' also stays in its tab", rows(B) == 1 and rows(A) == 2,
              f"B {rows(B)}, A {rows(A)}")
        w._btn_clear_quick.click()
        check(f"{tag}: the tab's own clear clears only that tab", rows(B) == 4 and rows(A) == 2,
              f"B {rows(B)}, A {rows(A)}")
        go(A)
        w._on_col_filter_applied(eid_col, "include", ["4624", "4634"])
        check(f"{tag}: changing the filter in a tab", rows(A) == 3 and rows(B) == 4, f"A {rows(A)}, B {rows(B)}")
        go(None)
        w._on_col_filter_applied(eid_col, "include", ["7036"])
        check(f"{tag}: All Events has its own filter", rows(None) == 2 and rows(A) == 3, f"All {rows(None)}, A {rows(A)}")
        w._close_file_tab(A)
        if jm:
            w._open_jm_file_tab(A)
        else:
            w._create_file_tab(A)
        T.pump(200)
        go(A)
        check(f"{tag}: a closed and reopened tab starts unfiltered", rows(A) == 4
              and not w._col_filters.get(A), f"{rows(A)} {w._col_filters.get(A)}")
        go(B)
        w._on_col_filter_applied(eid_col, "include", ["4624"])
        w._btn_clear_all_filters.click()
        T.pump(300)
        check(f"{tag}: Clear All Filters resets every tab", rows(None) == 8 and rows(A) == 4 and rows(B) == 4,
              f"All {rows(None)}, A {rows(A)}, B {rows(B)}")
        w.close(); T.pump(100)
    mw._FilterTargetDialog = real_dlg

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
