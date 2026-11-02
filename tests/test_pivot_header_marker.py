"""A filtered column in an Around tab carries the header marker, as in any tab.

Found by Codex in audit-5 (E5-13, pre-existing): in an Around (pivot) tab a
column popup filter and a "filter by this value" filtered the rows
correctly, but the column header showed no "▼" marker in either mode, so
the tab looked unfiltered.  Expected: the marker appears on the filtered
column, and goes when the filter is cleared.  Synthetic events.
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
    from PySide6.QtCore import Qt
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.main_window import ColumnFilterPopup
    col = {k: i for i, k in ColumnFilterPopup.FILTERABLE.items()}
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        evs = T.dataset()
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
        key, st = T.open_tab(w, dict(evs[1]), timedelta(days=1), timedelta(days=1), "all", jm)
        check(f"{tag}: the Around tab is in front", key is not None and w._active_file_tab == key,
              str(w._active_file_tab))

        def header(c):
            return str(st.table.model().headerData(c, Qt.Orientation.Horizontal,
                                                   Qt.ItemDataRole.DisplayRole) or "")
        w._on_col_filter_applied(col["computer"], "include", ["WS01"])
        T.pump(300)
        check(f"{tag}: a popup filter in the Around tab marks its column", header(col["computer"]).startswith("▼"),
              header(col["computer"]))
        w._apply_quick_filter("event_id", "4624", True)
        T.pump(300)
        check(f"{tag}: a 'filter by this value' in the Around tab marks its column",
              header(col["event_id"]).startswith("▼"), header(col["event_id"]))
        w._on_col_filter_applied(col["computer"], "clear", [])
        T.pump(300)
        check(f"{tag}: clearing the popup filter removes that marker only",
              not header(col["computer"]).startswith("▼") and header(col["event_id"]).startswith("▼"),
              f"{header(col['computer'])} / {header(col['event_id'])}")

        # A chain tab (events held in memory, also in Juggernaut mode).
        from test_around_review_fixes import _Item
        w._open_chain_events_tab([_Item({"rule_name": "probe", "severity": "high",
                                         "events": [dict(evs[5]), dict(evs[9])]})])
        ckey = [k for k in w._file_tabs if k.startswith("__chain__")][-1]
        st = w._file_tabs[ckey]
        T.pump(100)
        w._on_col_filter_applied(col["computer"], "include", ["OTHER"])
        T.pump(300)
        check(f"{tag}: a popup filter in a chain tab marks its column", header(col["computer"]).startswith("▼"),
              header(col["computer"]))
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
