"""Editing a custom column drops its old filter even when another tab is in front (Gemini audit 5-10 part 3).

A custom column's edit is computed in a worker.  When it finished, the old
filter on the column was dropped only if the tab in front was the edited one:
an analyst who switched tabs meanwhile came back to a tab still filtered by
the OLD formula's values -- values the column no longer has, so most or all of
its events were hidden, with nothing saying why.  Expected: the old filter is
dropped in the edited tab (and its header record), whichever tab is in front,
and every event of that tab is shown again; the other tab is untouched.
Synthetic events, Normal mode.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
A, B = r"C:\c\A.evtx", r"C:\c\B.evtx"
TYPES = ["3", "10", "2", "3", "3", "11", "10"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import EventTableModel, compute_custom_values
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec

    evs = []
    for f in (A, B):
        for lt in TYPES:
            evs.append(T.ev(f, len(evs) + 1, "HOST", T.T0 + timedelta(seconds=len(evs)), 4624,
                            data={"LogonType": lt}))
    w = mw.MainWindow()
    w._view_mode = "separate"
    m = T.Mode(mw, False)
    m.load(w, evs)
    for f in (A, B):
        es = [e for e in evs if e["source_file"] == f]
        w._per_file_data[f] = {"events": es, "search_cache": [EventTableModel._build_search_str(e) for e in es]}
        w._create_file_tab(f)
    tabs = w._events_tab_widget
    tabs.setCurrentIndex(tabs.indexOf(w._file_tabs[A].table))
    T.pump(100)
    st, other = w._file_tabs[A], w._file_tabs[B]

    col = compile_spec(CustomColumnSpec(col_id=201, title="Logon Type", template="{Data[LogonType]}"))
    idx = st.model.add_custom_column(col, compute_custom_values(col, st.model._events))
    w._on_col_filter_applied(idx, "include", ["3"])
    T.pump(50)
    check("tab A is filtered to LogonType 3", st.proxy.rowCount() == 3, str(st.proxy.rowCount()))

    # Edit the column; while it is computed the analyst switches to tab B.
    col2 = compile_spec(CustomColumnSpec(col_id=201, title="Logon", template="type {Data[LogonType]}"))
    vals2 = compute_custom_values(col2, st.model._events)
    tabs.setCurrentIndex(tabs.indexOf(other.table))
    T.pump(100)
    w._on_custom_column_ready(st.model, col2, vals2, True, quiet=True, gen=getattr(w, "_dataset_gen", 0))
    T.pump(100)
    left = [q for q in st.proxy.get_quick_filters() if q.get("key") == "custom:201"]
    check("the old filter is gone from tab A", not left, str(left))
    check("tab A shows all its events again", st.proxy.rowCount() == len(TYPES), str(st.proxy.rowCount()))
    rec = w._col_filters.get(A, {})
    check("tab A's column-filter record no longer names it",
          all(v[2] != "custom:201" for v in rec.values()), str(rec))
    check("tab B is untouched", other.proxy.rowCount() == len(TYPES))
    check("the edited column shows the new values",
          "type 3" in [st.model.data(st.model.index(r, idx)) for r in range(st.model.rowCount())])

    T.teardown(w, False, m)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
