"""Custom columns in Normal mode: a real column of the tab it was added to.

Spec item 4: "The extracted value should appear as a normal column in the
table for every event: sortable, filterable ... per-tab, and the user can
remove or edit them."  Here the Normal model side: values per row, header,
numeric sort for an Integer column, the column popup's values and the column
filter, edit, remove, and a second tab left untouched.  Synthetic events.
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
A, B = r"C:\c\A.evtx", r"C:\c\B.evtx"
TYPES = ["3", "10", "2", "3", None, "3", "11", "10"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import EventTableModel, COLUMNS, compute_custom_values
    from evtx_tool.gui.jm_col_worker import NormalColValueWorker
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec

    evs = []
    for f in (A, B):
        for i, lt in enumerate(TYPES):
            ed = {"LogonType": lt} if lt is not None else {"Other": "x"}
            evs.append(T.ev(f, len(evs) + 1, "HOST", T.T0 + timedelta(seconds=len(evs)), 4624, data=ed))
    w = mw.MainWindow()
    w._view_mode = "separate"
    T.Mode(mw, False).load(w, evs)
    for f in (A, B):
        es = [e for e in evs if e["source_file"] == f]
        w._per_file_data[f] = {"events": es, "search_cache": [EventTableModel._build_search_str(e) for e in es]}
        w._create_file_tab(f)
    w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(w._file_tabs[A].table))
    T.pump(100)
    st, other = w._file_tabs[A], w._file_tabs[B]
    model, proxy = st.model, st.proxy

    col = compile_spec(CustomColumnSpec(col_id=101, title="Logon Type", template="{Data[LogonType]}", kind="int"))
    vals = compute_custom_values(col, model._events)
    idx = model.add_custom_column(col, vals)
    check("the column is added after the built-in ones", idx == len(COLUMNS) and model.columnCount() == len(COLUMNS) + 1)
    check("its header is the title", model.headerData(idx, Qt.Orientation.Horizontal) == "Logon Type")
    shown = [model.data(model.index(r, idx)) for r in range(model.rowCount())]
    want = [lt or "" for lt in TYPES]
    check("every row shows its own value (empty where the event has none)", shown == want, str(shown))
    check("the other tab has no such column", other.model.columnCount() == len(COLUMNS))
    check("the tab knows the column's filter key", w._col_key_for(idx) == "custom:101", w._col_key_for(idx))

    model.sort(idx, Qt.SortOrder.AscendingOrder)
    got = [model.data(model.index(r, idx)) for r in range(model.rowCount())]
    check("an Integer column sorts by number (2 < 3 < 10 < 11), empty last",
          got == ["2", "3", "3", "3", "10", "10", "11", ""], str(got))

    worker = NormalColValueWorker(list(model._events), "custom:101")
    counts = {}
    worker.finished.connect(lambda d: counts.update(d))
    worker.run()
    check("the column popup counts its values", counts.get("3") == 3 and counts.get("10") == 2 and counts.get("") == 1,
          str(counts))

    w._on_col_filter_applied(idx, "include", ["3", "11"])
    T.pump(50)
    check("the column filter keeps exactly the chosen values", proxy.rowCount() == 4, str(proxy.rowCount()))
    check("...and only in this tab", other.proxy.rowCount() == len(TYPES))
    w._on_col_filter_applied(idx, "exclude", ["3"])
    T.pump(50)
    check("an exclude on the column", proxy.rowCount() == len(TYPES) - 3, str(proxy.rowCount()))

    col2 = compile_spec(CustomColumnSpec(col_id=101, title="Logon", template="type {Data[LogonType]}", kind="text"))
    model.update_custom_column(101, col2, compute_custom_values(col2, model._events))
    check("editing changes the title and recomputes the values",
          model.column_title(idx) == "Logon"
          and "type 3" in [model.data(model.index(r, idx)) for r in range(model.rowCount())])
    w._remove_custom_column(101)
    T.pump(50)
    check("removing drops the column", model.columnCount() == len(COLUMNS))
    check("...and its filter, so every event is back", proxy.rowCount() == len(TYPES), str(proxy.rowCount()))

    many = [T.ev(A, i, "HOST", T.T0 + timedelta(seconds=i), 4624, data={"LogonType": str(i % 12)}) for i in range(200_000)]
    t = time.perf_counter()
    compute_custom_values(compile_spec(CustomColumnSpec(col_id=7, title="x", template="{Data[LogonType]}")), many)
    dt = time.perf_counter() - t
    check("200,000 events evaluate in under 3 s", dt < 3, f"{dt:.2f} s")
    w.close(); T.pump(50)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
