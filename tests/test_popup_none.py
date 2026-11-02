"""'None' in a column popup shows nothing, even when the popup is capped.

Found by Codex in audit-5 (E5-09): a column popup lists at most 1,000
values.  "None" + OK sent "exclude the listed values", so every value past
the cap stayed visible (125,295 Normal / 1,641,473 JM rows instead of 0 on a
custom RecordID column).  Expected: "None" means no event, for numeric and
text columns, in both modes.  Also: Juggernaut turned a non-numeric value in
a numeric column's filter into 0, so it matched events whose value is 0.
Synthetic events (1,200 distinct Event IDs; the popup is given the first
1,000, as the capped value query would).
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
N = 1200


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QPushButton
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.main_window import ColumnFilterPopup
    from evtx_tool.gui.models import compute_custom_values
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec, arrow_column_values
    eid_col = next(i for i, k in ColumnFilterPopup.FILTERABLE.items() if k == "event_id")
    evs = [T.ev(r"C:\c\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i), i) for i in range(N)]
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
        cc = compile_spec(CustomColumnSpec(col_id=601, title="Rec", template="{EventRecordID}"))
        model = w._custom_cols_model()
        vals = (arrow_column_values(cc, model._full_table, w._hw_model._get_shard_paths()) if jm
                else compute_custom_values(cc, model._events))
        cc_col = model.add_custom_column(cc, vals)
        T.pump(300)
        for label, col, values in (("Event ID (numeric)", eid_col, {str(i): 1 for i in range(1000)}),
                                   ("custom column (text)", cc_col, {str(i + 1): 1 for i in range(1000)})):
            pop = ColumnFilterPopup(col, values, parent=w)
            pop.filterApplied.connect(w._on_col_filter_applied)
            pop.show(); T.pump(100)                     # None acts on the rows the user sees
            next(b for b in pop.findChildren(QPushButton) if b.text() == "None").click()
            next(b for b in pop.findChildren(QPushButton) if b.text() == "OK").click()
            T.pump(200)
            check(f"{tag}: 'None' on a capped {label} popup shows no event", rows() == 0, f"{rows()} of {N}")
            w._on_col_filter_applied(col, "clear", [])
            check(f"{tag}: ...and clearing brings every event back", rows() == N, str(rows()))
        if jm:
            w._hw_model.set_quick_filters([{"key": "event_id", "value": "abc", "include": True}])
            check("JM: a non-numeric value in a numeric column's filter matches no event (not 0)", rows() == 0,
                  f"{rows()} (event 0 exists)")
            w._hw_model.set_quick_filters([])
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
