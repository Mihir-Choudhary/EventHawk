"""Custom columns: what the dialog shows while editing, where to start one,
and columns surviving a new parse.

  A. Dialog: a preview line shows the column's value for the selected event
     (or why it is empty / not valid yet) as the definition is typed; the
     event's own data fields are listed first; the field list filters by name
     or value; "This event (4624)" fills the Event ID filter.
  B. The event table's right-click menu offers Add Custom Column (the
     right-clicked event is the picker's sample).
  C. A new parse keeps the main table's custom columns: their definitions are
     rebuilt on the new events, without a message box per column (they used to
     vanish with every parse) -- Normal and Juggernaut.

Synthetic events.
Run: QT_QPA_PLATFORM=offscreen python tests/test_custom_column_ux.py
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
TYPES = ["3", "10", "2", "3", None, "3"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events(base=0, types=TYPES):
    out = []
    for i, lt in enumerate(types):
        ed = {"LogonType": lt, "IpAddress": f"10.0.0.{i}"} if lt is not None else {"Other": "x"}
        out.append(T.ev(r"C:\c\Security.evtx", base + i + 1, "HOST",
                        T.T0 + timedelta(seconds=base + i), 4624, data=ed))
    return out


def main() -> int:
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])  # noqa: F841
    from evtx_tool.gui.custom_column_dialog import CustomColumnDialog
    from evtx_tool.core.custom_columns import compile_spec, CustomColumnSpec
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import COLUMNS

    boxes = []
    for _n in ("warning", "information", "critical"):
        setattr(QMessageBox, _n, staticmethod(lambda *a, **k: boxes.append(a[1:3])))

    print("=== A. dialog ===")
    d = CustomColumnDialog(col_id=1, sample_event=events()[0])
    first = d._tree.topLevelItem(0).data(0, 0x0100 + 1)     # the token role
    check("the event's data fields come first in the picker", str(first).startswith("{Data["), str(first))
    check("an empty Value says how to start", "type a Value" in d._lbl_preview.text(), d._lbl_preview.text())
    d._inp_value.setText("{Data[LogonType]}")
    check("the preview shows the selected event's value",
          d._lbl_preview.text() == "For the selected event: 3", d._lbl_preview.text())
    d._inp_value.setText("Type {Data[LogonType]} from {Data[IpAddress]}")
    check("...for a template with text around the fields",
          d._lbl_preview.text() == "For the selected event: Type 3 from 10.0.0.0", d._lbl_preview.text())
    d._inp_value.setText("{Data[LogonType]")
    check("an unfinished token says it is not valid yet", d._lbl_preview.text().startswith("Not valid yet"),
          d._lbl_preview.text())
    d._inp_value.setText("{Data[NoSuchField]}")
    check("a field the event lacks previews as empty, and says why",
          "no such field" in d._lbl_preview.text(), d._lbl_preview.text())
    d._inp_value.setText("{Data[LogonType]}")
    d._inp_eids.setText("4625")
    check("an Event ID filter that leaves the event out says so",
          "outside the column's Event ID" in d._lbl_preview.text(), d._lbl_preview.text())
    d._inp_eids.setText("12x")
    check("an invalid Event ID filter is reported at once", d._lbl_preview.text().startswith("Event ID filter"),
          d._lbl_preview.text())
    check("there is a 'This event' button for the Event ID filter",
          d._btn_this_eid is not None and "4624" in d._btn_this_eid.text())
    d._btn_this_eid.click()
    check("...which fills the filter with the event's ID", d._inp_eids.text() == "4624", d._inp_eids.text())
    check("...and the preview is back to the value", d._lbl_preview.text() == "For the selected event: 3",
          d._lbl_preview.text())
    d._inp_field_filter.setText("ipaddr")
    shown = [d._tree.topLevelItem(i).text(0) for i in range(d._tree.topLevelItemCount())
             if not d._tree.topLevelItem(i).isHidden()]
    check("the field filter narrows the list by name", len(shown) == 1 and "IpAddress" in shown[0], str(shown))
    d._inp_field_filter.setText("10.0.0.0")
    shown = [d._tree.topLevelItem(i).text(0) for i in range(d._tree.topLevelItemCount())
             if not d._tree.topLevelItem(i).isHidden()]
    check("...and by value", shown and "IpAddress" in shown[0], str(shown))
    d2 = CustomColumnDialog(col_id=2, sample_event=None)
    check("with no event selected there is no 'This event' button", d2._btn_this_eid is None)

    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        print(f"\n=== B/C. {tag} ===")
        m = T.Mode(mw, jm)
        w = mw.MainWindow()
        m.load(w, events())
        if jm:
            w._table.setModel(w._hw_model)
        T.pump(300)
        w._table.selectRow(0)
        T.pump(100)

        # B. the row menu
        seen = {}

        def grab():
            pop = QApplication.activePopupWidget()
            if pop is None:
                return QTimer.singleShot(50, grab)
            seen["acts"] = [a.text() for a in pop.actions()]
            pop.close()
        QTimer.singleShot(100, grab)
        r = w._table.visualRect(w._table.model().index(0, 4))
        w._on_table_context_menu(r.center())
        T.pump(200)
        check(f"{tag}: the event menu offers Add Custom Column",
              "Add Custom Column\u2026" in seen.get("acts", []), str(seen.get("acts")))

        # C. carried across a new parse
        main = w._hw_model if jm else w._event_model
        spec = CustomColumnSpec(col_id=7, title="Logon Type", template="{Data[LogonType]}",
                                eid_expr="", providers=(), kind="int")
        spec2 = CustomColumnSpec(col_id=8, title="Nothing", template="{Data[NoSuchField]}",
                                 eid_expr="", providers=(), kind="text")
        w._compute_custom_column(main, compile_spec(spec), editing=False, quiet=True)
        w._compute_custom_column(main, compile_spec(spec2), editing=False, quiet=True)
        T.wait_for(lambda: main.columnCount() == len(COLUMNS) + 2, 30); T.pump(300)
        w._remember_custom_columns()
        n_boxes = len(boxes)
        new = events(base=100, types=["5", "5", "11"])
        m2 = T.Mode(mw, jm)
        m2.load(w, new)
        if jm:
            w._table.setModel(w._hw_model)
        else:
            T.pump(100)
        main2 = w._hw_model if jm else w._event_model
        check(f"{tag}: loading new events clears the old columns (as before)",
              main2.columnCount() == len(COLUMNS), str(main2.columnCount()))
        w._carry_custom_columns()
        T.wait_for(lambda: main2.columnCount() == len(COLUMNS) + 2, 30); T.pump(400)
        idx = main2.custom_col_index(7)
        vals = sorted(str(main2.data(main2.index(r, idx)) or "") for r in range(main2.rowCount())) if idx else []
        check(f"{tag}: the columns come back, computed on the new events",
              idx is not None and vals == ["11", "5", "5"], f"{idx} {vals}")
        check(f"{tag}: ...with no message box (also for the one that matches nothing here)",
              len(boxes) == n_boxes, str(boxes[n_boxes:]))
        w._carry_custom_columns()
        T.pump(300)
        check(f"{tag}: carrying again does not duplicate them", main2.columnCount() == len(COLUMNS) + 2)
        w._remember_custom_columns()
        w._file_list.clear()
        w._on_clear_files()
        check(f"{tag}: clearing the file list deliberately forgets them",
              not getattr(w, "_carry_specs", None))
        w.close(); T.pump(150)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
