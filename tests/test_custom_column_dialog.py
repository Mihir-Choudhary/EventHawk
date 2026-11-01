"""Add / edit / remove a custom column through its dialog and the header menu.

Spec item 4: "Add Custom Column ... from a right-click on a column header ...
Column title, Value, a field picker ... from a sample event ... click a field
instead of typing ... optional Event ID / Provider filter ... Text or Integer
... the user can remove or edit them."  R-6: a System field EventHawk does
not keep is refused in the dialog (it stays open); a field no event in the tab
has gets a warning with Edit / Keep.  The dialog is driven through its own
widgets; the window flow in Normal and Juggernaut.  Synthetic events.
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


def events():
    out = []
    for i, lt in enumerate(TYPES):
        ed = {"LogonType": lt, "IpAddress": f"10.0.0.{i}"} if lt is not None else {"Other": "x"}
        out.append(T.ev(r"C:\c\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i), 4624, data=ed))
    return out


def main() -> int:
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QMessageBox, QMenu
    from evtx_tool.gui.custom_column_dialog import CustomColumnDialog
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import COLUMNS

    boxes = []
    real_warning = QMessageBox.warning
    QMessageBox.warning = staticmethod(lambda _p, _t, text, *a, **k: boxes.append(text))

    # ── the dialog's own widgets ──────────────────────────────────────────────
    sample = events()[0]
    d = CustomColumnDialog(col_id=1, sample_event=sample)
    tree = d._tree
    item = next(tree.topLevelItem(i) for i in range(tree.topLevelItemCount())
                if tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole + 1) == "{Data[LogonType]}")
    check("the field picker lists the selected event's fields with values", item.text(1) == "3", item.text(1))
    tree.scrollToItem(item)
    QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier,
                     tree.visualItemRect(item).center())
    check("clicking a field inserts its token", d._inp_value.text() == "{Data[LogonType]}", d._inp_value.text())
    check("...and suggests a title", d._inp_title.text() == "LogonType", d._inp_title.text())
    d._cmb_type.setCurrentIndex(1)
    QTest.mouseClick(d._btn_ok, Qt.MouseButton.LeftButton)
    check("OK accepts a valid column", d.result() == d.DialogCode.Accepted and d.spec().kind == "int")
    d2 = CustomColumnDialog(col_id=2, sample_event=None)
    check("with no event selected the picker offers the System fields and says why",
          d2._tree.topLevelItemCount() > 5 and "select an event" in d2._lbl_hint.text().lower())
    d2._inp_title.setText("x"); d2._inp_value.setText("{Correlation[RelatedActivityID]}")
    n0 = len(boxes)
    QTest.mouseClick(d2._btn_ok, Qt.MouseButton.LeftButton)
    check("a System field EventHawk does not keep is refused and the dialog stays open",
          d2.result() != d2.DialogCode.Accepted and len(boxes) > n0 and "does not keep" in boxes[-1], boxes[-1:])

    # ── the window flow, both modes ──────────────────────────────────────────
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        evs = events()
        w = mw.MainWindow()
        T.Mode(mw, jm).load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
        T.pump(300)
        w._table.selectRow(0)
        T.pump(100)
        model = w._custom_cols_model()
        fill = {}

        def drive():
            dlg = QApplication.activeModalWidget()
            if not isinstance(dlg, CustomColumnDialog):
                return QTimer.singleShot(50, drive)
            fill["prefilled"] = dlg._inp_value.text()
            if fill.get("title") is not None:
                dlg._inp_title.setText(fill["title"])
            if fill.get("value") is not None:
                dlg._inp_value.setText(fill["value"])
            dlg._cmb_type.setCurrentIndex(1 if fill.get("int") else 0)
            QTest.mouseClick(dlg._btn_ok, Qt.MouseButton.LeftButton)

        def keep_warning():
            box = QApplication.activeModalWidget()
            if isinstance(box, QMessageBox):
                fill["warning"] = box.text()
                keep = next(b for b in box.buttons() if b.text().replace("&", "") == "Keep")
                keep.click()
            else:
                QTimer.singleShot(50, keep_warning)

        fill.update(title="Logon Type", value="{Data[LogonType]}", int=True)
        QTimer.singleShot(50, drive)
        w._add_custom_column_dialog()
        T.wait_for(lambda: model.columnCount() == len(COLUMNS) + 1, 30); T.pump(400)
        idx = len(COLUMNS)
        got = [model.data(model.index(r, idx)) for r in range(model.rowCount())]
        check(f"{tag}: the column appears in the tab with every value",
              model.columnCount() == len(COLUMNS) + 1 and sorted(got) == sorted(lt or "" for lt in TYPES), str(got))
        check(f"{tag}: the column is shown", not w._table.isColumnHidden(idx))
        cid = model.col_id_at(idx)

        fill.update(title="Typo", value="{Data[LogonTyp]}", int=False)
        QTimer.singleShot(50, drive)
        QTimer.singleShot(400, keep_warning)
        w._add_custom_column_dialog()
        T.wait_for(lambda: "warning" in fill, 30); T.pump(300)
        check(f"{tag}: a field no event in the tab has is warned about",
              "LogonTyp" in fill.get("warning", "") and "no event" in fill.get("warning", "").lower(),
              fill.get("warning", "")[:120])
        check(f"{tag}: Keep keeps the (empty) column", model.columnCount() == len(COLUMNS) + 2)
        typo_id = model.col_id_at(idx + 1)

        w._on_col_filter_applied(idx, "include", ["3"])
        T.pump(300)
        if jm:
            T.wait_for(lambda: w._hw_model.rowCount() == 3, 30)
        fill.update(title="Logon", value="LT {Data[LogonType]}", int=False)
        fill.pop("prefilled", None)
        QTimer.singleShot(50, drive)
        w._edit_custom_column(cid)
        T.wait_for(lambda: model.column_title(idx) == "Logon", 30); T.pump(400)
        rows = model.rowCount()
        check(f"{tag}: Edit opens the dialog filled in", fill.get("prefilled") == "{Data[LogonType]}", fill.get("prefilled"))
        check(f"{tag}: editing recomputes the values", "LT 3" in [model.data(model.index(r, idx)) for r in range(rows)])
        check(f"{tag}: editing drops the column's old filter", rows == len(TYPES), str(rows))

        seen = {}

        def read_and_close():
            menu = QApplication.activePopupWidget()
            if isinstance(menu, QMenu):
                seen.setdefault("menus", []).append([x.text() for x in menu.actions()])
                menu.close()
            else:
                QTimer.singleShot(50, read_and_close)
        hdr = w._table.horizontalHeader()
        from PySide6.QtCore import QPoint
        QTimer.singleShot(50, read_and_close)
        w._on_header_context_menu(QPoint(hdr.sectionViewportPosition(1) + 5, 5), w._table)
        QTimer.singleShot(50, read_and_close)
        w._on_header_context_menu(QPoint(hdr.sectionViewportPosition(idx) + 5, 5), w._table)
        menus = seen.get("menus", [])
        check(f"{tag}: the header menu offers Add Custom Column",
              menus and any(t.startswith("Add Custom Column") for t in menus[0]), str(menus[:1]))
        check(f"{tag}: on a custom column it also offers Edit and Remove",
              len(menus) > 1 and any(t.startswith("Edit Custom Column") for t in menus[1])
              and "Remove Custom Column" in menus[1], str(menus[1:2]))
        w._remove_custom_column(typo_id)
        w._remove_custom_column(cid)
        T.pump(300)
        check(f"{tag}: removing both leaves the built-in columns", model.columnCount() == len(COLUMNS))
        w.close(); T.pump(100)
    QMessageBox.warning = real_warning

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
