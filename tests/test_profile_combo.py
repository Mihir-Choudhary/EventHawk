"""Clicking a profile must select it — once.

Reported: a profile in the dropdown "gets deselected instantly" on click.
Cause: the row was toggled TWICE per click. Our handler ran on mouse PRESS,
then Qt's own ItemIsUserCheckable handling in QAbstractItemView toggled it
again on RELEASE. Net effect: it flicked on and straight back off.

These checks drive real mouse events through the popup viewport, because the
bug only exists in the press/release pair — calling the toggle method directly
would have passed throughout.

Run: QT_QPA_PLATFORM=offscreen python tests/test_profile_combo.py
"""
import os, sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt, QEvent, QPointF
    from PySide6.QtGui import QMouseEvent
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import CheckableComboBox

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    names = ["Logon Activity", "Process Creation", "PowerShell", "Service Install"]
    c = CheckableComboBox()
    for n in names:
        c.addCheckItem(n, checked=False)
    c.showPopup(); app.processEvents()
    view = c.view()

    def real_click(row: int, x_off: int):
        """A genuine press+release pair over the row, as a mouse would send."""
        rect = view.visualRect(c._proxy_model.index(row, 0))
        pos = QPointF(rect.left() + x_off, rect.center().y())
        for t in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease):
            app.sendEvent(view.viewport(), QMouseEvent(
                t, pos, Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                Qt.KeyboardModifier.NoModifier))
        app.processEvents()
        return c._chk_model.item(row).checkState()

    # on the checkbox indicator AND on the label — both used to double-toggle
    check("clicking the checkbox square selects the profile",
          real_click(0, 8) == Qt.CheckState.Checked)
    check("clicking it again deselects it",
          real_click(0, 8) == Qt.CheckState.Unchecked)
    check("clicking the profile NAME selects it",
          real_click(1, 90) == Qt.CheckState.Checked)
    check("clicking the name again deselects it",
          real_click(1, 90) == Qt.CheckState.Unchecked)

    # the popup must stay open so several profiles can be picked in one go
    c.showPopup(); app.processEvents()
    real_click(0, 60); real_click(2, 60); real_click(3, 60)
    check("multiple profiles can be selected without the popup closing",
          view.isVisible(), "popup closed after the first click")
    got = set(c.checkedItems())
    check("every clicked profile is reported as checked",
          got == {names[0], names[2], names[3]}, str(sorted(got)))

    # deselecting one must not disturb the others
    real_click(2, 60)
    got = set(c.checkedItems())
    check("deselecting one profile leaves the rest checked",
          got == {names[0], names[3]}, str(sorted(got)))

    # the search filter remaps rows; a click must still hit the right profile
    c.setFilterText("PowerShell"); app.processEvents()
    if c._proxy_model.rowCount() == 1:
        rect = view.visualRect(c._proxy_model.index(0, 0))
        pos = QPointF(rect.left() + 60, rect.center().y())
        for t in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonRelease):
            app.sendEvent(view.viewport(), QMouseEvent(
                t, pos, Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton,
                Qt.KeyboardModifier.NoModifier))
        app.processEvents()
        got = set(c.checkedItems())
        check("clicking a SEARCH-FILTERED row toggles that same profile",
              "PowerShell" in got, str(sorted(got)))
    else:
        check("search filter narrowed the list", False,
              f"{c._proxy_model.rowCount()} rows")
    c.setFilterText(""); app.processEvents()

    # checkAll / uncheckAll still work
    c.checkAll(); app.processEvents()
    check("checkAll selects everything", set(c.checkedItems()) == set(names),
          str(sorted(c.checkedItems())))
    c.uncheckAll(); app.processEvents()
    check("uncheckAll clears everything", not c.checkedItems(),
          str(c.checkedItems()))

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
