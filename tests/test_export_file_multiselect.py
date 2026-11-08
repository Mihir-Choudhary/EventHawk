"""Export "Specific files": highlight several rows and tick them together.

The checklist already filters by name, keeps hidden rows' ticks, and has All /
None (every row) and Select shown / Clear shown (visible rows) -- see
test_export_file_picker.py, which must keep passing unchanged.  What it lacked
is selecting several rows at once from the keyboard or mouse, which matters
with hundreds of logs.  Ticked still means "will be exported"; "highlighted"
is the new, separate marking.

Driven with REAL mouse and key events on the real checkbox rows:

  * a plain click still ticks / unticks just that row (unchanged);
  * Ctrl+click highlights without ticking; Shift+click highlights a range of
    the SHOWN rows; Ctrl+A highlights every shown row; Shift+Down extends;
  * Space and "Tick / Untick highlighted" change every highlighted row, and a
    plain click on a highlighted row applies to all of them;
  * the filter never changes ticks, and drops hidden rows from the highlight;
  * All / None still act on every row (hidden ones included) and Select shown
    / Clear shown on the shown rows only;
  * the count line adds "N highlighted" only while something is highlighted.

Run: QT_QPA_PLATFORM=offscreen python tests/test_export_file_multiselect.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication, QPushButton
    from PySide6.QtCore import Qt, QPoint
    from PySide6.QtTest import QTest
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw

    paths = [rf"C:\case\host{i:02d}\{n}.evtx" for i in range(10) for n in ("Security", "System", "Application")]
    N = len(paths)
    dlg = mw._ExportScopeDialog(paths, None, "separate", 999, None)
    dlg._rb_specific.setChecked(True)
    dlg.show(); app.processEvents()
    rows = [c for c, _fp in dlg._file_checks]

    def ticked():
        return {fp for c, fp in dlg._file_checks if c.isChecked()}

    def hl():
        return sorted(dlg._hl_rows)

    def click(i, mods=Qt.KeyboardModifier.NoModifier):
        c = rows[i]
        c.parentWidget().parentWidget().parentWidget().ensureWidgetVisible(c) \
            if hasattr(c.parentWidget().parentWidget().parentWidget(), "ensureWidgetVisible") else None
        QTest.mouseClick(c, Qt.MouseButton.LeftButton, mods, QPoint(8, c.height() // 2))
        app.processEvents()

    def key(i, k, mods=Qt.KeyboardModifier.NoModifier):
        rows[i].setFocus()
        QTest.keyClick(rows[i], k, mods)
        app.processEvents()

    click(0)
    check("a plain click still unticks just that row", ticked() == set(paths) - {paths[0]})
    click(0)
    check("…and ticks it again", ticked() == set(paths))
    check("the count line is unchanged while nothing is highlighted",
          dlg._lbl_file_count.text() == f"{N} of {N} shown, {N} selected", dlg._lbl_file_count.text())
    check("Tick/Untick highlighted start disabled",
          not dlg._btn_tick_hl.isEnabled() and not dlg._btn_untick_hl.isEnabled())

    click(1, Qt.KeyboardModifier.ControlModifier)
    click(3, Qt.KeyboardModifier.ControlModifier)
    check("Ctrl+click highlights rows without ticking them",
          hl() == [1, 3] and ticked() == set(paths), f"{hl()}")
    click(6, Qt.KeyboardModifier.ShiftModifier)
    check("Shift+click highlights the range from the anchor", hl() == [3, 4, 5, 6], f"{hl()}")
    check("the count line says how many are highlighted",
          dlg._lbl_file_count.text().endswith(", 4 highlighted"), dlg._lbl_file_count.text())
    check("Tick/Untick highlighted are enabled", dlg._btn_tick_hl.isEnabled())

    key(6, Qt.Key.Key_Space)
    check("Space unticks every highlighted row",
          ticked() == set(paths) - {paths[i] for i in (3, 4, 5, 6)}, f"{N - len(ticked())} unticked")
    key(6, Qt.Key.Key_Space)
    check("Space again ticks them back", ticked() == set(paths))
    dlg._btn_untick_hl.click(); app.processEvents()
    check("'Untick highlighted' unticks exactly the highlighted rows",
          ticked() == set(paths) - {paths[i] for i in (3, 4, 5, 6)})
    click(5)
    check("a plain click on a highlighted row applies to all highlighted rows",
          ticked() == set(paths) and hl() == [3, 4, 5, 6], f"{N - len(ticked())} unticked, hl={hl()}")

    key(6, Qt.Key.Key_Down, Qt.KeyboardModifier.ShiftModifier)
    check("Shift+Down extends the highlight", hl() == [3, 4, 5, 6, 7], f"{hl()}")
    key(7, Qt.Key.Key_Escape)
    check("Escape clears the highlight", hl() == [])

    # ── filter: ticks kept, highlight limited to shown rows ──────────────────
    dlg._inp_file_search.setText("system"); app.processEvents()
    shown = [i for i, c in enumerate(rows) if not c.isHidden()]
    key(shown[0], Qt.Key.Key_A, Qt.KeyboardModifier.ControlModifier)
    check("Ctrl+A highlights every shown row and nothing hidden", hl() == shown, f"{len(hl())} of {len(shown)}")
    dlg._btn_untick_hl.click(); app.processEvents()
    check("…so 'Untick highlighted' leaves hidden rows' ticks alone",
          ticked() == {p for p in paths if not p.endswith("System.evtx")})
    click(shown[0], Qt.KeyboardModifier.ControlModifier)
    dlg._inp_file_search.setText("security"); app.processEvents()
    check("a filter change drops now-hidden rows from the highlight", hl() == [], f"{hl()}")
    check("…and never changes a tick", ticked() == {p for p in paths if not p.endswith("System.evtx")})

    # ── existing buttons keep their scopes ───────────────────────────────────
    dlg._btn_clear_shown.click(); app.processEvents()
    check("Clear shown still unticks only the shown rows",
          ticked() == {p for p in paths if p.endswith("Application.evtx")})
    btns = {b.text(): b for b in dlg._files_box.findChildren(QPushButton)}
    btns["All"].click(); app.processEvents()
    check("All still ticks every row, hidden ones included", ticked() == set(paths))
    btns["None"].click(); app.processEvents()
    check("None still unticks every row, hidden ones included", ticked() == set())
    dlg._btn_select_shown.click(); app.processEvents()
    check("Select shown still ticks only the shown rows",
          ticked() == {p for p in paths if p.endswith("Security.evtx")})
    dlg._inp_file_search.setText(""); app.processEvents()
    check("selected_files() returns exactly the ticked paths",
          dlg.selected_files() == {p for p in paths if p.endswith("Security.evtx")})
    dlg.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
