"""Export "Specific files": tick or untick a range of files in one go.

The checklist already filters by name, keeps hidden rows' ticks, and has All /
None (every row) and Select shown / Clear shown (visible rows) -- see
test_export_file_picker.py, which must keep passing unchanged.  What it lacked
is picking a set of files quickly -- "only these 10 / 50 of 272 logs".

There is ONE kind of selection: the tick (= will be exported).  Driven with
REAL mouse and key events on the real checkbox rows:

  * a plain (or Ctrl+) click ticks / unticks just that row, as before, and
    becomes the anchor;
  * Shift+click gives every SHOWN row between the anchor and the clicked row
    the anchor's state -- so None, click file 1, Shift+click file 10 selects
    exactly those 10; on an unticked anchor it unticks the range;
  * rows hidden by the filter inside the range keep their tick;
  * keyboard: Up/Down move between shown rows (scrolling them into view),
    Space ticks / unticks the focused row, Shift+Up/Down extend the anchor's
    state, Ctrl+A ticks every shown row;
  * the count line keeps its format; there is no second, "highlighted" state.

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
    from PySide6.QtWidgets import QApplication, QPushButton, QScrollArea
    from PySide6.QtCore import Qt, QPoint
    from PySide6.QtTest import QTest
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw

    SHIFT, CTRL = Qt.KeyboardModifier.ShiftModifier, Qt.KeyboardModifier.ControlModifier

    def make(paths):
        dlg = mw._ExportScopeDialog(paths, None, "separate", 999, None)
        dlg._rb_specific.setChecked(True)
        dlg.show(); app.processEvents()
        return dlg

    def scroll_of(dlg):
        return next(s for s in dlg._files_box.findChildren(QScrollArea))

    def ticked(dlg):
        return {fp for c, fp in dlg._file_checks if c.isChecked()}

    def click(dlg, i, mods=Qt.KeyboardModifier.NoModifier):
        c = dlg._file_checks[i][0]
        scroll_of(dlg).ensureWidgetVisible(c)
        app.processEvents()
        QTest.mouseClick(c, Qt.MouseButton.LeftButton, mods, QPoint(8, c.height() // 2))
        app.processEvents()

    def key(dlg, i, k, mods=Qt.KeyboardModifier.NoModifier):
        c = dlg._file_checks[i][0]
        c.setFocus(); app.processEvents()
        QTest.keyClick(c, k, mods)
        app.processEvents()

    def btn(dlg, text):
        return next(b for b in dlg._files_box.findChildren(QPushButton) if b.text() == text)

    paths = [rf"C:\case\host{i:02d}\{n}.evtx" for i in range(10) for n in ("Security", "System", "Application")]
    N = len(paths)
    dlg = make(paths)

    # ── single rows: unchanged ───────────────────────────────────────────────
    click(dlg, 0)
    check("a plain click still unticks just that row", ticked(dlg) == set(paths) - {paths[0]})
    click(dlg, 0)
    check("…and ticks it again", ticked(dlg) == set(paths))
    check("the count line keeps its format",
          dlg._lbl_file_count.text() == f"{N} of {N} shown, {N} selected", dlg._lbl_file_count.text())
    click(dlg, 2, CTRL)
    check("Ctrl+click also ticks / unticks just that row", ticked(dlg) == set(paths) - {paths[2]})
    click(dlg, 2)

    # ── "only these 10": None, click, Shift+click ────────────────────────────
    btn(dlg, "None").click(); app.processEvents()
    click(dlg, 0)
    click(dlg, 9, SHIFT)
    check("None, click file 1, Shift+click file 10 -> exactly those 10 selected",
          ticked(dlg) == set(paths[0:10]), f"{len(ticked(dlg))} selected")
    check("the count line says 10 selected",
          dlg._lbl_file_count.text() == f"{N} of {N} shown, 10 selected", dlg._lbl_file_count.text())
    click(dlg, 20)
    click(dlg, 14, SHIFT)
    check("a second range adds to the first, and works upwards too",
          ticked(dlg) == set(paths[0:10]) | set(paths[14:21]), f"{len(ticked(dlg))} selected")
    click(dlg, 5)                      # unticks 5 -> anchor is unticked
    click(dlg, 8, SHIFT)
    check("Shift+click from an unticked row unticks the range",
          ticked(dlg) == (set(paths[0:5]) | {paths[9]} | set(paths[14:21])), f"{len(ticked(dlg))} selected")

    # ── the filter: ranges skip hidden rows ──────────────────────────────────
    btn(dlg, "None").click(); app.processEvents()
    dlg._inp_file_search.setText("system"); app.processEvents()
    shown = [i for i, (c, _fp) in enumerate(dlg._file_checks) if not c.isHidden()]
    click(dlg, shown[0])
    click(dlg, shown[3], SHIFT)
    want = {paths[i] for i in shown[0:4]}
    check("with a filter, a range ticks only the shown rows in it",
          ticked(dlg) == want, f"{sorted(ticked(dlg) - want)}")
    dlg._inp_file_search.setText(""); app.processEvents()
    check("…and clearing the filter changes no tick", ticked(dlg) == want)

    # ── keyboard ─────────────────────────────────────────────────────────────
    btn(dlg, "None").click(); app.processEvents()
    key(dlg, 3, Qt.Key.Key_Space)
    check("Space ticks the focused row", ticked(dlg) == {paths[3]})
    for r in (3, 4, 5):
        key(dlg, r, Qt.Key.Key_Down, SHIFT)
    check("Shift+Down carries the row's tick down: Space then Shift+Down x3 -> 4 rows",
          ticked(dlg) == set(paths[3:7]), f"{len(ticked(dlg))}")
    check("…with focus on the last of them", dlg._file_checks[6][0].hasFocus())
    key(dlg, 6, Qt.Key.Key_Down)
    check("plain Down only moves focus", dlg._file_checks[7][0].hasFocus() and ticked(dlg) == set(paths[3:7]))
    dlg._inp_file_search.setText("security"); app.processEvents()
    shown = [i for i, (c, _fp) in enumerate(dlg._file_checks) if not c.isHidden()]
    key(dlg, shown[0], Qt.Key.Key_A, CTRL)
    check("Ctrl+A ticks every shown row and leaves hidden rows alone",
          ticked(dlg) == set(paths[3:7]) | {paths[i] for i in shown}, f"{len(ticked(dlg))}")
    dlg._inp_file_search.setText(""); app.processEvents()

    # ── existing buttons keep their scopes ───────────────────────────────────
    dlg._inp_file_search.setText("application"); app.processEvents()
    dlg._btn_clear_shown.click(); app.processEvents()
    check("Clear shown still unticks only the shown rows",
          not any(p.endswith("Application.evtx") for p in ticked(dlg)))
    btn(dlg, "All").click(); app.processEvents()
    check("All still ticks every row, hidden ones included", ticked(dlg) == set(paths))
    btn(dlg, "None").click(); app.processEvents()
    check("None still unticks every row, hidden ones included", ticked(dlg) == set())
    dlg._btn_select_shown.click(); app.processEvents()
    check("Select shown still ticks only the shown rows",
          ticked(dlg) == {p for p in paths if p.endswith("Application.evtx")})
    dlg._inp_file_search.setText(""); app.processEvents()
    check("selected_files() returns exactly the ticked paths",
          dlg.selected_files() == {p for p in paths if p.endswith("Application.evtx")})
    texts = [w.text() for w in dlg._files_box.findChildren(QPushButton)] + [dlg._lbl_file_count.text()]
    check("there is no separate 'highlighted' state left",
          not any("highlight" in t.lower() for t in texts) and not hasattr(dlg, "_hl_rows"), f"{texts}")
    dlg.close()

    # ── at the scale it is for: 50 of 300 logs ──────────────────────────────
    big = [rf"C:\case\host{i:03d}\Security.evtx" for i in range(300)]
    dlg = make(big)
    btn(dlg, "None").click(); app.processEvents()
    click(dlg, 100)
    click(dlg, 149, SHIFT)
    check("50 of 300: None, click file 101, Shift+click file 150 -> exactly 50 selected",
          ticked(dlg) == set(big[100:150]), f"{len(ticked(dlg))} selected")
    for _ in range(12):
        foc = next(i for i, (c, _fp) in enumerate(dlg._file_checks) if c.hasFocus()) \
            if any(c.hasFocus() for c, _fp in dlg._file_checks) else 149
        key(dlg, foc, Qt.Key.Key_Down)
    foc = next((i for i, (c, _fp) in enumerate(dlg._file_checks) if c.hasFocus()), None)
    vp = scroll_of(dlg).viewport()
    c = dlg._file_checks[foc][0] if foc is not None else None
    top = c.mapTo(vp, QPoint(0, 0)).y() if c is not None else -1
    check("keyboard focus scrolls the row into view",
          foc == 161 and 0 <= top and top + c.height() <= vp.height(), f"row {foc}, y={top}, viewport={vp.height()}")
    dlg.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
