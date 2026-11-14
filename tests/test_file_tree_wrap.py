"""File list (Tab per file): long log names wrap instead of ending in "...".

  - A long name's row is taller (two lines or more), a short name's is one line.
  - Widening the panel re-measures: the long name fits on fewer lines.
  - The item text is unchanged (the break points are display only).

Run: QT_QPA_PLATFORM=offscreen python tests/test_file_tree_wrap.py
"""
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QTreeWidgetItem
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw

    def pump(sec=0.3):
        end = time.time() + sec
        while time.time() < end:
            app.processEvents()
            time.sleep(0.01)

    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    t = w._file_tree
    w._file_tree_panel.setVisible(True)
    w._file_tree_panel.setFixedWidth(230)
    long_name = "Security-LessPrivilegedAppContainer / Operational"
    for text, n in (("Setup", "2,495"), (long_name, "1,977"),
                    ("Resource-Exhaustion-Detector / Operational", "862")):
        t.addTopLevelItem(QTreeWidgetItem([text, n]))
    pump()
    h = [t.visualItemRect(t.topLevelItem(i)).height() for i in range(3)]
    check("a short name takes one line", h[0] < 34, str(h))
    check("a long name gets a taller row (it wraps, no ellipsis)", h[1] >= h[0] * 1.6 and h[2] >= h[0] * 1.6, str(h))
    check("the item text itself is unchanged", t.topLevelItem(1).text(0) == long_name)
    w._file_tree_panel.setFixedWidth(520)
    pump()
    h2 = t.visualItemRect(t.topLevelItem(1)).height()
    check("a wider panel re-measures: fewer lines", h2 < h[1], f"{h[1]} -> {h2}")

    # An open file's name is bold, and bold is wider: a name that fits one
    # line in the regular weight can need two.  The row must be measured in
    # the font it is drawn in, or the second line is cut off (user report:
    # "Biometrics / Operational" selected and clipped).
    from PySide6.QtGui import QFontMetrics
    t.clear()
    name = "Biometrics / Operational"
    item = QTreeWidgetItem([name, "1,297"])
    t.addTopLevelItem(item)
    pump()
    fm = QFontMetrics(t.font())
    bf = t.font(); bf.setBold(True)
    fmb = QFontMetrics(bf)
    # Width where the regular name fits on one line but the bold one does not.
    col = (fm.horizontalAdvance(name) + fmb.horizontalAdvance(name)) // 2 + 16
    gap = fmb.horizontalAdvance(name) - fm.horizontalAdvance(name)
    w._file_tree_panel.setFixedWidth(col + (t.width() - t.header().sectionSize(0)))
    pump()
    t.header().resizeSection(0, col)
    pump()
    reg_h = t.visualItemRect(item).height()
    f = item.font(0); f.setBold(True); item.setFont(0, f)
    pump()
    bold_h = t.visualItemRect(item).height()
    check("bold (open) name gets the taller row it wraps to", gap < 4 or bold_h >= reg_h * 1.6,
          f"regular {reg_h} px, bold {bold_h} px, bold is {gap} px wider")
    t.setCurrentItem(item); pump()
    check("selecting it keeps the taller row", t.visualItemRect(item).height() == bold_h,
          str(t.visualItemRect(item).height()))
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
