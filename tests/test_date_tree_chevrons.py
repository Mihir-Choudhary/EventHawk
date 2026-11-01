"""The Timestamp filter tree shows an expand chevron the user can see and click.

Reported by the user (2026-11-01): the popup showed plain years with no hint
that they expand; only a double-click opened them.  The tree is expandable,
but its branch arrow is drawn by the native Windows style, which follows the
OS dark/light setting, on a popup whose colours are fixed cream -- in OS dark
mode the arrow is drawn light on light.  Expected: explicit chevron images
(closed / open) in the theme's text colour on every expandable row, visible
whatever the colour scheme; one click on the chevron expands and collapses;
double-click still works.  Synthetic values only.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt, QPoint
    from PySide6.QtGui import QPixmap, QColor, QGuiApplication
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(sys.argv)
    from evtx_tool.gui.main_window import ColumnFilterPopup
    date_col = next(i for i, k in ColumnFilterPopup.FILTERABLE.items() if k == "timestamp_date")

    p = ColumnFilterPopup(date_col, {"2024-05-14": 3, "2024-06-02": 1, "2025-01-02": 1})
    p.show(); app.processEvents()
    qss = p.styleSheet()
    for name in ("chevron_closed.svg", "chevron_open.svg"):
        m = [ln for ln in qss.splitlines() if name in ln]
        check(f"the popup stylesheet uses {name}", m, f"{len(m)} rule line(s)")
    img_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "evtx_tool", "resources", "images")
    for name in ("chevron_closed.svg", "chevron_open.svg", "chevron_closed_hover.svg", "chevron_open_hover.svg"):
        path = os.path.join(img_dir, name)
        check(f"{name} exists and renders", os.path.isfile(path) and not QPixmap(path).isNull())
    check("the branch rules target rows that have children",
          "::branch:closed:has-children" in qss and "::branch:open:has-children" in qss)

    tree = p._tree
    year = p._year_items["2024"]
    check("a year row has children (so it shows a chevron)", year.childCount() > 0)
    tree.scrollToItem(year)
    rect = tree.visualItemRect(year)
    arrow = QPoint(rect.left() - tree.indentation() // 2, rect.center().y())
    QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, arrow)
    app.processEvents()
    check("one click on the chevron expands the year", year.isExpanded())
    QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, arrow)
    app.processEvents()
    check("a second click collapses it", not year.isExpanded())
    # A real double-click is press, release, then the double-click press: Qt
    # only expands when the first press landed on the same row.
    text_pt = QPoint(rect.left() + 40, rect.center().y())
    QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, text_pt)
    QTest.mouseDClick(tree.viewport(), Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, text_pt)
    app.processEvents()
    check("double-click on the row still expands", year.isExpanded())
    year.setExpanded(False); app.processEvents()

    # The chevron is drawn in the theme's text colour whatever the colour scheme.
    hints = QGuiApplication.styleHints()
    for scheme in (Qt.ColorScheme.Dark, Qt.ColorScheme.Light):
        hints.setColorScheme(scheme)
        app.processEvents()
        img = tree.viewport().grab().toImage()
        rect = tree.visualItemRect(year)
        dark = 0
        for x in range(max(0, rect.left() - tree.indentation()), rect.left()):
            for y in range(rect.top(), rect.bottom() + 1):
                c = QColor(img.pixel(x, y))
                if c.red() < 90 and c.green() < 80 and c.blue() < 70:
                    dark += 1
        check(f"the chevron is drawn dark on the cream popup ({scheme.name} scheme)", dark >= 6,
              f"{dark} dark pixels in the branch area")
    hints.unsetColorScheme()
    p.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
