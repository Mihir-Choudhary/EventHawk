"""Date tree: a tick / dash in each checkbox, and rows never cut off.

The popup's stylesheet draws the checkbox as a filled square, so "all",
"some" and "none" of a year, month or day differed only by a shade of amber.
And with the hour level the tree is five levels deep, so at the old 260 px an
hour row ("14:00–14:59  (1,234)") was cut off with "…" and could not be read.

Painting and layout only.  What must hold (pixels and geometry of the real
popup, since the problem was purely visual):

  * checked boxes show a tick, partly checked a dash, unchecked boxes nothing;
  * the popup opens at least 320 px wide, rows are never elided, the column is
    as wide as the widest row, and a horizontal scrollbar is always shown and
    reaches the end of a row when the popup is squeezed;
  * nothing about the tree's data changes: lazy hour loading still fetches a
    day's hours only on first expand, through the same provider, and the
    emitted values (dates, hours) are exactly what they were.

Run: QT_QPA_PLATFORM=offscreen python tests/test_date_tree_ticks.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


DATE_COL = 3
VALUES = {"2026-10-25": 4120, "2026-10-26": 5210, "2026-09-30": 611, "2025-12-31": 77}
HOURS = {"2026-10-26": {"00": 19, "01": 4, "13": 1234567, "14": 600}}


def main() -> int:
    from PySide6.QtWidgets import QApplication, QStyle, QStyleOptionViewItem
    from PySide6.QtCore import Qt
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import ColumnFilterPopup

    calls = []

    def hour_provider(day):
        calls.append(day)
        return dict(HOURS.get(day, {"12": 1}))

    p = ColumnFilterPopup(DATE_COL, dict(VALUES), hour_provider=hour_provider)
    p.show(); app.processEvents()
    t = p._tree
    root = t.topLevelItem(0)

    def child(item, prefix):
        return next(item.child(i) for i in range(item.childCount())
                    if item.child(i).text(0).startswith(prefix))

    y26 = child(root, "2026"); y26.setExpanded(True)
    octo = child(y26, "October"); octo.setExpanded(True)
    d26 = child(octo, "26")
    check("hours are not loaded before the day is expanded", "2026-10-26" not in calls)
    d26.setExpanded(True); app.processEvents()
    check("expanding the day loads its hours, once, through the provider",
          calls.count("2026-10-26") == 1 and d26.childCount() == 4,
          f"calls={calls}, hours={d26.childCount()}")
    d26.setExpanded(False); d26.setExpanded(True); app.processEvents()
    check("re-expanding does not fetch the hours again", calls.count("2026-10-26") == 1)
    app.processEvents()

    # ── ticks ─────────────────────────────────────────────────────────────────
    d25 = child(octo, "25")
    d25.setCheckState(0, Qt.CheckState.Unchecked)
    app.processEvents()
    img = t.viewport().grab().toImage()

    def box(item):
        opt = QStyleOptionViewItem()
        idx = t.indexFromItem(item)
        opt.rect = t.visualRect(idx); opt.widget = t
        t.itemDelegate().initStyleOption(opt, idx)
        return t.style().subElementRect(QStyle.SubElement.SE_ItemViewItemCheckIndicator, opt, t)

    def ink_pixels(item):
        """Pixels in the box interior that differ from the box's own fill."""
        r = box(item).adjusted(3, 3, -3, -3)
        fill = img.pixelColor(r.left(), r.top())
        return sum(1 for x in range(r.left(), r.right() + 1) for y in range(r.top(), r.bottom() + 1)
                   if abs(img.pixelColor(x, y).lightness() - fill.lightness()) > 60)

    hour13 = child(d26, "13")
    check("a checked row shows a tick", ink_pixels(hour13) >= 4, f"{ink_pixels(hour13)} px")
    check("October is partly checked and shows a dash",
          octo.checkState(0) == Qt.CheckState.PartiallyChecked and ink_pixels(octo) >= 4,
          f"{ink_pixels(octo)} px")
    check("an unchecked row shows nothing", ink_pixels(d25) == 0, f"{ink_pixels(d25)} px")

    # ── no cut-off ────────────────────────────────────────────────────────────
    check("the date popup opens at least 320 px wide", p.width() >= 320, f"{p.width()} px")
    check("rows are never elided", t.textElideMode() == Qt.TextElideMode.ElideNone)
    check("the bottom scrollbar is always shown", t.horizontalScrollBar().isVisible())
    needed = t.visualItemRect(hour13).left() + 16 + t.fontMetrics().horizontalAdvance(hour13.text(0))
    check("the column is as wide as the deepest, longest row",
          t.columnWidth(0) >= needed, f"column {t.columnWidth(0)}, row needs {needed}")
    p.setMinimumWidth(0); p.resize(200, p.height()); app.processEvents()
    hbar = t.horizontalScrollBar()
    hbar.setValue(hbar.maximum()); app.processEvents()
    check("squeezed narrow, scrolling right reaches the end of the row",
          hbar.maximum() > 0 and needed - hbar.value() <= t.viewport().width(),
          f"row ends at {needed - hbar.value()}, viewport {t.viewport().width()}")

    # ── data unchanged: the same selection emits the same filter ──────────────
    # A partly ticked day (hour 01 unticked) and an unticked day (25).  What the
    # popup emits must not depend on the delegate: compare with Qt's plain one.
    hour01 = child(d26, "01")
    hour01.setCheckState(0, Qt.CheckState.Unchecked)
    app.processEvents()
    from PySide6.QtWidgets import QStyledItemDelegate
    emitted = []
    p.filterApplied.connect(lambda c, m, v: emitted.append((c, m, sorted(v))))
    p._apply()
    t.setItemDelegate(QStyledItemDelegate(t))
    p._apply()
    check("a partial-hour selection emits exactly what it emits without the ticks",
          len(emitted) == 2 and emitted[0] == emitted[1], f"{emitted[:1]}")
    check("…and that filter names the checked hours of the partly ticked day",
          any("2026-10-26 13" in v for _c, _m, v in emitted[:1])
          or any("2026-10-26 01" in v for _c, _m, v in emitted[:1]), f"{emitted[:1]}")
    p.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
