"""IOC tab: every category reachable at any width; times like the event table.

  - While every category's tab fits, they show as tabs; when they would not
    (18 categories on a laptop-width pane scrolled off behind arrows) a
    "Category" drop-down with every category and its count replaces the bar,
    and picking from it shows that category's table.  Widening brings the
    tabs back.
  - First / Last Seen are in the display zone and precision, as in the event
    table (they were raw UTC ISO strings); the exact UTC value is the tooltip.
  - The Correlation tab has a line icon, not an emoji; its confidence colours
    are theme colours (readable, WCAG 4.5:1).

Run: QT_QPA_PLATFORM=offscreen python tests/test_ioc_categories.py
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


KEYS = ["ipv4", "ipv6", "domains", "urls", "sha256", "sha1", "md5", "processes", "commandlines", "registry",
        "filepaths", "services", "tasks", "named_pipes", "shares", "dlls", "users", "computers"]


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import apply_tz

    def pump(sec=0.3):
        end = time.time() + sec
        while time.time() < end:
            app.processEvents()
            time.sleep(0.01)

    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    pump()
    first = "2025-12-05T07:13:17.123456Z"
    w._iocs = {k: [{"value": f"{k}-value-{i}", "count": i + 1, "first_seen": first,
                    "last_seen": "2025-12-06T08:00:00.000000Z", "score": 10}
                   for i in range(3)] for k in KEYS}
    w._iocs["correlation"] = {"pairs": [{"value_a": "10.0.0.1", "type_a": "ipv4", "value_b": "alice",
                                        "type_b": "users", "shared_context": 3, "confidence": "high"}]}
    w._refresh_iocs_tab()
    tabs = w._ioc_tabs
    # Put the IOC page in front so it has a real width.
    from PySide6.QtWidgets import QTabWidget
    for t in w.findChildren(QTabWidget):
        for i in range(t.count()):
            if t.tabText(i).replace("&", "").startswith("IOC"):
                t.setCurrentIndex(i)
    pump()
    n = tabs.count()
    check("every category and the correlation get a page", n == len(KEYS) + 1, str(n))

    tabs.parentWidget().setFixedWidth(620)
    pump()
    check("narrow pane: the drop-down replaces tabs that would scroll off",
          w._ioc_cat_row.isVisible() and not tabs.tabBar().isVisible(),
          f"row {w._ioc_cat_row.isVisible()} bar {tabs.tabBar().isVisible()}")
    cmb = w._cmb_ioc_cat
    check("...it lists every category with its count", cmb.count() == n and cmb.itemText(0) == tabs.tabText(0),
          f"{cmb.count()} {cmb.itemText(0)!r}")
    cmb.setCurrentIndex(9)
    pump(0.1)
    check("...picking one shows that category", tabs.currentIndex() == 9, str(tabs.currentIndex()))
    tabs.setCurrentIndex(3)
    pump(0.1)
    check("...and it follows the page shown", cmb.currentIndex() == 3, str(cmb.currentIndex()))
    check("...it has a name for screen readers", cmb.accessibleName() == "IOC category")

    tabs.parentWidget().setMinimumWidth(0)
    tabs.parentWidget().setMaximumWidth(16777215)
    w._iocs = {k: w._iocs[k] for k in ("ipv4", "users")}
    w._refresh_iocs_tab()
    pump()
    check("few categories on a wide pane: tabs, no drop-down",
          tabs.tabBar().isVisible() and not w._ioc_cat_row.isVisible())

    tbl = tabs.widget(0)
    cell = tbl.item(0, 2)
    check("First Seen in the display zone and precision", cell.text() == apply_tz(first), cell.text())
    check("...exact UTC on hover", cell.toolTip() == f"UTC {first}", cell.toolTip())

    w._iocs = {"ipv4": w._iocs["ipv4"], "correlation": {"pairs": [{"value_a": "a", "type_a": "ipv4", "value_b": "b",
                                                                   "type_b": "users", "shared_context": 1,
                                                                   "confidence": "low"}]}}
    w._refresh_iocs_tab()
    pump()
    ct = tabs.tabText(tabs.count() - 1)
    check("Correlation tab: a line icon, no emoji", ct.startswith("Correlation") and not tabs.tabIcon(tabs.count() - 1).isNull(),
          ct)
    from evtx_tool.gui.theme import COLORS
    fg = tabs.widget(tabs.count() - 1).item(0, 4).foreground().color().name()
    check("Correlation confidence uses a theme colour", fg == COLORS["text_dim"].lower(), fg)
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
