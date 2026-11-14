"""Bottom panel: switching analysis tabs never moves the Event Detail divider.

The IOC tab's one-line summary ("289 unique IOC values -- double-click to
pivot | right-click to copy | Export for full list") set the tab's minimum
width once it was shown; the splitter pushed the divider left to make room
and never gave the width back, so Event Detail lost about a third of its
width for the rest of the session after one look at IOCs.

  - Visiting every tab with long summary texts leaves the sizes unchanged.
  - The long summaries still show in full (they wrap, nothing is cut).

Run: QT_QPA_PLATFORM=offscreen python tests/test_bottom_split_stable.py
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
    from PySide6.QtWidgets import QApplication
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
    pump(0.6)
    bs, tabs = w._bottom_split, w._analysis_tabs
    texts = {
        "ioc": "289 unique IOC values  —  double-click to pivot  |  right-click to copy  |  Export for full list",
        "ioc_none": "IOC extraction was not run. Tick IOC Extraction in the side panel and parse again.",
        "attack": "3,335 of 75,412 events tagged  |  8 tactics  |  10 techniques  —  click a tactic to filter",
    }
    w._lbl_ioc_summary.setText(texts["ioc"])
    w._lbl_attack_summary.setText(texts["attack"])
    pump()
    before = bs.sizes()
    for i in range(tabs.count()):
        tabs.setCurrentIndex(i)
        pump(0.3)
    tabs.setCurrentIndex(0)
    pump(0.3)
    after = bs.sizes()
    check("visiting every analysis tab leaves the divider where it was", after == before,
          f"{before} -> {after}")
    check("Event Detail keeps the larger share", after[0] > after[1], str(after))

    tabs.setCurrentIndex(1)
    pump(0.3)
    lbl = w._lbl_ioc_summary
    need = lbl.heightForWidth(lbl.width()) if lbl.wordWrap() else lbl.sizeHint().height()
    check("the long IOC summary is shown in full (it wraps)",
          lbl.wordWrap() and lbl.height() >= need, f"wrap={lbl.wordWrap()} h={lbl.height()} need={need}")
    w._lbl_ioc_summary.setText(texts["ioc_none"])
    pump(0.3)
    check("the long 'not run' text does not move the divider either", bs.sizes() == before, str(bs.sizes()))

    # IOC table at this laptop width: the value column keeps room to be read.
    w._iocs = {"ipv4": [{"value": "255.255.192.0", "count": 6, "first_seen": "2025-12-05T07:13:17.123456Z",
                         "last_seen": "2025-12-06T08:00:00.000000Z", "score": 30}]}
    w._iocs_ran = True
    w._refresh_iocs_tab()
    pump(0.4)
    tbl = w._ioc_tabs.widget(0)
    from PySide6.QtWidgets import QTableWidget
    if not isinstance(tbl, QTableWidget):
        tbl = tbl.findChild(QTableWidget)
    fm = tbl.fontMetrics()
    need = fm.horizontalAdvance("255.255.192.0") + 12
    check("an IP address fits its Value column on a laptop-width pane",
          tbl.columnWidth(0) >= need, f"value col {tbl.columnWidth(0)} px, needs {need}; "
          f"cols {[tbl.columnWidth(c) for c in range(5)]}, viewport {tbl.viewport().width()}")
    check("the date stays visible in First Seen", tbl.columnWidth(2) >= fm.horizontalAdvance("2025-12-05 ...") + 8,
          str(tbl.columnWidth(2)))
    w._btn_analysis_panel.click()          # hide, then show the panel at full width
    pump(0.3)
    bs.setSizes([300, 900])
    w._btn_analysis_panel.click()
    pump(0.3)
    bs.setSizes([300, 900])
    pump(0.4)
    check("with room, the times get their full width back", tbl.columnWidth(2) >= 140,
          f"{tbl.columnWidth(2)} at viewport {tbl.viewport().width()}")
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
