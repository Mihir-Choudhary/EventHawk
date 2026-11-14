"""Sentinel window: fits a laptop, empty pages explain themselves, calm forms.

  - The window's minimum size fits a 1280 x 720 screen (it was 1000 x 720).
  - Results and Metrics are always clickable; until an analysis has run they
    say what will appear and offer "Go to Analysis" (they were disabled tabs
    that ignored a click).  Filling them shows the tables; clear() brings
    the empty state back.
  - Baseline Setup / Analysis: no 0 % progress bar before a run, a line that
    says what to do first, the run button is the primary action, the log
    says what it will hold.
  - Metrics number columns fit their headers.

Run: QT_QPA_PLATFORM=offscreen python tests/test_sentinel_ux.py
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
    from PySide6.QtWidgets import QApplication, QHeaderView
    app = QApplication.instance() or QApplication([])
    from sentinel.gui.window import SentinelWindow
    win = SentinelWindow()
    win.show()
    app.processEvents()
    m = win.minimumSize()
    check("minimum size fits a 1280 x 720 laptop screen", m.width() <= 1280 and m.height() <= 640,
          f"{m.width()} x {m.height()}")
    tabs = win._tabs
    check("Results and Metrics can be opened before an analysis", tabs.isTabEnabled(2) and tabs.isTabEnabled(3))
    rt, mt = win._results_tab, win._metrics_tab
    check("Results says what will appear until an analysis", rt._stack.currentWidget() is rt.empty)
    check("Metrics too", mt._stack.currentWidget() is mt.empty)
    tabs.setCurrentIndex(2)
    rt.empty.button.click()
    app.processEvents()
    check("\"Go to Analysis\" opens the Analysis tab", tabs.currentWidget() is win._analysis_tab)
    rt.populate([])
    check("filling Results shows its tables", rt._stack.currentIndex() == 1)
    rt.clear()
    check("...clearing brings the explanation back", rt._stack.currentWidget() is rt.empty)
    mt.populate([], {})
    check("filling Metrics shows its tables", mt._stack.currentIndex() == 1)
    for name, tab, btn in (("Baseline Setup", win._baseline_tab, "_build_btn"),
                           ("Analysis", win._analysis_tab, "_run_btn")):
        check(f"{name}: no progress bar before a run", tab._progress_bar.isHidden())
        check(f"{name}: a line says what to do first", len(tab._status_label.text()) > 40, tab._status_label.text()[:60])
        check(f"{name}: the run button is the primary action", getattr(tab, btn).objectName() == "parseBtn")
        check(f"{name}: the log says what it will hold", "appear here" in tab._log_edit.placeholderText())
    hdr = mt._top_procs_table.horizontalHeader()
    check("Metrics: \"Suppressed Count\" fits its header",
          hdr.sectionResizeMode(1) == QHeaderView.ResizeMode.ResizeToContents)
    win.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
