"""Event detail vs analysis panel: detail gets the room, analysis on demand.

  - The event detail starts with the larger share of the bottom area (it was
    50/50, which left the viewer cramped).
  - The Analysis button in the detail header (and View > Analysis Panel,
    Ctrl+Shift+A) hides the ATT&CK / IOCs / Chains / Bookmarks tabs so the
    detail takes the whole width, and brings them back; button and menu stay
    in step.

Run: QT_QPA_PLATFORM=offscreen python tests/test_analysis_panel_toggle.py
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
    w.resize(1536, 790)
    w.show()
    pump()
    left, right = w._bottom_split.sizes()
    check("the event detail starts with the larger share", left > right, f"{left} / {right}")
    btn, act = w._btn_analysis_panel, w._act_analysis_panel
    check("the Analysis button and the View menu entry start on", btn.isChecked() and act.isChecked())
    btn.click()
    pump()
    check("Analysis off: the analysis tabs are hidden", not w._analysis_widget.isVisible())
    check("...the event detail takes the whole width",
          w._detail_browser.width() > w._bottom_split.width() * 0.9,
          f"{w._detail_browser.width()} of {w._bottom_split.width()}")
    check("...and the View menu entry follows", not act.isChecked())
    act.trigger()
    pump()
    check("View > Analysis Panel brings them back", w._analysis_widget.isVisible() and btn.isChecked())
    shortcut = act.shortcut().toString()
    check("Ctrl+Shift+A is the shortcut", shortcut == "Ctrl+Shift+A", shortcut)
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
