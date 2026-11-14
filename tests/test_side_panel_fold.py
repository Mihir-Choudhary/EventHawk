"""Side panel: folds only when the events need the room, and is easy to bring back.

  - After a parse the panel folds only below 1240 px (1500 folded it on every
    non-maximised window of a 1536 px laptop screen).
  - Folded, the strip is 24 px with a larger amber arrow and a tooltip that
    says what it does (the 16 px strip with a faint arrow looked stuck).
  - One click on the strip opens the panel again; the automatic fold is not
    remembered as the user's choice.

Run: QT_QPA_PLATFORM=offscreen python tests/test_side_panel_fold.py
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

    def pump(sec=0.4):
        end = time.time() + sec
        while time.time() < end:
            app.processEvents()
            time.sleep(0.01)

    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    pump()
    if not w._panel_open:
        w._toggle_left_panel(persist=False)
        pump()
    w._fold_panel_for_room()
    pump()
    check("a 1366 px window keeps the side panel open after a parse", w._panel_open)
    w.resize(1200, 700)
    pump()
    w._fold_panel_for_room()
    pump(0.5)
    wrap = w._left_panel_wrapper
    check("a 1200 px window folds it to give the events room", not w._panel_open)
    check("...to a 24 px strip, not a 16 px sliver", wrap.maximumWidth() == 24 and w._btn_panel_toggle.width() == 24,
          f"{wrap.maximumWidth()} / {w._btn_panel_toggle.width()}")
    check("...whose tooltip says what it does", "Show the side panel" in w._btn_panel_toggle.toolTip(),
          w._btn_panel_toggle.toolTip())
    check("...and which a screen reader can name", bool(w._btn_panel_toggle.accessibleName()))
    w._btn_panel_toggle.click()
    pump(0.5)
    check("one click on the strip opens the panel again", w._panel_open and wrap.width() >= 290, str(wrap.width()))
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
