"""Windows sized for a big monitor must fit a laptop screen.

Logon Sessions (1340 px), WiFi History (1400), System Activity (1450) and the
profile editor (740 px tall) opened past the edges of a 1366x768 or 1280x720
screen, with OK / Close out of reach.  A window opened larger than its screen's
available area is now shrunk to fit and moved inside it; one that fits is left
exactly where and as big as it is.

  A. the geometry rule (pure function) for the shapes that were reported;
  B. the app-wide filter on a real oversized dialog (installed explicitly:
     the app skips it on the offscreen platform, whose virtual screen is
     smaller than any real one).

Run: QT_QPA_PLATFORM=offscreen python tests/test_fit_to_screen.py
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


def inside(r, area):
    x, y, w, h = r
    ax, ay, aw, ah = area
    return x >= ax and y >= ay and x + w <= ax + aw and y + h <= ay + ah


def main() -> int:
    from PySide6.QtWidgets import QApplication, QDialog
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    fit = mw.fit_rect_to_screen

    print("=== A. geometry rule ===")
    laptop = (0, 0, 1280, 680)          # 1280x720 less a 40 px taskbar
    for name, (w, h) in {"System Activity": (1450, 680), "WiFi History": (1400, 640),
                         "Logon Sessions": (1340, 620), "Profile editor": (640, 740),
                         "Main window": (1420, 860)}.items():
        r = fit(100, 50, w, h, *laptop)
        check(f"{name} {w}x{h} fits a 1280x720 screen", inside(r, laptop), str(r))
        check(f"{name}: shrunk only where it was too big",
              (r[2] == w or r[2] < w) and (r[3] == h or r[3] < h)
              and (w <= laptop[2] - 48 or r[2] < w) and (h <= laptop[3] - 48 or r[3] < h), str(r))
    r = fit(200, 100, 600, 400, *laptop)
    check("a window that fits is left unchanged", r == (200, 100, 600, 400), str(r))
    r = fit(1100, 500, 600, 400, *laptop)
    check("a small window hanging off the edge is moved inside, same size",
          inside(r, laptop) and r[2:] == (600, 400), str(r))
    second = (1920, 0, 1366, 728)        # a second monitor to the right
    r = fit(1900, -20, 1450, 680, *second)
    check("works on a monitor that does not start at 0,0", inside(r, second), str(r))

    print("\n=== B. the filter on a real dialog ===")
    f = mw._FitWindowsToScreen(app)
    app.installEventFilter(f)
    try:
        area = app.primaryScreen().availableGeometry()
        big = QDialog()
        big.resize(area.width() + 400, area.height() + 300)
        big.show(); app.processEvents()
        g = big.geometry()
        check("an oversized dialog is fitted to the screen on first show",
              big.width() <= area.width() and big.height() <= area.height(),
              f"{big.width()}x{big.height()} on {area.width()}x{area.height()}")
        big.resize(area.width() + 400, area.height() + 300)
        big.hide(); big.show(); app.processEvents()
        check("only on the first show (a size the user picks later is kept)",
              big.width() == area.width() + 400, f"{big.width()}")
        big.close()
        small = QDialog()
        small.resize(300, 200)
        small.show(); app.processEvents()
        check("a dialog that fits keeps its size", (small.width(), small.height()) == (300, 200),
              f"{small.width()}x{small.height()}")
        small.close()
    finally:
        app.removeEventFilter(f)

    mw.install_fit_windows_to_screen(app)
    check("the app does not install it on the offscreen platform",
          getattr(app, "_eh_fit_filter", None) is None)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
