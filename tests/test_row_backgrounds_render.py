"""Row backgrounds a model or table item sets are actually DRAWN.

The app stylesheet had a ``QTableView::item { padding; border }`` rule.  Any
such rule makes Qt's stylesheet style paint every cell itself and drop the
cell's own background, so the models' backgrounds were computed and never
shown: bookmarked rows were not highlighted, and the Logon Sessions / WiFi /
System Activity state fills and the IOC score tints were invisible.  (Tests
that read the model's BackgroundRole passed all along -- the colour was right,
it just never reached the screen.)

This grabs the rendered table and reads pixels:

  * a bookmarked row is drawn in the bookmark colour, in Normal and
    Juggernaut mode, light and dark theme;
  * its neighbours keep the normal row colours;
  * the stylesheet carries no QTableView::item rule.

Synthetic data only.
Run: QT_QPA_PLATFORM=offscreen python tests/test_row_backgrounds_render.py
"""
import os
import re
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
SEC = r"C:\s\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def close(a, b, tol=6):
    return all(abs(x - y) <= tol for x, y in zip(a.getRgb()[:3], b.getRgb()[:3]))


def main() -> int:
    from PySide6.QtCore import QSettings
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui import theme

    check("the stylesheet has no QTableView::item rule (it hides cell backgrounds)",
          not re.search(r"QTableView::item\s*\{", theme.LIGHT_QSS))

    st = QSettings("EventHawk", "GUI")
    had, prev = st.contains(theme._SETTINGS_KEY), st.value(theme._SETTINGS_KEY)
    evs = [T.ev(SEC, i + 1, "HOST", T.T0 + timedelta(seconds=i), 4624) for i in range(8)]
    try:
        for name in ("light", "dark"):
            theme.apply_theme(app, name)
            for jm in (False, True):
                tag = f"{name}/{'JM' if jm else 'Normal'}"
                m = T.Mode(mw, jm)
                w = mw.MainWindow()
                m.load(w, evs)
                if jm:
                    w._table.setModel(w._hw_model)
                w.resize(1400, 800); w.show(); T.pump(300)
                model = w._table.model()
                ev = model.get_event(2) if jm else w._proxy_model.get_source_event(2)
                w._bookmark_event(ev); T.pump(400)
                w._table.clearSelection(); T.pump(200)
                img = w._table.viewport().grab().toImage()
                rh = w._table.rowHeight(0)
                x = w._table.columnViewportPosition(7) + 20      # ATT&CK: empty cells
                px = [img.pixelColor(x, r * rh + rh // 2) for r in range(4)]
                want = QColor(theme.tc("#e8c96e"))
                check(f"{tag}: the bookmarked row is drawn in the bookmark colour",
                      close(px[2], want), f"{px[2].name()} vs {want.name()}")
                check(f"{tag}: its neighbours are not",
                      not close(px[1], want) and not close(px[3], want),
                      f"{px[1].name()} / {px[3].name()}")
                w.close(); T.pump(150)
                if m.tmp:
                    import shutil
                    shutil.rmtree(m.tmp, ignore_errors=True)
    finally:
        theme.apply_theme(app, "light")
        if had:
            st.setValue(theme._SETTINGS_KEY, prev)
        else:
            st.remove(theme._SETTINGS_KEY)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
