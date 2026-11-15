"""The Event Detail pane follows a time-zone change; clearing bookmarks unfilters.

Gemini audit 5-06 (Medium): the detail pane caches the event it shows, so
after a time-zone (or precision) change the grid showed the new time and the
pane the old one; in Juggernaut mode the refresh read a proxy that is not
the table's model.
Gemini audit 5-14 (Medium): in Normal mode double-clicking a bookmark filtered
through the IOC/record-id slot, and "Clear all bookmarks" clears the bookmark
slot, so the table stayed filtered to one event.

Expected: after switching to UTC+09:00 the pane shows the +9 h time, in both
modes; after a bookmark double-click and "Clear all bookmarks" the Normal table
shows every event again.  Synthetic events.
"""
import os
import sys
from datetime import datetime, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QMessageBox
    QMessageBox.question = staticmethod(lambda *a, **k: QMessageBox.StandardButton.Yes)
    evs =[T.ev(r"C:\c\a.evtx", i + 1, "H", datetime(2026, 3, 1, 10, i, tzinfo=timezone.utc)) for i in range(3)]
    for jm in (False, True):
        mode = "Juggernaut" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
            w._connect_jm_model_signals(w._hw_model)
        w._warn_blocking = lambda *a, **k: None
        w._tz_mode, w._tz_custom_offset_min = "utc", 0
        w._apply_tz_to_all_models()
        T.pump(200)
        w._active_table.selectRow(0)
        T.pump(400)
        w._tz_mode, w._tz_custom_offset_min = "custom", 540
        w._apply_tz_to_all_models()
        T.pump(400)
        pane = w._detail_browser.toPlainText() if hasattr(w, "_detail_browser") else ""
        if not pane:
            for attr in ("_txt_detail", "_detail_view", "_detail_text"):
                if hasattr(w, attr):
                    pane = getattr(w, attr).toPlainText()
                    break
        check(f"{mode}: the detail pane shows the UTC+09:00 time (19:00)", "19:00" in pane, pane[:120].replace("\n", " "))
        w._tz_mode, w._tz_custom_offset_min = "utc", 0
        w._apply_tz_to_all_models()
        if not jm:
            w._bookmark_event(w._proxy_model.get_source_event(0))
            T.pump(200)
            w._on_bookmark_double_click(w._tbl_bookmarks.model().index(0, 0))
            T.pump(300)
            during = w._proxy_model.rowCount()
            w._clear_all_bookmarks()
            T.pump(300)
            check("Normal: after a bookmark pivot, Clear all bookmarks shows every event",
                  during == 1 and w._proxy_model.rowCount() == 3, f"{during} -> {w._proxy_model.rowCount()}")
        T.teardown(w, jm, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
