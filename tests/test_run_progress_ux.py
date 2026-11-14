"""Side panel run progress, and the Source File column's font.

  - The progress bar shows while a parse or analysis runs (Stop enabled)
    and hides when it ends: left full it was a heavy block repeating what
    the stats row and status bar say.  The stats row stays.
  - Hiding it keeps its space: Export report does not jump.
  - Source File cells use the table's font (they were Consolas 9).

Run: QT_QPA_PLATFORM=offscreen python tests/test_run_progress_ux.py
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
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui import models

    def pump(sec=0.3):
        end = time.time() + sec
        while time.time() < end:
            app.processEvents()
            time.sleep(0.01)

    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    pump()
    if not w._panel_open:                   # the offscreen screen is small: open the side panel
        w._toggle_left_panel()
        pump(0.6)
    check("no progress before the first run", w._run_stats_box.isHidden())
    w._btn_stop.setEnabled(True)            # what every run path does when it starts
    pump()
    bar = w._progress_bar
    check("the bar shows while a run is going", not w._run_stats_box.isHidden() and not bar.isHidden())
    y_running = w._btn_export.mapTo(w, w._btn_export.rect().topLeft()).y()
    bar.setValue(100)
    w._btn_stop.setEnabled(False)           # ...and what it does when it ends
    pump()
    check("the bar hides when the run ends", bar.isHidden())
    check("the stats row stays", not w._run_stats_box.isHidden() and not w._lbl_matched.isHidden())
    y_done = w._btn_export.mapTo(w, w._btn_export.rect().topLeft()).y()
    check("Export report does not jump when the bar hides", y_done == y_running, f"{y_running} -> {y_done}")
    w._btn_stop.setEnabled(True)
    pump()
    check("the next run shows it again", not bar.isHidden())

    # Mid-parse, with ATT&CK Mapping ticked, the tab said "was not run. Tick
    # ATT&CK Mapping in the side panel" -- contradicting the ticked box.
    class _Busy:
        def isRunning(self):
            return True
    w._chk_attack.setChecked(True)
    w._attack_summary = None
    w._worker = _Busy()
    w._refresh_attack_tab()
    txt = w._lbl_attack_summary.text()
    check("mid-parse, ATT&CK says results are coming (not 'was not run')",
          "appear" in txt and "not run" not in txt, txt)
    w._worker = None
    w._refresh_attack_tab()
    check("after the run without results it says it was not run", "not run" in w._lbl_attack_summary.text()
          or "matched" in w._lbl_attack_summary.text(), w._lbl_attack_summary.text())
    w.close()

    m = models.EventTableModel()
    m.set_events([{"event_id": 1, "source_file": r"C:\\logs\\Security.evtx", "record_id": 1,
                   "timestamp": "2025-01-01T00:00:00Z", "level_name": "Information", "channel": "Security",
                   "computer": "PC", "event_data": {}}])
    font = m.data(m.index(0, models.COL_SOURCE), Qt.ItemDataRole.FontRole)
    check("Source File cells use the table's own font (no Consolas)", font is None, repr(font))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
