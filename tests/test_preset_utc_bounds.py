"""A saved filter preset means the same instants in the CLI and in any display zone.

Gemini audit 4-05 (High): the dialog saved its From/To as display-zone wall
time ("2026-03-01 09:00:00" meant 09:00 IST) with no zone.  The CLI reads a
preset's bounds as UTC, so --filter-file filtered 5.5 hours off; reloaded
under another display zone the dialog showed the same wall time, a
different instant.

Expected: a preset saved in UTC+05:30 for 09:00-10:00 also carries the UTC
bounds 03:30Z-04:30Z; the CLI with that file keeps an event at 04:00Z and
drops one at 06:00Z; reloaded under UTC the dialog shows 03:30-04:30.
Synthetic values.
"""
import json
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QDateTime, QDate, QTime
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    QApplication.instance() or QApplication([])
    import evtx_tool.gui.models as M
    from evtx_tool.gui.filter_dialog import FilterDialog
    path = os.path.join(tempfile.mkdtemp(prefix="preset_"), "p.json")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (path, ""))
    QMessageBox.information = staticmethod(lambda *a, **k: None)
    M.set_tz_config("custom", "UTC", 330)
    dlg = FilterDialog({})
    dlg._chk_date_enable.setChecked(True)
    dlg._chk_time_enable.setChecked(True)
    dlg._dt_from.setDateTime(QDateTime(QDate(2026, 3, 1), QTime(9, 0, 0)))
    dlg._dt_to.setDateTime(QDateTime(QDate(2026, 3, 1), QTime(10, 0, 0)))
    dlg._save_preset()
    dlg.close()
    saved = json.load(open(path, encoding="utf-8"))
    check("the preset carries the UTC bounds 03:30Z-04:30Z",
          saved.get("date_from_utc") == "2026-03-01T03:30:00Z" and saved.get("date_to_utc") == "2026-03-01T04:30:00Z",
          f"{saved.get('date_from_utc')} / {saved.get('date_to_utc')}")
    from evtx_tool.core.filters import load_filter, compile_filter
    f = compile_filter(load_filter(path))
    ev = lambda t: {"event_id": 1, "timestamp": t, "event_data": {}}
    check("CLI --filter-file keeps 04:00Z", f(ev("2026-03-01T04:00:00.000000Z")))
    check("CLI --filter-file drops 06:00Z", not f(ev("2026-03-01T06:00:00.000000Z")))
    M.set_tz_config("utc", "UTC", 0)
    d2 = FilterDialog({}, current_filter=saved)
    got = (d2._dt_from.dateTime().toString("yyyy-MM-dd HH:mm:ss"), d2._dt_to.dateTime().toString("yyyy-MM-dd HH:mm:ss"))
    check("reloaded under UTC the dialog shows 03:30-04:30", got == ("2026-03-01 03:30:00", "2026-03-01 04:30:00"), str(got))
    d2.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
