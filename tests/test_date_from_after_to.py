"""The filter dialog refuses From later than To; an unavailable zone is not claimed.

Gemini audit 4-09 (Medium): FilterDialog accepted From > To in every date
mode with no error, so the filter silently matched nothing (or, in some
modes, everything), indistinguishable from "no events".
Gemini audit 4-06 (High): with no tzdata (frozen builds), choosing a named
zone left the display in UTC while the status bar said "Timezone:
Asia/Kolkata".

Expected: From > To is an error in range, date-only, time-only and separate
modes; From <= To is not; a zone ZoneInfo cannot load is reported and the
status bar does not claim it.  Synthetic values.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QDateTime, QDate, QTime
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.gui.filter_dialog import FilterDialog
    late = QDateTime(QDate(2026, 3, 5), QTime(18, 0, 0))
    early = QDateTime(QDate(2026, 3, 1), QTime(6, 0, 0))
    for label, d, t, sep in (("range", True, True, False), ("date only", True, False, False),
                             ("time only", False, True, False), ("separate", True, True, True)):
        for frm, to, bad in ((late, early, True), (early, late, False)):
            dlg = FilterDialog({})
            dlg._chk_date_enable.setChecked(d)
            dlg._chk_time_enable.setChecked(t)
            dlg._chk_separately.setChecked(sep)
            dlg._dt_from.setDateTime(frm)
            dlg._dt_to.setDateTime(to)
            errs = [e for e in dlg._validate_inputs() if "From" in e or "later" in e]
            check(f"{label}: From {'>' if bad else '<='} To is {'refused' if bad else 'accepted'}",
                  bool(errs) == bad, str(errs[:1]))
            dlg.close()

    import zoneinfo
    import evtx_tool.gui.main_window as mw
    real = zoneinfo.ZoneInfo

    def fake(name):
        if name == "Asia/Kolkata":
            raise zoneinfo.ZoneInfoNotFoundError(name)
        return real(name)
    zoneinfo.ZoneInfo = fake
    w = mw.MainWindow()
    warned = []
    w._warn_blocking = lambda title, text, **k: warned.append(text)
    w._tz_mode, w._tz_specific = "specific", "Asia/Kolkata"
    w._apply_tz_to_all_models()
    status = w._lbl_status.text()
    check("an unavailable zone is reported", warned and "Asia/Kolkata" in warned[-1], str(warned[-1:])[:120])
    check("the status bar does not claim the unavailable zone", "Timezone: Asia/Kolkata" != status, status)
    zoneinfo.ZoneInfo = real
    w._tz_mode = "utc"
    w._apply_tz_to_all_models()
    w.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
