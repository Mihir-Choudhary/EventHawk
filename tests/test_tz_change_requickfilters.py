"""Changing the display time zone re-applies date quick filters; the label is right.

Gemini audit 4-04 (High): a Timestamp quick filter ("date = 2026-03-01") is a
DISPLAYED date.  After a time-zone change Juggernaut kept the SQL built for
the old zone and the Normal proxy was not re-run, so the view kept rows
whose shown date no longer matched.
Gemini audit 4-07 (Medium): a negative custom offset was labelled with floor
division: UTC-00:30 read "UTC-1:30".

Expected, both modes: with "date = 2026-03-01" set in UTC on events at
2026-03-01 20:00Z and 2026-03-02 01:00Z, switching to UTC+09:00 (both now
shown on 2026-03-02) leaves 0 rows; the status bar says "UTC-00:30" for -30.
Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from datetime import datetime, timezone                             # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = [T.ev(r"C:\c\a.evtx", 1, "H", datetime(2026, 3, 1, 20, 0, tzinfo=timezone.utc)),
           T.ev(r"C:\c\a.evtx", 2, "H", datetime(2026, 3, 2, 1, 0, tzinfo=timezone.utc))]
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
        w._apply_quick_filter("timestamp_date", "2026-03-01", True)
        T.pump(500)
        mdl = w._active_table.model()
        if jm:
            T.wait_for(lambda: mdl.rowCount() == 1, 10)
        before = mdl.rowCount()
        w._tz_mode, w._tz_custom_offset_min = "custom", 540
        w._apply_tz_to_all_models()
        T.pump(600)
        if jm:
            T.wait_for(lambda: mdl.rowCount() == 0, 10)
            T.pump(200)
        after = mdl.rowCount()
        check(f"{mode}: 'date = 2026-03-01' follows the zone change (1 -> 0 rows)", before == 1 and after == 0,
              f"{before} -> {after}")
        if not jm:
            w._tz_mode, w._tz_custom_offset_min = "custom", -30
            w._apply_tz_to_all_models()
            txt = w.statusBar().currentMessage() if hasattr(w, "statusBar") else ""
            lab = getattr(w, "_lbl_status", None)
            txt = (lab.text() if lab is not None else "") or txt
            check("a -30 minute custom offset is labelled UTC-00:30", "UTC-00:30" in txt, txt)
        w._tz_mode, w._tz_custom_offset_min = "utc", 0
        w._apply_tz_to_all_models()
        T.teardown(w, jm, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
