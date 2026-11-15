"""Sorting by Channel or Source File follows the text on screen, in both modes.

Gemini audit 5-07 (Medium): the Channel cell drops "Microsoft-Windows-" but
both modes sorted on the full name, so "Sysmon/Operational" sorted after
"Windows PowerShell"; Juggernaut sorted Source File on the full path while
Normal sorted on the file name shown.

Expected: ascending by Channel gives the order of the shown names in both
modes; ascending by Source File gives the order of the shown file names in
both modes.  Synthetic events.
"""
import os
import sys
from datetime import timedelta

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
    from PySide6.QtCore import Qt
    rows = [("Microsoft-Windows-Sysmon/Operational", r"C:\z\b.evtx"),
            ("Security", r"C:\a\c.evtx"),
            ("Microsoft-Windows-AppLocker/EXE and DLL", r"C:\y\a.evtx")]
    evs = []
    for i, (ch, sf) in enumerate(rows):
        e = T.ev(sf, i + 1, "H", T.T0 + timedelta(seconds=i))
        e["channel"] = ch
        evs.append(e)
    want = {5: sorted(r[0].removeprefix("Microsoft-Windows-") for r in rows),
            8: sorted(os.path.basename(r[1]) for r in rows)}
    for jm in (False, True):
        mode = "Juggernaut" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
            w._connect_jm_model_signals(w._hw_model)
        for col, label in ((5, "Channel"), (8, "Source File")):
            mdl = w._active_table.model()
            mdl.sort(col, Qt.SortOrder.AscendingOrder)
            T.pump(400)
            if jm:
                T.wait_for(lambda: not mdl.filter_pending(), 10)
                T.pump(200)
            shown = [str(mdl.index(r, col).data()) for r in range(mdl.rowCount())]
            check(f"{mode}: ascending by {label} follows the shown text", shown == want[col], str(shown))
        T.teardown(w, jm, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
