"""Right-click "Quick Filter: X = value" keeps the row it was taken from, in both modes.

Gemini audit 3-15 / 5-01 (High): the menu filtered by the cell's DISPLAY text,
which drops "Microsoft-Windows-" from Channel and the folder from Source File,
so "Channel = Sysmon/Operational" matched 0 rows (and "≠" hid nothing).
Gemini audit 3-03 / 5-02 (High): in Juggernaut mode "Event Record ID = n" was
accepted (badge lit) but had no column mapping, so it filtered nothing.

Expected, in Normal and Juggernaut mode: "=" on Channel, Source File and
Event Record ID keeps exactly the rows with that value; "≠" removes them.
Synthetic events; the real context menu is built and its action triggered.
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
    import faulthandler
    faulthandler.dump_traceback_later(240, exit=True)    # a hang prints where, then exits
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QMenu, QMessageBox
    for _n in ("information", "warning", "critical", "question"):
        setattr(QMessageBox, _n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    evs = []
    for i in range(4):
        e = T.ev(r"C:\Case\HostA\Sysmon.evtx" if i < 1 else r"C:\Case\HostA\Security.evtx", i + 1, "HOST",
                 T.T0 + timedelta(seconds=i), 1 if i < 1 else 4624)
        e["channel"] = "Microsoft-Windows-Sysmon/Operational" if i < 1 else "Security"
        e["event_record_id"] = 9000 + i
        evs.append(e)
    pick = {"include": True}

    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication

    def click_menu():
        """The real menu is open (its own event loop): trigger the item, close it."""
        menu = QApplication.activePopupWidget()
        if menu is None:
            QTimer.singleShot(50, click_menu)
            return
        acts = [x for x in menu.actions() if x.text().startswith("Quick Filter")]
        menu.close()
        if acts:
            (acts[0] if pick["include"] else acts[1]).trigger()

    for jm in (False, True):
        mode = "Juggernaut" if jm else "Normal"
        for col, label in ((5, "Channel"), (8, "Source File"), (22, "Event Record ID")):
            for include in (True, False):
                w = mw.MainWindow()
                m = T.Mode(mw, jm)
                m.load(w, evs)
                if jm:
                    w._table.setModel(w._hw_model)
                    w._connect_jm_model_signals(w._hw_model)
                w._warn_blocking = lambda *a, **k: None
                T.pump(200)
                table = w._active_table
                idx = table.model().index(0, col)
                table.indexAt = lambda pos, _i=idx: _i          # the cell that was right-clicked
                pick["include"] = include
                from PySide6.QtCore import QPoint
                QTimer.singleShot(50, click_menu)
                w._on_table_context_menu(QPoint(1, 1))
                T.pump(400)
                if jm:
                    T.wait_for(lambda: not getattr(w._hw_model, "_filtering", False), 10)
                    T.pump(300)
                n = table.model().rowCount()
                want = 1 if include else 3
                check(f"{mode}: {label} {'=' if include else '≠'} keeps {want} row(s)", n == want, f"{n} rows")
                T.teardown(w, jm, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
