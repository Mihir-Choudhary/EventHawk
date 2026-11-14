"""Logon Session Browser: people's sessions first, every column in view.

  - Windows' own accounts (SYSTEM, LOCAL / NETWORK SERVICE, DWM-n, UMFD-n,
    NAME$) are hidden by default; the box says how many; unticking shows them.
  - Every column fits a 1280 px screen without scrolling sideways: the
    Initiation text is the Logon Type cell's tooltip.
  - The row tints have a legend; headers carry no emoji.

Run: QT_QPA_PLATFORM=offscreen python tests/test_logon_sessions_ux.py
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


def logon(rid, user, lid, t, ltype="2", domain="WS1"):
    return {"event_id": 4624, "computer": "WS1", "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "record_id": rid, "event_record_id": rid, "timestamp": t, "source_file": "Security.evtx",
            "level": 0, "level_name": "Information",
            "event_data": {"TargetUserName": user, "TargetDomainName": domain, "TargetLogonId": lid,
                           "LogonType": ltype}}


def main() -> int:
    from PySide6.QtWidgets import QApplication, QLabel
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    evs = [logon(1, "alice", "0x1001", "2025-06-29T12:00:00.000000Z"),
           logon(2, "SYSTEM", "0x3e7", "2025-06-29T12:00:01.000000Z", "0", "NT AUTHORITY"),
           logon(3, "DWM-1", "0x2001", "2025-06-29T12:00:02.000000Z", "2", "Window Manager"),
           logon(4, "UMFD-1", "0x2002", "2025-06-29T12:00:02.000000Z", "2", "Font Driver Host"),
           logon(5, "WS1$", "0x2003", "2025-06-29T12:00:03.000000Z", "3", "CORP"),
           logon(6, "bob", "0x1002", "2025-06-29T12:05:00.000000Z", "10")]
    dlg = mw._LogonSessionDialog(evs, on_filter_fn=lambda *a, **k: None)
    dlg.resize(1260, 640)
    dlg.show()
    app.processEvents()
    users = {dlg._tbl.item(r, 0).text() for r in range(dlg._tbl.rowCount())}
    check("system accounts are hidden by default", users == {"alice", "bob"}, str(sorted(users)))
    check("...the box says how many", "(4)" in dlg._chk_hide_system.text(), dlg._chk_hide_system.text())
    dlg._chk_hide_system.setChecked(False)
    users = {dlg._tbl.item(r, 0).text() for r in range(dlg._tbl.rowCount())}
    check("...unticking shows them", {"SYSTEM", "DWM-1", "UMFD-1", "WS1$"} <= users, str(sorted(users)))
    dlg._chk_hide_system.setChecked(True)
    app.processEvents()

    hdr = dlg._tbl.horizontalHeader()
    shown = [c for c in range(dlg._tbl.columnCount()) if not dlg._tbl.isColumnHidden(c)]
    width = sum(dlg._tbl.columnWidth(c) for c in shown)
    check("every column fits without scrolling sideways at 1260 px",
          dlg._tbl.horizontalScrollBar().maximum() == 0, f"columns {width} px, viewport {dlg._tbl.viewport().width()}")
    names = [dlg._tbl.horizontalHeaderItem(c).text() for c in range(dlg._tbl.columnCount())]
    check("headers carry no emoji", all(ord(ch) < 0x2190 for n in names for ch in n), str(names))
    r_alice = next(r for r in range(dlg._tbl.rowCount()) if dlg._tbl.item(r, 0).text() == "alice")
    check("what the logon type means is its tooltip",
          "console" in dlg._tbl.item(r_alice, 2).toolTip().lower(), dlg._tbl.item(r_alice, 2).toolTip())
    legend = [lb.text() for lb in dlg.findChildren(QLabel)]
    check("the row tints have a legend",
          "Dangerous privileges assigned" in legend and "No logoff recorded" in legend)
    dlg.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
