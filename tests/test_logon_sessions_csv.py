"""The Logon Sessions dialog exports its table to CSV (Gemini 14-03).

The four other forensic dialogs (WiFi, remote access, RDP, PowerShell) export
CSV; Logon Sessions had no export at all. Expected: an "Export CSV" button; the
file holds the table exactly as shown (same columns, same text, the order the
analyst sorted it in, only the rows the display filters leave), formula-safe
cells. Synthetic events only.
"""
import csv
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")
CHECKS = []
T0 = datetime(2026, 1, 1, 10, 0, 0)


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(secs, eid, rid, ed):
    return {"event_id": eid, "computer": "WS1", "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "timestamp": (T0 + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "record_id": rid, "source_file": "Security.evtx", "event_data": dict(ed)}


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox, QPushButton
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import _LogonSessionDialog
    evs = [ev(0, 4624, 1, {"TargetLogonId": "0xa1", "LogonType": "2", "TargetUserName": "alice"}),
           ev(60, 4634, 2, {"TargetLogonId": "0xa1"}),
           ev(100, 4624, 3, {"TargetLogonId": "0xb1", "LogonType": "3", "TargetUserName": "=HYPERLINK(\"x\")"}),
           ev(200, 4624, 4, {"TargetLogonId": "0xc1", "LogonType": "10", "TargetUserName": "carol"})]
    d = _LogonSessionDialog(events=evs, on_filter_fn=lambda *a: None)
    btns = [b.text() for b in d.findChildren(QPushButton)]
    check("an Export CSV button exists", any("Export CSV" in t for t in btns), str(btns))
    if not hasattr(d, "_on_export_csv"):
        check("export runs", False, "no _on_export_csv")
    else:
        d._tbl.sortItems(0, Qt.SortOrder.DescendingOrder)
        shown = [[d._tbl.item(r, c).text() if d._tbl.item(r, c) else "" for c in range(d._tbl.columnCount())]
                 for r in range(d._tbl.rowCount()) if not d._tbl.isRowHidden(r)]
        tmp = tempfile.mkdtemp(prefix="lsc_")
        out = os.path.join(tmp, "s.csv")
        real = (QFileDialog.getSaveFileName, QMessageBox.information, QMessageBox.critical)
        msgs = []
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
        QMessageBox.information = staticmethod(lambda *a, **k: msgs.append(("info", a[2] if len(a) > 2 else "")))
        QMessageBox.critical = staticmethod(lambda *a, **k: msgs.append(("crit", a[2] if len(a) > 2 else "")))
        try:
            d._on_export_csv()
        finally:
            QFileDialog.getSaveFileName, QMessageBox.information, QMessageBox.critical = real
        rows = list(csv.reader(open(out, encoding="utf-8-sig", newline=""))) if os.path.exists(out) else []
        check("header = the table's columns", rows and rows[0] == list(d._HEADERS), str(rows[:1]))
        body = [[c[1:] if c.startswith("'=") else c for c in r] for r in rows[1:]]
        check("rows = the table as shown, in its sorted order", body == shown, f"{len(body)} vs {len(shown)}")
        check("a formula-like user name is made safe", any(c.startswith("'=") for r in rows[1:] for c in r))
        check("completion message names the count", any(k == "info" and str(len(shown)) in m for k, m in msgs), str(msgs))
        shutil.rmtree(tmp, ignore_errors=True)
    d.close()
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
