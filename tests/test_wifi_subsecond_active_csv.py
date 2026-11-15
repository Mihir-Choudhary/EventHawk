"""WiFi history: sub-second order, "Active" only when connected, CSV as shown.

Gemini audit 8-02 (High): connect and disconnect events were merged and sorted
on whole-second timestamps, connects first.  A disconnect from AP1 and a roam
to AP2 700 ms later in the same second ran in the wrong order: AP1 was left
"no disconnect" and AP2 was closed by AP1's disconnect, 0 s.

Gemini audit 8-08 (Medium): the table and the summary called a session
"Active" when it had no disconnect time, so a failed 8004 attempt and a
superseded session (no disconnect logged) read "Active" and counted as active.

Gemini audit 8-13 (Medium): Export CSV wrote the whole-second values, an empty
Disconnected cell for an active session, and the stored duration, not what the
table showed at the analyst's precision.

Expected: AP1 closed, AP2 open (Active); only genuinely open sessions read
"Active" and are counted; the CSV cells match the table's.  Synthetic events.
"""
import csv
import os
import shutil
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import wlan                             # noqa: E402

CHECKS = []
GUID2 = "{99999999-2222-3333-4444-555555555555}"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    _app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import set_ts_precision, get_ts_precision
    D = mw._WifiHistoryDialog

    # 8-02: T0 is xx:25.366; the disconnect (30.066) and the roam (30.766) share a second.
    evs = [wlan("H", 1, 0.0, 8001, "AP1"), wlan("H", 2, 4.7, 8003, "AP1"), wlan("H", 3, 5.4, 8001, "AP2")]
    ss = {s["ssid"]: s for s in D._build_sessions(evs)}
    a1, a2 = ss.get("AP1", {}), ss.get("AP2", {})
    check("AP1 is closed by its own disconnect", a1.get("disconnect_ts") and "no_disconnect" not in a1.get("anomaly_flags", ["no_disconnect"]),
          f"{a1.get('disconnect_ts')!r} {a1.get('anomaly_flags')}")
    check("AP2 (connected after the disconnect) is still active", a2.get("duration") == "Active"
          and not a2.get("disconnect_ts"), f"{a2.get('duration')!r} {a2.get('disconnect_ts')!r}")

    # 8-08: one failed attempt, one superseded session, one genuinely open one.
    evs2 = [wlan("H", 1, 0, 8004, "Failed"), wlan("H", 2, 60, 8001, "Super"), wlan("H", 3, 120, 8001, "Open")]
    for e in evs2[:1]:
        e["event_data"]["InterfaceGuid"] = GUID2           # its own adapter: not superseded
    d = D(evs2)
    try:
        ses = {s["ssid"]: s for s in d._shown_sessions}
        rows = {}
        for r in range(d._tbl.rowCount()):
            rows[d._tbl.item(r, 0).text()] = d._tbl.item(r, 5).text()
        check("a failed attempt and a superseded session do not read 'Active'",
              rows.get("Failed") != "Active" and rows.get("Super") != "Active", str(rows))
        check("the open session reads 'Active'", rows.get("Open") == "Active", str(rows))
        txt = d._lbl_summary.text()
        check("the summary counts 1 active", "<b>1</b> active" in txt, txt)
        check("durations are untouched", (ses["Failed"]["duration"], ses["Super"]["duration"]) ==
              ("Failed (no close)", "Unavailable (no disconnect logged)"), str([s["duration"] for s in ses.values()]))
    finally:
        d.close()

    # 8-13: CSV = table, at microsecond precision.
    old = get_ts_precision()
    set_ts_precision(6)
    tmp = tempfile.mkdtemp(prefix="wifi813_")
    real = (QFileDialog.getSaveFileName, QMessageBox.information, QMessageBox.critical)
    try:
        d = D([wlan("H", 1, 0, 8001, "Roam"), wlan("H", 2, 5.5, 8003, "Roam"), wlan("H", 3, 60, 8001, "Now")])
        table = {}
        for r in range(d._tbl.rowCount()):
            table[d._tbl.item(r, 0).text()] = [d._tbl.item(r, c).text() for c in (4, 5, 6)]
        p = os.path.join(tmp, "w.csv")
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (p, "CSV (*.csv)"))
        QMessageBox.information = staticmethod(lambda *a, **k: None)
        QMessageBox.critical = staticmethod(lambda *a, **k: print("  export error box:", a[2:3]))
        d._on_export_csv()
        with open(p, encoding="utf-8-sig", newline="") as fh:
            rr = list(csv.reader(fh))[1:]
        got = {r[0]: [r[4], r[5], r[6]] for r in rr}
        check("CSV connect/disconnect/duration cells equal the table's", got == table and len(got) == 2,
              f"csv={got} table={table}")
        check("the table shows microseconds (the check is not vacuous)",
              table.get("Roam", [""])[0].count(".") == 1 and table["Roam"][2] == "5.500000s", str(table.get("Roam")))
        d.close()
    finally:
        QFileDialog.getSaveFileName, QMessageBox.information, QMessageBox.critical = real
        set_ts_precision(old)
        shutil.rmtree(tmp, ignore_errors=True)

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
