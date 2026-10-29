"""Inbound RDP boundaries must survive ID reuse without inferred durations.

Synthetic evidence only. Row references identify the original reconstruction
row, so sorting/filtering/export cannot silently retarget a continuation.
"""
import csv
import multiprocessing
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path[:0] = [str(Path(__file__).resolve().parents[1]), str(Path(__file__).parent)]
import test_around_pivot as T
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication
import evtx_tool.gui.main_window as mw

APP = QApplication.instance() or QApplication([])
CHECKS = []
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
RCM = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"


def check(name, ok):
    CHECKS.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'} {name}", flush=True)


def ev(eid, sec, sid="3", user="SYNTH\\alice", channel=LSM, **extra):
    data = {"SessionID": sid, "User": user, "Address": "192.0.2.5"}
    data.update(extra.pop("data", {}))
    result = dict(event_id=eid, timestamp=(BASE+timedelta(seconds=sec)).isoformat().replace("+00:00", "Z"),
                  channel=channel, provider=channel.split("/")[0], computer="SYNTH-HOST",
                  source_file="synthetic.evtx", record_id=sec*10+eid, event_data=data)
    result.update(extra)
    return result


def build(events):
    return mw._RemoteAssistanceDialog._build_sessions(events)


def pure():
    rows = build([ev(21, 0), ev(23, 60), ev(21, 120), ev(23, 180)])
    check("reused SessionID yields two separate 60 second rows",
          len(rows) == 2 and [r["duration_secs"] for r in rows] == [60, 60])
    check("new logon after logoff never claims continuity", all(not r.get("continuity") for r in rows))
    chain = [ev(21, 0), ev(22, 1), ev(24, 60), ev(25, 120), ev(23, 180)]
    rows = build(chain)
    check("disconnect/reconnect yields two separately proved intervals",
          len(rows) == 2 and [r["duration_secs"] for r in rows] == [60, 60])
    check("reconnect visibly references the earlier row",
          len(rows) == 2 and rows[1].get("continuity") == "continues the session in row 1 (reconnect)")
    check("continuation filter includes only its own evidence",
          len(rows) == 2 and rows[1]["related_keys"] == frozenset(("synthetic.evtx", e["record_id"]) for e in chain[3:]))
    for label, events in [
        ("missing end", [ev(21, 0), ev(22, 1)]),
        ("missing start", [ev(22, 0), ev(24, 60)]),
        ("authentication is not a logon", [ev(1149, 0, channel=RCM), ev(24, 60)]),
        ("user mismatch", [ev(21, 0), ev(23, 60, user="OTHER\\alice")]),
        ("missing SessionID", [ev(21, 0, sid=""), ev(23, 60, sid="")]),
        ("missing host and source", [ev(21, 0, computer="", source_file=""), ev(23, 60, computer="", source_file="")]),
        ("boot barrier", [ev(21, 0), ev(4608, 30, channel="Security"), ev(23, 60)]),
    ]:
        r = build(events)
        check(label+": duration Unavailable", bool(r) and all(x["duration"] == "Unavailable" for x in r))
    r=build([ev(21,0),ev(4608,30,channel="Security"),ev(23,60)])
    check("missing termination does not claim that a session is still active",all(x['status']!='Active / Ongoing' for x in r))
    for label, events in [
        ("different domain", [ev(21, 0), ev(24, 60), ev(25, 120, user="OTHER\\alice")]),
        ("intervening logoff", [ev(21, 0), ev(24, 60), ev(23, 90), ev(25, 120)]),
        ("intervening boot", [ev(21, 0), ev(24, 60), ev(4608, 90, channel="Security"), ev(25, 120)]),
    ]:
        check(label+": no continuity claim", all(not r.get("continuity") for r in build(events)))
    r = build([ev(41, 0), ev(22, 60)])
    check("arbitration and shell events never prove boundaries", all(x["duration"] == "Unavailable" for x in r))
    r = build([ev(21, 0), ev(39, 60, data={"SessionID":"", "TargetSession":"3"})])
    check("LSM 39 TargetSession proves disconnect of that session", any(x["duration_secs"] == 60 for x in r))
    sec = [ev(4778, 0, channel="Security", data={"LogonID":"0x10", "AccountName":"alice", "AccountDomain":"SYNTH"}),
           ev(4779, 60, channel="Security", data={"LogonID":"0x10", "AccountName":"alice", "AccountDomain":"SYNTH"})]
    r = build(sec)
    check("Security reconnect/disconnect uses documented LogonID", len(r) == 1 and r[0]["duration_secs"] == 60)
    r = build([ev(21, 0, sid="16"), ev(23, 60, sid="16")]+sec)
    check("Security LUID and LSM SessionID remain separate rows", len(r) == 2 and all(x["duration_secs"] == 60 for x in r))
    reused = [ev(4624,0,channel="Security",data={"LogonType":"10","TargetLogonId":"0x10"}),
              sec[0],ev(4624,30,channel="Security",data={"LogonType":"10","TargetLogonId":"0x10"}),sec[1]]
    reused[1] = dict(reused[1],timestamp=(BASE+timedelta(seconds=10)).isoformat().replace("+00:00","Z"))
    check("new Security logon invalidates a prior connection interval",all(r["duration"]=="Unavailable" for r in build(reused)))
    sec_other = [dict(e, record_id=e["record_id"]+10000, event_data={**e["event_data"],"LogonID":"0x20"}) for e in sec]
    r=build(sec+sec_other)
    check("concurrent Security LUIDs stay separate",len(r)==2 and all(x["duration_secs"]==60 for x in r))
    copies = [dict(e,source_file="copy.evtx") for e in chain]
    r = build(chain+copies)
    check("copies do not create sessions", len(r) == 2)
    check("copies remain filterable and disclosed", sum(len(x["related_keys"]) for x in r) == 10 and all("copy.evtx" in x["source_log"] for x in r))
    fractional = ev(21,0)
    fractional["timestamp"] = "2024-01-01T00:00:00.0000001Z"
    distinct = dict(fractional, source_file="other_capture.evtx", timestamp="2024-01-01T00:00:00.0000002Z")
    check("distinct raw timestamps are not collapsed at display precision",len(build([fractional,distinct]))==2)
    return chain


def gui(chain):
    for jm in (False, True):
        mode=T.Mode(mw,jm);w=mw.MainWindow()
        try:
            mode.load(w,chain);w._on_show_remote_assist()
            ready=T.wait_for(lambda:getattr(w,"_ra_dlg",None) is not None,20)
            check(f"{'JM' if jm else 'Normal'} opens actual Tools dialog",ready)
            if not ready:continue
            d=w._ra_dlg
            check(f"{jm}: two real dialog rows",d._tbl.rowCount()==2)
            headers=[d._tbl.horizontalHeaderItem(i).text() for i in range(d._tbl.columnCount())]
            check(f"{jm}: visible Row and Continuity columns", "Row" in headers and "Continuity" in headers)
            if "Continuity" not in headers:continue
            d._tbl.sortItems(2,Qt.SortOrder.DescendingOrder)
            check(f"{jm}: reference stays attached after sorting",d._tbl.item(0,headers.index("Continuity")).text()=="continues the session in row 1 (reconnect)" and d._tbl.item(0,headers.index("Row")).text()=="2")
            d._txt_search.setText("continues the session")
            d._apply_display_filters()
            check(f"{jm}: filtering retains stable row references",d._tbl.rowCount()==1 and d._tbl.item(0,headers.index("Row")).text()=="2")
            d._clear_filters()
            with tempfile.TemporaryDirectory(prefix="rdp_synthetic_") as tmp:
                path=str(Path(tmp)/"sessions.csv")
                with patch.object(mw.QFileDialog,"getSaveFileName",return_value=(path,"CSV")),patch.object(mw.QMessageBox,"information"):
                    d._on_export_csv()
                with open(path,encoding="utf-8-sig",newline="") as f:export=list(csv.DictReader(f))
                check(f"{jm}: CSV preserves sorted stable references",len(export)==2 and export[0]["Row"]=="2" and export[0]["Continuity"]=="continues the session in row 1 (reconnect)")
            d.close()
        finally:T.teardown(w,jm,mode)
        mode=T.Mode(mw,jm);w=mw.MainWindow()
        try:
            mode.load(w,[ev(21,0),ev(4608,30,channel="Security"),ev(23,60)])
            w._on_show_remote_assist();T.wait_for(lambda:getattr(w,"_ra_dlg",None) is not None,20)
            rows=w._ra_dlg._all_sessions
            check(f"{jm}: Tools fetch preserves boot barriers",len(rows)==2 and all(r["duration"]=="Unavailable" for r in rows))
        finally:T.teardown(w,jm,mode)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    gui(pure())
    print(f"{sum(CHECKS)}/{len(CHECKS)} checks passed")
    sys.exit(0 if all(CHECKS) else 1)
