"""Logon Sessions must not multiply when the same log is loaded twice.

A collection folder often holds "Security.evtx" next to "Security - Copy.evtx"
(the reference corpus has four).  _LogonSessionDialog opened a session on
every 4624 and attached each following 4672/4688 to the most recent session
for that LogonId -- so with copies, every copy of a logon became its own
session and EVERY copy of its privileged events landed on the last one.
Measured on the real log plus three copies, in both Normal and Juggernaut:
155 sessions became 890, and a session with one privileged event showed as
four rows -- one claiming 4 privileged events, three claiming none.

Repeats of the same physical record (host + event id + exact timestamp +
record id) are now collapsed first, as Remote Assistance already did.  The
copies' (file, record) keys are kept so the session filter still covers them.
"""
import os
import sys
from datetime import datetime, timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


T0 = datetime(2026, 2, 11, 16, 44, 11)


def log(jm: bool, source: str):
    """Two sessions: an admin logon with privileges and a process, and an RDP
    logon, each logged off.  *jm* selects Juggernaut's event shape."""
    rows = [
        (0, 4624, 101, {"TargetLogonId": "0x8c9c53", "LogonType": "11", "TargetUserName": "alice"}),
        (0, 4672, 102, {"SubjectLogonId": "0x8c9c53", "PrivilegeList": "SeDebugPrivilege"}),
        (5, 4688, 103, {"SubjectLogonId": "0x8c9c53", "NewProcessName": r"C:\Windows\cmd.exe"}),
        (60, 4634, 104, {"TargetLogonId": "0x8c9c53"}),
        (120, 4624, 105, {"TargetLogonId": "0x9a", "LogonType": "10", "TargetUserName": "bob"}),
        (900, 4634, 106, {"TargetLogonId": "0x9a"}),
    ]
    out = []
    for secs, eid, rid, ed in rows:
        ev = {"event_id": eid, "computer": "MSI",
              "timestamp": (T0 + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
              "event_data": dict(ed)}
        if jm:
            ev.update(_record_id=rid, _source_file=source)
        else:
            ev.update(record_id=rid, source_file=source, channel="Security")
        out.append(ev)
    return out


def sessions(events):
    from evtx_tool.gui.main_window import _LogonSessionDialog
    d = _LogonSessionDialog(events=events, on_filter_fn=lambda *a: None)
    s = d._all_sessions
    d.close()
    return s


def merged(*logs):
    # the merged view is in time order, so copies interleave record by record
    return sorted((e for lg in logs for e in lg), key=lambda e: e["timestamp"])


def main() -> int:
    for jm in (False, True):
        mode = "Juggernaut" if jm else "Normal"
        print(f"=== {mode} event shape ===")
        one = sessions(log(jm, "Security.evtx"))
        four = sessions(merged(*(log(jm, n) for n in (
            "Security.evtx", "Security - Copy.evtx",
            "Security - Copy (2).evtx", "Security - Copy - Copy.evtx"))))
        check(f"{mode}: one log gives 2 sessions", len(one) == 2, str(len(one)))
        check(f"{mode}: the log plus three copies gives the same 2",
              len(four) == len(one), str(len(four)))
        admin = [s for s in four if s.get("lid") == "0x8c9c53"]
        a = admin[0] if admin else {}
        check(f"{mode}: the admin session keeps exactly 1 privileged event",
              [s.get("priv_count") for s in admin] == [1],
              str([s.get("priv_count") for s in admin]))
        if jm:
            keys = a.get("related_keys") or set()
            files = {f for f, _r in keys}
            check(f"{mode}: the session filter keys still cover every copy",
                  len(files) == 4, str(sorted(files)))

    print("\n=== an event without a record id is never collapsed ===")
    evs = log(False, "a.evtx")
    for e in evs:
        e.pop("record_id")
    s = sessions(evs + [dict(evs[0])])        # exact repeat, but no record id
    check("two record-id-less 4624s stay two sessions",
          sum(1 for x in s if x.get("lid") == "0x8c9c53") == 2,
          str(sum(1 for x in s if x.get("lid") == "0x8c9c53")))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
