"""LogonId sessions are per host, per logon, and case-insensitive.

Gemini audit 7-02 (High): the correlator's session index keyed sessions by
the raw LogonId text only.  A LogonId is unique per host and boot, so a
process on host B joined a logon on host A; a reused LogonId replaced the
earlier logon (its processes were credited to the later one, even ones
that ran before it); and "0x4F120" and "0x4f120" were different sessions.

Expected: a process on another host with the same LogonId is not linked;
after a LogonId is reused, each logon keeps its own processes; a LogonId
differing only in hex case is the same session.  Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, eid, sec, comp, data):
    return {"record_id": rid, "event_id": eid, "timestamp": f"2026-01-01T10:{sec // 60:02d}:{sec % 60:02d}.000000Z",
            "computer": comp, "channel": "Security", "provider": "P", "source_file": "s.evtx", "event_data": data}


def main() -> int:
    from evtx_tool.analysis.correlator import _LogonSessionIndex
    logon = lambda r, s, c, lid, u="alice": ev(r, 4624, s, c, {"TargetLogonId": lid, "TargetUserName": u, "LogonType": "3"})
    proc = lambda r, s, c, lid: ev(r, 4688, s, c, {"SubjectLogonId": lid, "NewProcessName": "x.exe"})
    idx = _LogonSessionIndex([logon(1, 0, "HOST-A", "0x4f120"), proc(2, 5, "HOST-B", "0x4f120")])
    linked = [s for s in idx.sessions.values() if s["logon"] and s["procs"]]
    check("a process on another host is not linked to the logon", not linked, str(len(linked)))
    idx = _LogonSessionIndex([logon(1, 0, "HOST-A", "0x1234", "alice"), proc(2, 5, "HOST-A", "0x1234"),
                              logon(3, 600, "HOST-A", "0x1234", "bob"), proc(4, 605, "HOST-A", "0x1234")])
    byuser = {s["logon"]["event_data"]["TargetUserName"]: [p["record_id"] for p in s["procs"]]
              for s in idx.sessions.values() if s["logon"]}
    check("a reused LogonId keeps each logon's own processes", byuser == {"alice": [2], "bob": [4]}, str(byuser))
    idx = _LogonSessionIndex([logon(1, 0, "HOST-A", "0x4F120"), proc(2, 5, "HOST-A", "0x4f120")])
    linked = [s for s in idx.sessions.values() if s["logon"] and s["procs"]]
    check("0x4F120 and 0x4f120 are the same session", len(linked) == 1, str(len(linked)))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
