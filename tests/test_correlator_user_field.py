"""Correlation rules attribute a logon to the account that logged on.

Gemini audit 7-01 (High): _get_user() took SubjectUserName before
TargetUserName for every event.  On a 4624/4625 the subject is the local
caller -- "-" on a network logon, HOST$ otherwise -- so three different
accounts each logging on to one host became "User '-' made remote logons to
3 computers" (a false lateral-movement chain), and failures and a success
for one account were split or merged by the caller's name.

Expected: three network logons by alice/bob/carol to three hosts make no
Multi-Host Lateral Movement chain; five 4625s and one 4624 for alice
(subject "-") make a Brute Force -> Successful Logon chain for alice; a
4688's user is still its SubjectUserName.  Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, eid, sec, comp, data):
    return {"record_id": rid, "event_id": eid, "timestamp": f"2026-01-01T10:00:{sec:02d}.000000Z",
            "computer": comp, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "source_file": "s.evtx", "event_data": data}


def main() -> int:
    from evtx_tool.analysis.correlator import correlate, _get_user
    lat = [ev(i + 1, 4624, i, f"HOST-0{i + 1}", {"SubjectUserName": "-", "TargetUserName": u,
                                                 "LogonType": "3", "IpAddress": "192.0.2.9"})
           for i, u in enumerate(("alice", "bob", "carol"))]
    names = [c["rule_name"] for c in correlate(lat)]
    check("three accounts on three hosts are not lateral movement by '-'",
          "Multi-Host Lateral Movement" not in names, str(names))
    bf = [ev(i + 1, 4625, i, "HOST-01", {"SubjectUserName": "-", "TargetUserName": "alice", "LogonType": "3",
                                          "IpAddress": "192.0.2.50", "Status": "0xc000006d"}) for i in range(5)]
    bf.append(ev(6, 4624, 10, "HOST-01", {"SubjectUserName": "-", "TargetUserName": "alice", "LogonType": "3",
                                          "IpAddress": "192.0.2.50"}))
    ch = [c for c in correlate(bf) if c["rule_name"] == "Brute Force -> Successful Logon"]
    check("five failures + a success for alice make a brute-force chain for alice",
          ch and "alice" in [u.lower() for u in ch[0].get("users", [])], str([c.get("users") for c in ch]))
    p = ev(9, 4688, 20, "HOST-01", {"SubjectUserName": "dave", "TargetUserName": "-", "NewProcessName": "x.exe"})
    check("a 4688's user is its SubjectUserName", _get_user(p) == "dave", _get_user(p))
    from evtx_tool.analysis.correlator import _is_system_user
    check("Windows' DWM-n / UMFD-n session accounts count as built-in",
          _is_system_user("DWM-1") and _is_system_user("umfd-12") and not _is_system_user("dwm-admin"))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
