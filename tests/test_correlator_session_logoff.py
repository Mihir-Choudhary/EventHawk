"""The correlator's logon sessions end at 4647 / 4634 (Gemini audit 8-07, correlator part).

correlator._LogonSessionIndex closed a session only on 4634 and then never
looked at the close: a process started AFTER the 4634, under a LogonId that
Windows had destroyed and reused, joined the closed session -- so the
"network logon spawned N processes" chain named a process the logon never
ran, and the description printed the index's own key ("host|0x...|n") as
the LogonId.  4647 (the user logged off) was ignored.  The index also took the event
list in the order given.  Expected: an event after the 4634 starts a later
session; 4647 ends a session and the 4634 that follows replaces it; logoff
work between them stays in the session; unsorted input gives the same
sessions.  Synthetic events with made-up names only.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(n, eid, ts, **ed):
    return {"event_id": eid, "record_id": n, "timestamp": f"2026-01-01T{ts}.000000Z", "computer": "HOST-A",
            "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "source_file": r"C:\a\Security.evtx", "event_data": ed}


def events():
    L = "0x55a3"
    M = "0x55a2"
    return [
        # Session A: a network logon, one process, logoff, then a process under
        # the reused LogonId 15 minutes later with no new logon.
        ev(1, 4624, "12:00:00", TargetLogonId=L, LogonType="3", TargetUserName="alice", TargetDomainName="LAB"),
        ev(2, 4688, "12:01:00", SubjectLogonId=L, NewProcessName=r"C:\Windows\System32\whoami.exe",
           SubjectUserName="alice"),
        ev(3, 4634, "12:05:00", TargetLogonId=L),
        ev(4, 4688, "12:20:00", SubjectLogonId=L, NewProcessName=r"C:\Windows\System32\net.exe",
           SubjectUserName="alice"),
        # Session B: ended by the user (4647), logoff work, then Windows' 4634.
        ev(5, 4624, "11:00:00", TargetLogonId=M, LogonType="2", TargetUserName="bob", TargetDomainName="LAB"),
        ev(6, 4647, "11:10:00", TargetLogonId=M, TargetUserName="bob"),
        ev(7, 4688, "11:10:01", SubjectLogonId=M, NewProcessName=r"C:\Windows\System32\logoff-work.exe",
           SubjectUserName="bob"),
        ev(8, 4634, "11:10:02", TargetLogonId=M),
        # Session C: ended only by 4647 (its 4634 is not in the log).
        ev(9, 4624, "13:00:00", TargetLogonId="0x55a9", LogonType="2", TargetUserName="carol"),
        ev(10, 4647, "13:30:00", TargetLogonId="0x55a9", TargetUserName="carol"),
    ]


def by_logon(idx):
    out = {}
    for s in idx.sessions.values():
        key = s["logon"]["record_id"] if s["logon"] else None
        out.setdefault(key, []).append(s)
    return out


def main() -> int:
    from evtx_tool.analysis import correlator as C
    evs = events()
    srt = sorted(evs, key=lambda e: e["timestamp"])
    s = by_logon(C._LogonSessionIndex(srt))
    a = s[1][0]
    check("session A keeps only the process started before its 4634",
          [p["record_id"] for p in a["procs"]] == [2], str([p["record_id"] for p in a["procs"]]))
    orphan = [x for x in s.get(None, []) if any(p["record_id"] == 4 for p in x["procs"])]
    check("the process after the 4634 is in a later session with no logon", len(orphan) == 1)
    b = s[5][0]
    check("session B ends at the 4634 that follows the user's 4647",
          b["logoff"] and b["logoff"]["record_id"] == 8, str(b["logoff"] and b["logoff"]["record_id"]))
    check("logoff work between 4647 and 4634 stays in session B",
          [p["record_id"] for p in b["procs"]] == [7])
    c = s[9][0]
    check("session C ended only by 4647 has that logoff",
          c["logoff"] and c["logoff"]["record_id"] == 10, str(c["logoff"]))
    random.seed(7)
    shuffled = evs[:]
    for _ in range(5):
        random.shuffle(shuffled)
        s2 = by_logon(C._LogonSessionIndex(shuffled))
        same = (sorted(p["record_id"] for p in s2[1][0]["procs"]) == [2]
                and s2[5][0]["logoff"]["record_id"] == 8 and s2[9][0]["logoff"]["record_id"] == 10)
        if not same:
            break
    check("unsorted input gives the same sessions (5 shuffles)", same)
    chains = [ch for ch in C.correlate(srt) if "LogonId-Linked" in (ch.get("rule_name") or "")]
    ids = sorted({e.get("record_id") for ch in chains for e in ch.get("events", [])})
    check("the network-logon process chain names only the process the logon ran",
          len(chains) == 1 and ids == [1, 2], f"{len(chains)} chain(s), events {ids}")
    d = chains[0].get("description", "") if chains else ""
    check("the chain names the LogonId the 4624 recorded, not an internal key",
          "under LogonId 0x55a3 " in d and "|" not in d, d)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
