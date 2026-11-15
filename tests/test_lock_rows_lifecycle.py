"""System Activity lock rows: never across a restart, closed by an unlock logon, the locking user.

Gemini audit 8-04 (High), in system_activity._lock_rows:
1. a 4800 lock before a shutdown and a 4801 unlock after the restart were
   paired: 15 hours "Locked" while the host was off;
2. an unlock logon (Security 4624, LogonType 7) did not end the lock when
   no 4801 was logged (the lock read "no 4801 logged");
3. the row's user came from the closing event, not the locking one.

Expected: the lock across the restart has no end/duration and says the
host restarted; the 4624 type 7 ends the lock (300 s), with 4801 preferred
when both are logged; the user is the locking user.  Synthetic events.
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import kernel_boot                      # noqa: E402

CHECKS = []
H = "WS-LOCK"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def sec(rid, secs, eid, data):
    return T.ev("s.evtx", rid, H, T.T0 + timedelta(seconds=secs), eid, data=data)


def shutdown(rid, secs):
    e = T.ev("y.evtx", rid, H, T.T0 + timedelta(seconds=secs), 13, "Microsoft-Windows-Kernel-General",
             {"StopTime": T.iso(T.T0 + timedelta(seconds=secs))})
    e["channel"] = "System"
    return e


def locks(evs):
    from evtx_tool.analysis import system_activity as sa
    return [r for r in sa.build([e for e in evs if sa.relevant(e)])["rows"] if r["layer"] == "Lock"]


def main() -> int:
    u = {"TargetUserName": "alice", "TargetLogonId": "0x51", "SessionId": "1"}
    rows = locks([sec(1, 0, 4800, u), shutdown(2, 600), kernel_boot(H, 3, 54000, start=53990),
                  sec(4, 54060, 4801, dict(u, TargetUserName="bob"))])
    check("a lock never spans a restart (no end, no duration)", len(rows) >= 1 and rows[0]["end"] is None
          and rows[0]["duration"] is None, str([(r["end"], r["duration"]) for r in rows]))
    check("... and says the host restarted", rows and "restart" in rows[0]["notes"].lower(),
          rows[0]["notes"] if rows else "")

    # 8-03: the restart logged under the host's FQDN still bounds the lock.
    sd, bt = shutdown(2, 600), kernel_boot(H + ".corp.example", 3, 54000, start=53990)
    sd["computer"] = H + ".corp.example"
    rows = [r for r in locks([sec(1, 0, 4800, u), sd, bt, sec(4, 54060, 4801, u)]) if r["host"] == H]
    check("a restart logged under the FQDN also stops the lock", len(rows) == 1 and rows[0]["end"] is None,
          str([(r["end"], r["duration"]) for r in rows]))

    rows = locks([sec(1, 0, 4800, u),
                  sec(2, 300, 4624, {"TargetUserName": "alice", "TargetLogonId": "0x99", "LogonType": "7"})])
    check("an unlock logon (4624 type 7) ends the lock: 300 s", len(rows) == 1 and rows[0]["duration"]
          and rows[0]["duration"].total_seconds() == 300, str([(r["duration"], r["ended_by"]) for r in rows]))
    check("... named as the end", rows and "4624" in rows[0]["ended_by"], rows[0]["ended_by"] if rows else "")
    rows = locks([sec(1, 0, 4800, u),
                  sec(2, 300, 4624, {"TargetUserName": "carol", "TargetLogonId": "0x99", "LogonType": "7"})])
    check("another user's unlock logon does not end it", len(rows) == 1 and rows[0]["end"] is None,
          str([(r["end"], r["ended_by"]) for r in rows]))
    rows = locks([sec(1, 0, 4800, u),
                  sec(2, 300, 4624, {"TargetUserName": "alice", "TargetLogonId": "0x99", "LogonType": "7"}),
                  sec(3, 301, 4801, u)])
    check("with both logged, the 4801 ends it", len(rows) == 1 and rows[0]["ended_by"] == "Security 4801"
          and rows[0]["duration"].total_seconds() == 301, str([(r["duration"], r["ended_by"]) for r in rows]))

    rows = locks([sec(1, 0, 4800, u), sec(2, 60, 4801, dict(u, TargetUserName="bob"))])
    check("the user is the locking user", len(rows) == 1 and "user alice" in rows[0]["notes"]
          and "bob" not in rows[0]["notes"], rows[0]["notes"] if rows else "")
    rows = locks([sec(1, 0, 4800, u), sec(2, 60, 4800, dict(u, TargetUserName="bob"))])
    first = [r for r in rows if r["end"] is None and "next 4800" in r["notes"]]
    check("a lock left open by the next 4800 names its own user", first and "user alice" in first[0]["notes"],
          str([r["notes"] for r in rows]))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
