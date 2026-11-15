"""IOC co-occurrence links values seen in the same events, not a made-up user x host grid.

Gemini audit 7-16 (Medium), part 2: correlate_iocs paired every user of an
IOC with every computer of it, so 192.0.2.50 seen as (alice, HOST-01) and
(bob, HOST-02) "had" (alice, HOST-02) and was linked to 198.51.100.88, which
was seen only as (alice, HOST-02) -- the two IPs never shared an event.

Expected: those two IPs are not paired; two IPs in the same event are.
Synthetic events through the real extractor.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, sec, comp, user, data):
    return {"record_id": rid, "event_id": 4624, "timestamp": f"2026-01-01T{sec:02d}:00:00.000000Z",
            "computer": comp, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "source_file": "s.evtx", "event_data": dict(data, TargetUserName=user, LogonType="3")}


def pairs(iocs):
    from evtx_tool.analysis.ioc_correlation import correlate_iocs
    return {frozenset((p["value_a"], p["value_b"])) for p in correlate_iocs(iocs)["pairs"]}


def main() -> int:
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    evs = [ev(1, 8, "HOST-01", "alice", {"IpAddress": "192.0.2.50"}),
           ev(2, 9, "HOST-02", "bob", {"IpAddress": "192.0.2.50"}),
           ev(3, 10, "HOST-02", "alice", {"IpAddress": "198.51.100.88"})]
    got = pairs(extract_iocs(evs))
    check("two IPs that never shared an event are not paired",
          frozenset(("192.0.2.50", "198.51.100.88")) not in got, str(got))
    evs2 = [ev(5, 8, "HOST-01", "alice", {"IpAddress": "192.0.2.60", "WorkstationName": "198.51.100.61"})]
    got = pairs(extract_iocs(evs2))
    check("two IPs in the same event are paired", frozenset(("192.0.2.60", "198.51.100.61")) in got, str(got))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
