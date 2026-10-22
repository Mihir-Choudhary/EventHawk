"""Copies of a log must not fabricate detections or inflate IOC counts.

A collection folder often holds "Security.evtx" next to "Security - Copy.evtx"
(the reference corpus has four).  Every correlation rule and every IOC
occurrence count counted each copy again.  Measured with the log loaded four
times: TWO failed logons and a success became "Brute Force -> Successful
Logon", five failed users became "Password Spray Attack" -- neither fires on
the single log -- and real IOC counts were multiplied by four (gmail.com 165
-> 660), reordering the count-sorted lists.

Both analysers now count each physical record once (core.record_identity:
host + channel + event id + exact timestamp + record id); the IOC sources
still name every file a record was found in.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
SRCS = ["Security.evtx", "Security - Copy.evtx", "Security - Copy (2).evtx",
        "Security - Copy - Copy.evtx"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def sev(rid, eid, ts, src, **ed):
    return {"record_id": rid, "event_id": eid, "timestamp": ts, "computer": "WS01",
            "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "source_file": src, "event_data": ed}


def brute(src, n):
    out = [sev(i, 4625, f"2025-06-10T09:00:{i:02d}.000000Z", src, IpAddress="203.0.113.7",
               TargetUserName="admin", LogonType="3") for i in range(1, n + 1)]
    out.append(sev(99, 4624, "2025-06-10T09:00:30.000000Z", src, IpAddress="203.0.113.7",
                   TargetUserName="admin", LogonType="3", TargetLogonId="0x1a2b"))
    return out


def spray(src, n):
    return [sev(i, 4625, f"2025-06-10T11:00:{i:02d}.000000Z", src, IpAddress="198.51.100.9",
                TargetUserName=f"user{i}", LogonType="3") for i in range(1, n + 1)]


def copies(gen, n):
    return sorted((e for s in SRCS for e in gen(s, n)), key=lambda e: e["timestamp"])


def rules(chains):
    return sorted((c["rule_name"], c["event_count"]) for c in chains)


def main() -> int:
    from evtx_tool.analysis.correlator import correlate
    from evtx_tool.analysis.ioc_extractor import extract_iocs

    print("=== correlation: copies change nothing ===")
    for label, gen, n in (("2 failed logons + success", brute, 2),
                          ("4 failed logons + success", brute, 4),
                          ("15 failed logons + success", brute, 15),
                          ("5-user spray", spray, 5),
                          ("20-user spray", spray, 20)):
        one, four = rules(correlate(gen(SRCS[0], n))), rules(correlate(copies(gen, n)))
        check(f"{label}: four copies give the one-log result", one == four,
              f"one {one}, four {four}")
    check("a real attack is still detected (15 failures + success)",
          any(r == "Brute Force -> Successful Logon" for r, _ in rules(correlate(brute(SRCS[0], 15)))))

    print("\n=== IOCs: each record counted once, every file named ===")
    one, four = extract_iocs(brute(SRCS[0], 15)), extract_iocs(copies(brute, 15))
    ip1 = {x["value"]: x for x in one["ipv4"]}.get("203.0.113.7", {})
    ip4 = {x["value"]: x for x in four["ipv4"]}.get("203.0.113.7", {})
    check("the IP's occurrence count is the same with copies",
          ip1.get("count") is not None and ip1.get("count") == ip4.get("count"),
          f"one {ip1.get('count')}, four {ip4.get('count')}")
    check("its sources name all four files", sorted(ip4.get("sources") or []) == sorted(SRCS),
          str(ip4.get("sources")))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
