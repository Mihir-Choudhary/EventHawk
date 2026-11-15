"""Password spray and Kerberoasting rules: right on real attack shapes, quiet on noise.

Gemini audit 7-11 (High):
1. 25 network 4625s from ONE IP to 25 accounts (subject "-") made no spray chain;
2. 20 typos by 20 users from 20 different IPs made a "Password Spray" chain;
3. failed 4769s (Status 0x7) made a Kerberoasting chain -- no ticket was issued;
4. successful RC4 4769s written "0x00000017" were not recognised as RC4.

Expected: 1 -> a spray chain; 2 -> none; 3 -> no Kerberoasting chain;
4 -> a Kerberoasting chain.  Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, eid, sec, data, comp="DC-01"):
    return {"record_id": rid, "event_id": eid, "timestamp": f"2026-01-01T10:00:{sec:02d}.000000Z",
            "computer": comp, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing",
            "source_file": "s.evtx", "event_data": data}


def names(chains):
    return [c["rule_name"] for c in chains]


def main() -> int:
    from evtx_tool.analysis.correlator import correlate
    spray = [ev(i + 1, 4625, i, {"SubjectUserName": "-", "TargetUserName": f"employee{i:02d}", "LogonType": "3",
                                 "IpAddress": "198.51.100.77", "Status": "0xc000006d"}) for i in range(25)]
    got = names(correlate(spray))
    check("25 accounts from one IP is a password spray", any("Spray" in n for n in got), str(got))
    typos = [ev(i + 1, 4625, i, {"SubjectUserName": "", "TargetUserName": f"staff{i:02d}", "LogonType": "3",
                                 "IpAddress": f"192.0.2.{10 + i}", "Status": "0xc000006a"}) for i in range(20)]
    got = names(correlate(typos))
    check("20 users' typos from 20 IPs are not a spray", not any("Spray" in n for n in got), str(got))
    def tgs(i, status, enc):
        return ev(i + 1, 4769, i, {"TargetUserName": "alice", "ServiceName": f"svc{i}", "Status": status,
                                   "TicketEncryptionType": enc, "IpAddress": "198.51.100.5"})
    got = names(correlate([tgs(i, "0x7", "0x17") for i in range(3)]))
    check("failed TGS requests are not Kerberoasting", not any("Kerberoast" in n for n in got), str(got))
    got = names(correlate([tgs(i, "0x0", "0x00000017") for i in range(3)]))
    check("RC4 written 0x00000017 is Kerberoasting", any("Kerberoast" in n for n in got), str(got))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
