"""IOC extraction: counted once per event; IPv6 read whole; command lines scored whole.

Gemini audit 7-07 (High):
1. one 4624 counted its IpAddress twice (structured field + full-text pass);
2. the IPv6 regex cut "fe80::1" to "fe80::", missed "::1" and
   "::ffff:192.0.2.10", and link-local / unique-local addresses scored as
   "Public IP address";
3. command lines were cut to 500 characters, so an -EncodedCommand after the
   cut was never scored.

Expected: count 1 for one event; the three IPv6 values whole; fe80::1 and
fd00::1 not "Public"; a long command line kept whole and scored >= 50.
Synthetic events.  (Part 4, IPs/domains inside PowerShell script text, is
not extracted on purpose: script text is code, not observed activity.)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, eid, data):
    return {"record_id": rid, "event_id": eid, "timestamp": "2026-01-01T00:00:00.000000Z", "computer": "H",
            "channel": "Security", "provider": "P", "source_file": "s.evtx", "event_data": data}


def main() -> int:
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    from evtx_tool.analysis.ioc_scorer import score_ioc
    i = extract_iocs([ev(1, 4624, {"IpAddress": "192.0.2.44", "TargetUserName": "u", "LogonType": "3"})])
    cnt = [e.get("count") for e in i.get("ipv4") or [] if e.get("value") == "192.0.2.44"]
    check("one 4624 counts its IP once", cnt == [1], str(cnt))
    evs = [ev(k + 2, 3, {"DestinationIp": ip}) for k, ip in enumerate(("fe80::1", "::1", "::ffff:192.0.2.10"))]
    v6 = sorted(e.get("value") for e in extract_iocs(evs).get("ipv6") or [])
    check("IPv6 values are read whole", v6 == sorted(["fe80::1", "::1", "::ffff:192.0.2.10"]), str(v6))
    for ip in ("fe80::1", "fd00::1"):
        r = score_ioc("ipv6", ip)
        reasons = r[1] if isinstance(r, tuple) else (r.get("reasons") or r.get("score_reasons") or [])
        check(f"{ip} is not scored as a public address", "Public IP address" not in reasons, str(r))
    cmd = "powershell.exe " + "A" * 600 + " -EncodedCommand dGVzdA=="
    i = extract_iocs([ev(9, 4688, {"CommandLine": cmd, "NewProcessName": r"C:\x\powershell.exe"})])
    vals = [e.get("value") for e in i.get("commandlines") or []]
    check("a long command line is kept whole", cmd in vals, str([len(v) for v in vals]))
    r = score_ioc("commandlines", cmd)
    sc = r[0] if isinstance(r, tuple) else r.get("score", 0)
    check("...and scored on all of it (>= 50)", sc >= 50, str(sc))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
