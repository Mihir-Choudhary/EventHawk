"""Copies of a log collapse; two DIFFERENT records with the same metadata do not.

Codex release audit C1: record identity is host + channel + event id + time +
record id.  Copies of one log ("Security.evtx" and "Security - Copy.evtx")
share it and must count once.  But two records with that same identity and a
different payload were collapsed too: the second record's IP disappeared from
the IOC list and the first IP was credited to the second file.  A conflict is
evidence, not a copy.  Synthetic records only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(sf, ip):
    return {"event_id": 4625, "computer": "HOST", "channel": "Security", "record_id": 42,
            "timestamp": "2024-01-01T00:00:00.000000Z", "source_file": sf, "provider": "P",
            "level": 0, "level_name": "x",
            "event_data": {"IpAddress": ip, "TargetUserName": "u", "LogonType": "3"}}


def main() -> int:
    from evtx_tool.core.record_identity import collapse_copies
    a, a_copy = ev(r"C:\c\Security.evtx", "203.0.113.5"), ev(r"C:\c\Security - Copy.evtx", "203.0.113.5")
    other = ev(r"C:\d\Security-HOSTB.evtx", "198.51.100.7")
    kept, copies = collapse_copies([a, a_copy, other])
    check("a true copy collapses into its original", a in kept and a_copy not in kept and copies.get(id(a)) == [a_copy],
          f"kept {len(kept)}")
    check("a record with the same metadata but a different payload is kept", other in kept, f"kept {len(kept)}")

    from evtx_tool.analysis.ioc_extractor import extract_iocs
    res = extract_iocs([a, a_copy, other])
    ips = {}
    for key, val in res.items():
        if isinstance(val, list) and val and isinstance(val[0], dict) and "value" in val[0] and "ip" in key.lower():
            for e in val:
                ips[e["value"]] = e
    check("both IPs are IOCs", {"203.0.113.5", "198.51.100.7"} <= set(ips), str(sorted(ips)))
    srcs = str((ips.get("203.0.113.5") or {}).get("sources", ""))
    check("the first IP is not credited to the other machine's file", "Security-HOSTB" not in srcs, srcs[:200])

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
