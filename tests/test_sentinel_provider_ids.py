"""Sentinel reads an event ID only from the provider that defines it (Codex FO-11).

Sentinel dispatched on the event ID alone, so every Event ID 1 -- from any
provider -- was taken as a Sysmon process creation: on six real logs 2,511
events were scored where Windows XML proves 119 process creations (117
Security 4688, 2 Sysmon 1).  Expected: 4688/4689 only from
Microsoft-Windows-Security-Auditing, 1/5/8/10 only from Microsoft-Windows-Sysmon.
Synthetic records in pyevtx-rs JSON shape.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rec(eid, provider):
    return {"Event": {"System": {"EventID": eid, "Computer": "PC",
                                 "Provider": {"#attributes": {"Name": provider}},
                                 "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:05.000000Z"}}},
                      "EventData": {"Image": "C:\\x.exe", "NewProcessName": "C:\\x.exe",
                                    "ParentImage": "C:\\p.exe", "CommandLine": "x"}}}


def main() -> int:
    from sentinel.analysis.parser import _parse_record
    cases = [
        (1, "Microsoft-Windows-Sysmon", True),
        (1, "Microsoft-Windows-Kernel-General", False),
        (1, "Microsoft-Windows-FilterManager", False),
        (10, "Microsoft-Windows-Sysmon", True),
        (10, "Microsoft-Windows-Kernel-Power", False),
        (4688, "Microsoft-Windows-Security-Auditing", True),
        (4688, "SomeOtherProvider", False),
    ]
    for eid, prov, want in cases:
        got = _parse_record(rec(eid, prov), "") is not None
        check(f"Event ID {eid} from {prov}: {'read' if want else 'not read'}", got == want)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
