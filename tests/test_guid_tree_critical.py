"""Office -> shell is critical anywhere in a Sysmon process tree, logged parent or not.

Gemini audit 7-03 (High): the "Office/browser spawns a shell" check looked
only at the tree's root; WINWORD.EXE -> powershell.exe under explorer.exe
was critical alone but became only "high" as soon as explorer.exe also
started a LOLBAS (certutil.exe), and the WINWORD subtree was then marked
done.
Gemini audit 7-10 (High): a parent started before the log begins has no
Sysmon EID 1 of its own, and only parents with one were visited, so
WINWORD.EXE (running since before the log) -> powershell.exe made no chain,
although the child event names its parent image.

Expected: both cases give a critical "Sysmon ProcessGuid -- Suspicious Spawn
Chain".  Synthetic Sysmon EID 1 events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def s1(rid, sec, guid, img, pguid, pimg):
    return {"record_id": rid, "event_id": 1, "timestamp": f"2026-01-01T10:00:{sec:02d}.000000Z", "computer": "H",
            "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
            "source_file": "s.evtx",
            "event_data": {"ProcessGuid": guid, "Image": img, "ParentProcessGuid": pguid, "ParentImage": pimg,
                           "CommandLine": img}}


def sev(chains):
    return [c["severity"] for c in chains if c["rule_name"].startswith("Sysmon ProcessGuid")]


def main() -> int:
    from evtx_tool.analysis.correlator import correlate
    EXP, WW = r"C:\Windows\explorer.exe", r"C:\Program Files\Office\WINWORD.EXE"
    PS, CU = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", r"C:\Windows\System32\certutil.exe"
    tree = [s1(1, 0, "{E}", EXP, "{W0}", r"C:\Windows\System32\userinit.exe"),
            s1(2, 1, "{W}", WW, "{E}", EXP),
            s1(3, 2, "{P}", PS, "{W}", WW),
            s1(4, 3, "{C}", CU, "{E}", EXP)]
    got = sev(correlate(tree))
    check("WINWORD -> powershell under an explorer that also ran certutil is critical", "critical" in got, str(got))
    orphan = [s1(5, 4, "{P2}", PS, "{W-OLD}", WW)]     # WINWORD started before the log
    got = sev(correlate(orphan))
    check("WINWORD (no EID 1 of its own) -> powershell is critical", "critical" in got, str(got))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
