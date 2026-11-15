"""ATT&CK tags and descriptions follow the provider that defines the Event ID.

Gemini audit 7-05 (High): Event IDs above 25 were mapped by number alone, so a
1102 from the RDP client log was tagged "Clear Windows Event Logs" and a 7045
from an application "Windows Service"; the Sigma Sysmon rules required
"sysmon" in the CHANNEL, so Sysmon forwarded into ForwardedEvents (WEF)
matched nothing; and EID 53504 was described as a script-block event.

Expected: 1102 from Microsoft-Windows-Eventlog and 7045 from Service Control
Manager keep their tags; the same IDs from other providers get none; a
forwarded Sysmon EID 1 gets the same Sigma technique as native Sysmon; 53504
is not described as script-block logging.  Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.attack_mapping import get_attack_tags
    from evtx_tool.analysis.sigma_rules import get_sigma_tags
    from evtx_tool.analysis.event_descriptions import get_event_description
    tid = lambda eid, prov: [t["tid"] for t in get_attack_tags(eid, prov)]
    check("1102 from Eventlog is log clearing", tid(1102, "Microsoft-Windows-Eventlog") == ["T1070.001"])
    check("1102 from the RDP client is not", tid(1102, "Microsoft-Windows-TerminalServices-ClientActiveXCore") == [])
    check("7045 from Service Control Manager is a new service", tid(7045, "Service Control Manager") == ["T1543.003"])
    check("7045 from another provider is not", tid(7045, "SomeApp") == [])
    check("4624 from Security-Auditing keeps its tag", tid(4624, "Microsoft-Windows-Security-Auditing") == ["T1078"])
    ed = {"Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
          "CommandLine": "powershell.exe -Enc ZABlAGMAbwB5AA==", "ParentImage": r"C:\Windows\explorer.exe"}
    base = {"event_id": 1, "provider": "Microsoft-Windows-Sysmon", "event_data": ed, "computer": "H"}
    native = sorted({t["tid"] for t in (get_sigma_tags(dict(base, channel="Microsoft-Windows-Sysmon/Operational")) or [])})
    wef = sorted({t["tid"] for t in (get_sigma_tags(dict(base, channel="ForwardedEvents")) or [])})
    check("forwarded Sysmon gets the same Sigma techniques as native", native and native == wef, f"{native} vs {wef}")
    d = get_event_description({"event_id": 53504, "provider": "Microsoft-Windows-PowerShell",
                               "channel": "Microsoft-Windows-PowerShell/Operational", "event_data": {}}) or ""
    check("53504 is not described as script-block logging", "script block" not in d.lower(), d[:100])
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
