"""Four correlator rule-logic fixes.

Gemini audit 7-13 (Medium):
1. Pass-the-Hash fired on a 4624 whose KeyLength was blank, claiming
   "KeyLength=0";
2. "HOST-01", "host-01" and "HOST-01.corp.example" were three computers for
   Multi-Host Lateral Movement;
3. pwsh.exe (PowerShell 7) was not a PowerShell spawn for "Suspicious
   Process Spawn -> PowerShell Execution";
4. any provider's Event ID 4104 counted as a PowerShell script block there.

Expected: 1 -> no PtH; 2 -> no lateral movement; 3 -> a chain; 4 -> none.
Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, eid, sec, comp, data, prov="Microsoft-Windows-Security-Auditing"):
    return {"record_id": rid, "event_id": eid, "timestamp": f"2026-01-01T10:00:{sec:02d}.000000Z",
            "computer": comp, "channel": "Security", "provider": prov, "source_file": "s.evtx", "event_data": data}


def names(evs):
    from evtx_tool.analysis.correlator import correlate
    return [c["rule_name"] for c in correlate(evs)]


def main() -> int:
    pth = [ev(1, 4624, 0, "H", {"TargetUserName": "alice", "LogonType": "3", "LogonProcessName": "NtLmSsp ",
                                "AuthenticationPackageName": "NTLM", "KeyLength": "", "IpAddress": "192.0.2.4"})]
    got = names(pth)
    check("a blank KeyLength is not Pass-the-Hash", not any("Pass-the-Hash" in n for n in got), str(got))
    lat = [ev(i + 1, 4624, i, h, {"TargetUserName": "alice", "LogonType": "3", "IpAddress": "192.0.2.4"})
           for i, h in enumerate(("HOST-01", "host-01", "HOST-01.corp.example"))]
    got = names(lat)
    check("one host written three ways is not lateral movement", "Multi-Host Lateral Movement" not in got, str(got))
    spawn = ev(1, 4688, 0, "H", {"NewProcessName": r"C:\Tools\pwsh\pwsh.exe",
                                 "ParentProcessName": r"C:\Office\WINWORD.EXE", "SubjectUserName": "alice"})
    blk = ev(2, 4104, 5, "H", {"ScriptBlockText": "Get-Process"}, prov="Microsoft-Windows-PowerShell")
    got = names([spawn, blk])
    check("pwsh.exe spawned by Word, then a script block, is a chain",
          "Suspicious Process Spawn -> PowerShell Execution" in got, str(got))
    ps = ev(1, 4688, 0, "H", {"NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                              "ParentProcessName": r"C:\Office\WINWORD.EXE", "SubjectUserName": "alice"})
    app = ev(2, 4104, 5, "H", {"Data": "x"}, prov="CustomApp")
    got = names([ps, app])
    check("another provider's 4104 is not a script block",
          "Suspicious Process Spawn -> PowerShell Execution" not in got, str(got))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
