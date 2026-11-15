"""Sentinel: a thread-injection or process-access event never rewrites a process's parent.

Gemini audit 10-02 (Critical): LineageTracker.process_event registered every
event that was not a process exit as a process creation.  Sysmon 8
(CreateRemoteThread) and 10 (ProcessAccess) carry the TARGET image in
parent_name, so injector.exe -> lsass.exe replaced injector.exe's real parent
(explorer.exe) with lsass.exe, and a child of injector.exe got the ancestry
cmd.exe <- injector.exe <- lsass.exe.  Sysmon 10 also read SourceProcessGuid,
but ProcessAccess names the field SourceProcessGUID, so its GUID was empty.

Expected: ancestry stays cmd.exe <- injector.exe <- explorer.exe after a
Sysmon 8, a Sysmon 10 and a 4624 for the same process; Sysmon 10's source GUID
is read under either spelling.  Synthetic records only.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from sentinel.analysis import parser as P
    from sentinel.analysis.lineage import LineageTracker
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    host = "HOST-A"
    EXP = r"C:\Windows\explorer.exe"
    INJ = r"C:\Users\Public\injector.exe"
    LSA = r"C:\Windows\System32\lsass.exe"
    CMD = r"C:\Windows\System32\cmd.exe"

    def s1(i, guid, pid, img, pguid, ppid, pimg):
        return P._from_sysmon1(t0 + timedelta(seconds=i), host, 1, {
            "ProcessGuid": guid, "ProcessId": str(pid), "Image": img, "ParentProcessGuid": pguid,
            "ParentProcessId": str(ppid), "ParentImage": pimg, "CommandLine": img, "User": "u",
            "IntegrityLevel": "Medium", "Hashes": ""})

    evs = [
        s1(0, "{G-EXP}", 100, EXP, "{G-WIN}", 4, r"C:\Windows\System32\winlogon.exe"),
        s1(1, "{G-INJ}", 200, INJ, "{G-EXP}", 100, EXP),
        P._from_sysmon8(t0 + timedelta(seconds=2), host, 8, {
            "SourceProcessGuid": "{G-INJ}", "SourceProcessId": "200", "SourceImage": INJ,
            "TargetImage": LSA, "StartFunction": "f", "User": "u"}),
        P._from_sysmon10(t0 + timedelta(seconds=3), host, 10, {
            "SourceProcessGUID": "{G-INJ}", "SourceProcessId": "200", "SourceImage": INJ,
            "TargetImage": LSA, "CallTrace": "x", "User": "u"}),
        s1(4, "{G-CMD}", 300, CMD, "{G-INJ}", 200, INJ),
    ]
    check("Sysmon 10's SourceProcessGUID (ProcessAccess spelling) is read", evs[3].process_guid == "{G-INJ}",
          repr(evs[3].process_guid))
    alt = P._from_sysmon10(t0, host, 10, {"SourceProcessGuid": "{G-X}", "SourceProcessId": "1", "SourceImage": INJ,
                                          "TargetImage": LSA})
    check("...and the SourceProcessGuid spelling still works", alt.process_guid == "{G-X}", repr(alt.process_guid))

    tr = LineageTracker()
    for e in evs:
        tr.process_event(e)
    inj_entry = tr._by_guid.get("{G-INJ}")
    check("injector.exe's parent stays explorer.exe after Sysmon 8 and 10",
          inj_entry is not None and inj_entry.parent_name.lower() == "explorer.exe",
          inj_entry and inj_entry.parent_name)
    cmd = evs[-1]
    ch = tr.get_ancestry_chain(cmd, "cmd.exe", "injector.exe")
    check("cmd.exe's ancestry is cmd.exe <- injector.exe <- explorer.exe",
          [c.lower() for c in ch[:3]] == ["cmd.exe", "injector.exe", "explorer.exe"], str(ch))

    # A logon event for the same PID does not register a process either
    tr2 = LineageTracker()
    tr2.process_event(evs[0]); tr2.process_event(evs[1])
    from sentinel.models import RawEvent
    logon = RawEvent(timestamp=t0 + timedelta(seconds=5), host=host, event_id=4624, process_guid="", pid=200, ppid=0,
                     parent_guid="", process_name="lsass.exe", process_path=LSA, parent_name="", parent_path="",
                     cmdline="", user="u", integrity_level="", image_hash="")
    tr2.process_event(logon)
    e2 = tr2._by_pid.get(200)
    check("a 4624 for PID 200 does not replace injector.exe in the PID map",
          e2 is not None and e2.name.lower() == "injector.exe", e2 and e2.name)

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
