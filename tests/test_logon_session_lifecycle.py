"""Logon Sessions: one logon per 4624, 4647 ends it, nothing joins after 4634, open scope stays open.

Gemini audit 8-07 (High), four defects in _LogonSessionDialog._build_sessions:
1. a 4672 logged before its 4624 in the same second opened a partial session
   and the 4624 opened a second one (one logon shown as two rows);
2. Security 4647 (user-initiated logoff) was ignored: a session ended by
   4647 alone read "no logoff in log" (Juggernaut did not even query it);
3. a 4688 logged after the session's 4634 (same LogonId, later time) was
   still counted as the session's process;
4. a session with no logoff had its filter scope cut at its last
   4624/4672/4688, so its later events (a 4698 scheduled task under the same
   LogonId) were hidden.  With no logoff the scope ends at the next logon of
   that LogonId or the host's next start, else stays open.

Expected: each of those.  Synthetic events.
"""
import os
import sys
from datetime import datetime, timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []
T0 = datetime(2026, 1, 1, 10, 0, 0)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(secs, eid, rid, ed, provider="Microsoft-Windows-Security-Auditing", channel="Security"):
    return {"event_id": eid, "computer": "WS1", "channel": channel, "provider": provider,
            "timestamp": (T0 + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "record_id": rid, "source_file": "Security.evtx", "event_data": dict(ed)}


def sessions(events):
    from evtx_tool.gui.main_window import _LogonSessionDialog
    d = _LogonSessionDialog(events=events, on_filter_fn=lambda *a: None)
    s = d._all_sessions
    d.close()
    return s


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])

    # 1. 4672 first, same second.
    s = sessions([ev(0, 4672, 1, {"SubjectLogonId": "0xa1", "PrivilegeList": "SeDebugPrivilege"}),
                  ev(0, 4624, 2, {"TargetLogonId": "0xa1", "LogonType": "2", "TargetUserName": "alice"}),
                  ev(60, 4634, 3, {"TargetLogonId": "0xa1"})])
    check("a 4672 logged before its 4624 joins it: one session", len(s) == 1, str(len(s)))
    check("... with its privilege and its logon", s and s[0]["priv_count"] == 1 and s[0]["user"] == "alice"
          and s[0]["has_dangerous"], str([(x["priv_count"], x["user"]) for x in s]))

    # 2. 4647 alone ends the session; 4647 then 4634 is one session ended by the 4634.
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xb1", "LogonType": "2", "TargetUserName": "bob"}),
                  ev(600, 4647, 2, {"TargetLogonId": "0xb1", "TargetUserName": "bob"})])
    check("a 4647 alone is the logoff", len(s) == 1 and s[0]["logoff_ts"].startswith("2026-01-01T10:10:00")
          and s[0]["duration"].startswith("10m"), str([(x["logoff_ts"], x["duration"]) for x in s]))
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xb2", "LogonType": "2", "TargetUserName": "bob"}),
                  ev(600, 4647, 2, {"TargetLogonId": "0xb2"}),
                  ev(602, 4634, 3, {"TargetLogonId": "0xb2"})])
    check("4647 then 4634: one session, ended by the 4634", len(s) == 1
          and s[0]["logoff_ts"].startswith("2026-01-01T10:10:02"), str([(x["logoff_ts"], x["duration"]) for x in s]))

    # 3. a process after the 4634.
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xc1", "LogonType": "3", "TargetUserName": "carol"}),
                  ev(5, 4688, 2, {"SubjectLogonId": "0xc1", "NewProcessName": "a.exe"}),
                  ev(60, 4634, 3, {"TargetLogonId": "0xc1"}),
                  ev(300, 4688, 4, {"SubjectLogonId": "0xc1", "NewProcessName": "b.exe"})])
    main_s = [x for x in s if x["user"] == "carol"]
    check("a 4688 after the 4634 is not the closed session's process",
          len(main_s) == 1 and main_s[0]["proc_count"] == 1, str([(x["user"], x["proc_count"]) for x in s]))
    check("... and it is still shown (its own row, no logon)", sum(x["proc_count"] for x in s) == 2,
          str([(x["user"], x["proc_count"]) for x in s]))

    # 4. open session scope.
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xd1", "LogonType": "2", "TargetUserName": "dave"}),
                  ev(5, 4688, 2, {"SubjectLogonId": "0xd1", "NewProcessName": "a.exe"})])
    check("no logoff and nothing after: the scope stays open", len(s) == 1 and not s[0]["scope_end_ts"],
          str([x["scope_end_ts"] for x in s]))
    boot = ev(900, 12, 9, {}, provider="Microsoft-Windows-Kernel-General", channel="System")
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xd2", "LogonType": "2", "TargetUserName": "dave"}),
                  ev(5, 4688, 2, {"SubjectLogonId": "0xd2", "NewProcessName": "a.exe"}), boot])
    d2 = [x for x in s if x["lid"] == "0xd2"]
    check("no logoff, then the host restarts: the scope ends at the restart",
          len(d2) == 1 and d2[0]["scope_end_ts"] == "2026-01-01 10:15:00" and not d2[0]["scope_end_inclusive"],
          str([(x["scope_end_ts"], x["scope_end_inclusive"]) for x in d2]))
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xd3", "LogonType": "2", "TargetUserName": "dave"}),
                  ev(60, 4634, 2, {"TargetLogonId": "0xd3"})])
    check("with a logoff the scope still ends at it (inclusive)",
          s and s[0]["scope_end_ts"] == "2026-01-01 10:01:00" and s[0]["scope_end_inclusive"],
          str([(x["scope_end_ts"], x["scope_end_inclusive"]) for x in s]))

    # linked split-token pair: one logged off, the other still open -> the union is open.
    s = sessions([ev(0, 4624, 1, {"TargetLogonId": "0xe1", "TargetLinkedLogonId": "0xe2", "LogonType": "2",
                                  "TargetUserName": "erin"}),
                  ev(0, 4624, 2, {"TargetLogonId": "0xe2", "TargetLinkedLogonId": "0xe1", "LogonType": "2",
                                  "TargetUserName": "erin"}),
                  ev(30, 4634, 3, {"TargetLogonId": "0xe1"})])
    lk = {x["lid"]: x.get("linked_scope_end_ts", "?") for x in s}
    check("a linked pair with one side still open has an open union scope", lk == {"0xe1": "", "0xe2": ""}, str(lk))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
