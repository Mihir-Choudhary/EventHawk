"""Terminal Services session descriptions say what the event shows.

Windows runs console sessions through Remote Desktop Services too, and the
LocalSessionManager log records them with source Address 'LOCAL'.  Every one
was described as "Remote Desktop session logon succeeded" -- an analyst who
never used RDP read remote access in the detail pane, the bookmarks and the
report.  And the fields sit under UserData/EventXML, so the user, Address and
session were never found (the description named none of them).

  * Address LOCAL       -> a console session, "not a remote connection";
  * a remote Address    -> the Remote Desktop wording, with the source;
  * no Address (logoff, disconnect by reason) -> logged for console and
    Remote Desktop sessions alike;
  * the user and session ID from EventXML are named.

Run: python tests/test_lsm_descriptions.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from evtx_tool.analysis.event_descriptions import get_event_description  # noqa: E402

CHECKS = []
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, **fields):
    return {"event_id": eid, "provider": LSM, "channel": f"{LSM}/Operational",
            "event_data": {"EventXML": {"#attributes": {"xmlns": "Event_NS"}, **fields}}}


def main() -> int:
    d = get_event_description(ev(21, User=r"PC01\analyst", SessionID=16, Address="LOCAL"))
    check("a LOCAL logon is a console session, not a remote connection",
          "console" in d and "NOT a remote connection" in d and "Remote Desktop session logon" not in d, d)
    check("...naming the user and session (read from EventXML)",
          r"User 'PC01\analyst'" in d and "Session ID: 16" in d, d)
    for eid in (22, 24, 25):
        d = get_event_description(ev(eid, User="u", SessionID=2, Address="LOCAL"))
        check(f"LOCAL {eid} is described as local", "local" in d.lower() and "Remote Desktop session" not in d, d)
    d = get_event_description(ev(21, User=r"CORP\bob", SessionID=3, Address="10.0.0.5"))
    check("a logon from a remote address keeps the Remote Desktop wording and names the source",
          "Remote Desktop session logon succeeded" in d and "Source: 10.0.0.5" in d, d)
    for eid in (23, 40):
        d = get_event_description(ev(eid, User="u", SessionID=2))
        check(f"{eid} without an address says it is logged for console and RDP alike",
              "console and Remote Desktop sessions alike" in d, d)
    d = get_event_description(ev(39, TargetSession=15, Source=15))
    check("39 (disconnected by another session) is neutral", "alike" in d, d)
    d = get_event_description(ev(23, User="u", SessionID=2, Address="10.0.0.9"))
    check("a logoff that does name a remote address keeps the RDP wording",
          "Remote Desktop session logoff" in d and "Source: 10.0.0.9" in d, d)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
