"""Inbound RDP: LogonIDs compared as numbers; Remote IP only an IP; ClientName used.

Gemini audit 8-14 (Medium), in inbound_rdp.build_inbound_sessions:
1. a 4778 with LogonID "0x4F120" and its 4779 with "0x4f120" were two
   sessions (the LogonID was compared as text);
2. a remote that is a host name ("jumpbox.corp.example") was also put in
   the Remote IP column;
3. a 4778/4779 with ClientName and no address showed no remote host.

Expected: one Completed session of 5 m with Remote host the name and Remote
IP empty; the ClientName as the remote host; an IP still shown in both
columns as before.  Synthetic events.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
BASE = datetime(2026, 1, 1, 10, tzinfo=timezone.utc)
SA = "Microsoft-Windows-Security-Auditing"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(host, rid, secs, eid, data):
    return {"event_id": eid, "channel": "Security", "provider": SA, "computer": host,
            "timestamp": (BASE + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "record_id": rid, "source_file": "s.evtx", "event_data": dict(data)}


def main() -> int:
    from evtx_tool.analysis.inbound_rdp import build_inbound_sessions
    fields = lambda e: e.get("event_data") or {}                    # noqa: E731
    u = {"AccountName": "u", "AccountDomain": "D"}
    rows = build_inbound_sessions([ev("H1", 1, 0, 4778, dict(u, LogonID="0x4F120", ClientAddress="jumpbox.corp.example")),
                                   ev("H1", 2, 300, 4779, dict(u, LogonID="0x4f120", ClientAddress="jumpbox.corp.example"))],
                                  fields)
    check("one session across LogonID letter case", len(rows) == 1 and rows[0]["status"] == "Completed"
          and rows[0]["duration_secs"] == 300, str([(r["status"], r["duration_secs"]) for r in rows]))
    check("a host-name remote is the remote host, not the remote IP",
          rows and rows[0]["remote_host"] == "jumpbox.corp.example" and rows[0]["remote_ip"] == "",
          str([(r["remote_host"], r["remote_ip"]) for r in rows]))
    rows = build_inbound_sessions([ev("H2", 1, 0, 4778, dict(u, LogonID="0x9", ClientName="SYNTH-LAPTOP-09")),
                                   ev("H2", 2, 60, 4779, dict(u, LogonID="0x9", ClientName="SYNTH-LAPTOP-09"))], fields)
    check("ClientName is the remote host when no address is logged",
          rows and rows[0]["remote_host"] == "SYNTH-LAPTOP-09", str([(r["remote_host"], r["remote_ip"]) for r in rows]))
    rows = build_inbound_sessions([ev("H3", 1, 0, 4778, dict(u, LogonID="0x7", ClientAddress="192.0.2.5")),
                                   ev("H3", 2, 60, 4779, dict(u, LogonID="0x7", ClientAddress="192.0.2.5"))], fields)
    check("an IP address is still shown as both", rows and rows[0]["remote_ip"] == "192.0.2.5"
          and rows[0]["remote_host"] == "192.0.2.5", str([(r["remote_host"], r["remote_ip"]) for r in rows]))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
