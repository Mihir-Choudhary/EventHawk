"""Outbound RDP duration requires RDPClient connected (1025) then disconnect (1026)."""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.gui.main_window import _RemoteAssistanceDialog as Dialog  # noqa: E402

CH = "Microsoft-Windows-TerminalServices-RDPClient/Operational"


def ev(eid, second):
    timestamp = (datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"event_id": eid, "channel": CH, "computer": "SYNTH-HOST",
            "timestamp": timestamp,
            "record_id": str(eid + second), "source_file": "synthetic.evtx",
            "event_data": {"Value": "SYNTH-DEST"}}


def row(events):
    rows = [r for r in Dialog._build_sessions(events) if r["type"] == "RDP (Outbound)"]
    return rows[0] if len(rows) == 1 else {}


def main():
    connected = row([ev(1024, 0), ev(1025, 20), ev(1026, 60)])
    attempted = row([ev(1024, 0), ev(1026, 60)])
    transport = row([ev(1102, 0), ev(1105, 60)])
    checks = [
        ("duration starts at connected (1025), not attempt (1024)", connected.get("duration_secs") == 40),
        ("attempt (1024) plus disconnect (1026) stays Unavailable", attempted.get("duration") == "Unavailable"),
        ("multi-transport activity (1102/1105) stays Unavailable", transport.get("duration") == "Unavailable"),
    ]
    for name, value in checks:
        print(f"  {'PASS' if value else 'FAIL'}  {name}")
    print(f"\n{sum(bool(v) for _, v in checks)}/{len(checks)} checks passed")
    return 0 if all(v for _, v in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
