"""Classic Remote Assistance uses documented session/control events, not tracing IDs."""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.gui.main_window import _RemoteAssistanceDialog as Dialog  # noqa: E402

RA = "Microsoft-Windows-RemoteAssistance/Operational"


def ev(eid, second):
    timestamp = (datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"event_id": eid, "channel": RA, "provider": "Microsoft-Windows-RemoteAssistance",
            "computer": "SYNTH-HOST", "timestamp": timestamp,
            "record_id": str(eid + second), "source_file": "synthetic.evtx",
            "event_data": {"LocalFQDNName": "SYNTH-HOST", "UserName": "SYNTH"}}


def main():
    rows = Dialog._build_sessions([ev(1, 0), ev(16, 10), ev(21, 20), ev(18, 70), ev(2, 80), ev(3, 90)])
    ra = [r for r in rows if r["type"] == "Classic RA"]
    one = ra[0] if len(ra) == 1 else {}
    checks = [
        ("documented 16 -> 18 gives the 60-second session duration", one.get("duration_secs") == 60),
        ("documented 21 alone grants Control", one.get("control") == "Yes"),
        ("tracing/error IDs are retained as observations, not discarded", one.get("event_count") == 6),
    ]
    for name, value in checks:
        print(f"  {'PASS' if value else 'FAIL'}  {name}  -- {one}")
    print(f"\n{sum(bool(v) for _, v in checks)}/{len(checks)} checks passed")
    return 0 if all(v for _, v in checks) else 1


if __name__ == "__main__":
    sys.exit(main())
