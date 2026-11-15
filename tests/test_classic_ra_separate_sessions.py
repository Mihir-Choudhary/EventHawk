"""Two completed Classic Remote Assistance sessions stay two sessions.

Gemini audit 8-01 (High): a finished session (16 -> 21 -> 18) and a second,
view-only one (16 -> 18) by the same helper 30 minutes later were merged into
one row: 40 minutes long (the 30-minute gap counted as a session) with
Control "Yes" for both.

Expected: two rows, 300 s each, Control Yes and No; events logged after an
end that start nothing still join the session they follow.  Synthetic events.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.gui.main_window import _RemoteAssistanceDialog as Dialog  # noqa: E402

RA = "Microsoft-Windows-RemoteAssistance/Operational"
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, second, rid):
    ts = (datetime(2024, 1, 1, 10, tzinfo=timezone.utc) + timedelta(seconds=second)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    return {"event_id": eid, "channel": RA, "provider": "Microsoft-Windows-RemoteAssistance",
            "computer": "SYNTH-HOST", "timestamp": ts, "record_id": rid, "source_file": "synthetic.evtx",
            "event_data": {"LocalFQDNName": "SYNTH-HOST", "UserName": "SYNTH\\helper"}}


def main() -> int:
    evs = [ev(16, 0, 1), ev(21, 60, 2), ev(18, 300, 3), ev(3, 310, 4),
           ev(16, 2100, 5), ev(18, 2400, 6)]
    ra = sorted((r for r in Dialog._build_sessions(evs) if r["type"] == "Classic RA"),
                key=lambda r: str(r.get("start_ts") or r.get("start") or ""))
    check("two Classic RA sessions", len(ra) == 2, str(len(ra)))
    check("each lasts 300 s", [r.get("duration_secs") for r in ra] == [300, 300],
          str([r.get("duration_secs") for r in ra]))
    check("Control Yes for the first, No for the second", [r.get("control") for r in ra] == ["Yes", "No"],
          str([r.get("control") for r in ra]))
    check("the event after the first end stays with it", [r.get("event_count") for r in ra] == [4, 2],
          str([r.get("event_count") for r in ra]))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
