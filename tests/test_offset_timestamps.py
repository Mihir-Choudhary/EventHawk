"""Timestamps with a UTC offset are converted, not cut.

Gemini audit 8-12 (Medium): host_identity.iso_z dropped any offset other
than Z / +00:00 without converting ("15:30+05:30" stayed 15:30), and the
Remote Assistance builder's parser failed on "+00:00" with no fraction (a
duration of "?") and read "+05:30" as UTC.

Expected: offsets converted to UTC; a session 10:00Z -> 10:05Z lasts 300 s
whichever way its ends are written.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
RA = "Microsoft-Windows-RemoteAssistance/Operational"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ra(eid, ts, rid):
    return {"event_id": eid, "channel": RA, "provider": "Microsoft-Windows-RemoteAssistance",
            "computer": "SYNTH-HOST", "timestamp": ts, "record_id": rid, "source_file": "s.evtx",
            "event_data": {"LocalFQDNName": "SYNTH-HOST", "UserName": "SYNTH\\helper"}}


def main() -> int:
    from evtx_tool.core.host_identity import iso_z
    got = iso_z("2026-01-01T15:30:00+05:30")
    check("iso_z converts +05:30 to UTC", got == "2026-01-01T10:00:00.000000Z", got)
    got = iso_z("2026-01-01T10:00:00.5-02:00")
    check("iso_z converts -02:00, keeping the fraction", got == "2026-01-01T12:00:00.500000Z", got)
    check("iso_z keeps the usual shapes", iso_z("2026-01-01T10:00:00.123456Z") == "2026-01-01T10:00:00.123456Z"
          and iso_z("2026-01-01 10:00:00.123456") == "2026-01-01T10:00:00.123456Z")

    from evtx_tool.gui.main_window import _RemoteAssistanceDialog as D
    for name, a, b in (("+00:00 with no fraction", "2026-01-01T10:00:00+00:00", "2026-01-01T10:05:00+00:00"),
                       ("+05:30 start, Z end", "2026-01-01T15:30:00+05:30", "2026-01-01T10:05:00Z")):
        rows = [r for r in D._build_sessions([ra(16, a, 1), ra(18, b, 2)]) if r["type"] == "Classic RA"]
        secs = [r.get("duration_secs") for r in rows]
        check(f"RA session written {name} lasts 300 s", secs == [300], str((secs, [r.get("duration") for r in rows])))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
