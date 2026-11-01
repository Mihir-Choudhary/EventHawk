"""Logon duration arithmetic retains the EVTX timestamp precision."""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.gui.main_window import _LogonSessionDialog as Dialog  # noqa: E402


def ev(eid, timestamp, data):
    return {"event_id": eid, "channel": "Security", "computer": "SYNTH-HOST",
            "timestamp": timestamp, "record_id": str(eid), "source_file": "synthetic.evtx",
            "event_data": data}


def main():
    rows = Dialog._build_sessions(Dialog.__new__(Dialog), [
        ev(4624, "2024-01-01T00:00:00.250000Z", {"TargetLogonId": "0xA", "TargetUserName": "SYNTH", "LogonType": "2"}),
        ev(4634, "2024-01-01T00:00:01.750000Z", {"TargetLogonId": "0xA"}),
    ])
    duration = rows[0]["duration"]
    ok = duration == "1.5s"
    print(f"  {'PASS' if ok else 'FAIL'}  1.5-second evidence is not truncated to whole seconds  -- {duration}")
    print(f"\n{int(ok)}/1 checks passed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
