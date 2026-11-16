"""Sentinel collapses only true copies of a record.

Gemini audit 10-05 (High): sentinel.analysis.parser._collapse_copies
dropped any event sharing host, event ID, time and record ID with an
earlier one, without looking at its content, so two different 4688s in two
logs of one host (a cleared log restarts its record IDs) became one and a
"powershell.exe -nop -w hidden" execution vanished.

Expected: different content is kept (2 events); a true copy still collapses
(1).  Synthetic events.
"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ev(name, cmd, pid):
    from sentinel.models import RawEvent
    return RawEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), host="H1", event_id=4688,
                    process_guid="", pid=pid, ppid=4, parent_guid="", process_name=name,
                    process_path="C:\\Windows\\System32\\" + name, parent_name="explorer.exe",
                    parent_path="", cmdline=cmd, user="u", integrity_level="", image_hash="", record_id=42)


def main() -> int:
    from sentinel.analysis.parser import _collapse_copies
    a = ev("conhost.exe", "conhost.exe 0x4", 100)
    b = ev("powershell.exe", "powershell.exe -nop -w hidden -c Get-Date", 200)
    got = _collapse_copies([a, b])
    ok1 = len(got) == 2
    print(f"  {'PASS' if ok1 else 'FAIL'}  two different events with one identity are both kept  -- {len(got)}")
    got = _collapse_copies([a, ev("conhost.exe", "conhost.exe 0x4", 100)])
    ok2 = len(got) == 1
    print(f"  {'PASS' if ok2 else 'FAIL'}  a true copy still collapses  -- {len(got)}")
    n = ok1 + ok2
    print(f"{n}/2 checks passed")
    return 0 if n == 2 else 1


if __name__ == "__main__":
    sys.exit(main())
