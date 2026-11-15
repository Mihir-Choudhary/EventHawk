"""Display time zone "local": a date before 1970 never crashes the Normal filter.

Gemini audit 4-02 (High): on Windows, datetime.astimezone() raises OSError
for any instant before 1970-01-01 UTC.  With the display zone set to
"local", utc_to_display_naive() and the Normal proxy's boundary conversion
called it bare, so a From of 1601-01-01 (or Qt's minimum date) raised
OSError out of set_advanced_filter, while Juggernaut handled it.

Expected: utc_to_display_naive(1601-01-01 UTC) returns a value; a Normal
date filter from 1601-01-01 to 2030 applies without an exception and keeps
every event.  Synthetic events.  (Meaningful on Windows; elsewhere it passes
trivially.)
"""
import os
import sys
from datetime import datetime, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    import evtx_tool.gui.models as M
    M.set_tz_config("local", "UTC", 0)
    try:
        v = M.utc_to_display_naive(datetime(1601, 1, 1, tzinfo=timezone.utc))
        err = ""
    except Exception as e:
        v, err = None, repr(e)
    check("utc_to_display_naive(1601-01-01) returns a value", v is not None, err or str(v))
    base = {"event_id": 1, "level": 4, "level_name": "Information", "channel": "C", "computer": "H",
            "provider": "P", "event_data": {}, "source_file": "f.evtx", "user_id": ""}
    evs = [dict(base, record_id=i, timestamp=f"2026-01-0{i}T10:00:00.000000Z") for i in (1, 2, 3)]
    src = M.EventTableModel()
    src.set_events(evs)
    px = M.EventFilterProxyModel()
    px.setSourceModel(src)
    try:
        px.set_advanced_filter({"date_enabled": True, "time_enabled": True,
                                "date_from": "1601-01-01 00:00:00", "date_to": "2030-01-01 00:00:00"})
        n, err = px.rowCount(), ""
    except Exception as e:
        n, err = -1, repr(e)
    check("a Normal date filter from 1601 applies and keeps every event", n == 3, err or f"{n} rows")
    M.set_tz_config("utc", "UTC", 0)
    k = sum(ok for _, ok, _ in CHECKS)
    print(f"{k}/{len(CHECKS)} checks passed")
    return 0 if k == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
