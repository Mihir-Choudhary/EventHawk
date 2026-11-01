"""Normal mode converts each timestamp to its display date once, not on every filter.

Found by the dynamic filter-timing run (2026-11-01): on 130,028 real events the
date quick filter froze the window a steady 2.4 s every time, because every
filter pass converted every event's timestamp to the display time zone again.
Expected: repeat date filters do no conversion, and the result stays right
after a time-zone change and after the events are replaced.  Synthetic data.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events(n, start):
    return [{"event_id": 1, "record_id": i + 1, "computer": "C", "channel": "System", "provider": "P",
             "source_file": r"C:\s\System.evtx", "level": 4, "level_name": "Information", "event_data": {},
             "timestamp": (start + timedelta(minutes=i)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")} for i in range(n)]


def main() -> int:
    import evtx_tool.gui.models as M
    calls = {"n": 0}
    real = M._to_display_zone

    def counting(raw):
        calls["n"] += 1
        return real(raw)
    M._to_display_zone = counting
    M.set_tz_config("utc")
    model, proxy = M.EventTableModel(), M.EventFilterProxyModel()
    proxy.setSourceModel(model)
    # 2,000 events from 2024-01-01 20:00 UTC, one a minute: 240 on Jan 1, 1,440 on Jan 2, 320 on Jan 3 (UTC)
    model.set_events(events(2000, datetime(2024, 1, 1, 20, 0, tzinfo=timezone.utc)))

    def date_filter(day):
        proxy.set_quick_filters([{"key": "timestamp_date", "value": day, "include": True}])
        return proxy.rowCount()

    calls["n"] = 0
    n1 = date_filter("2024-01-02")
    first = calls["n"]
    check("first date filter is right (UTC)", n1 == 1440, str(n1))
    calls["n"] = 0
    n2 = date_filter("2024-01-01")
    check("a repeat date filter converts no timestamp again", calls["n"] == 0, f"{calls['n']} conversions (first: {first})")
    check("...and is right", n2 == 240, str(n2))
    # The column-popup value worker (run after every filter change) must reuse the
    # same converted dates: it re-converted every timestamp, which made every other
    # Normal-mode Advanced Filter apply take 3.5-4 s on 130k real events.
    from evtx_tool.gui.jm_col_worker import NormalColValueWorker
    calls["n"] = 0
    vals = {NormalColValueWorker._display_date(e["timestamp"]) for e in model._events}
    check("the column-popup worker converts no timestamp already converted", calls["n"] == 0,
          f"{calls['n']} conversions")
    check("...and gives the same dates", vals == {"2024-01-01", "2024-01-02", "2024-01-03"}, str(sorted(vals)))

    # +05:30: local Jan 2 is UTC [Jan 1 18:30, Jan 2 18:30) -> events 0..1349 = 1,350; local Jan 1 has none
    M.set_tz_config("custom", custom_offset_min=330)
    n3 = date_filter("2024-01-02")
    check("after a time-zone change the dates follow the new zone", n3 == 1350, f"{n3} (want 1350)")
    n3b = date_filter("2024-01-01")
    check("...for every day", n3b == 0, f"{n3b} (want 0)")

    M.set_tz_config("utc")
    model.set_events(events(100, datetime(2024, 5, 5, 0, 0, tzinfo=timezone.utc)))
    n4 = date_filter("2024-05-05")
    check("after the events are replaced the filter uses the new ones", n4 == 100, str(n4))
    M._to_display_zone = real

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
