"""CLI date bounds: a UTC offset is converted, a bare date is a date, nothing fails open.

Gemini audit 4-03 (High): core.filters._parse_ts cut "+05:30" off a bound and
read the rest as UTC (5.5 hours wrong); it did not know "+0530"; and a bare
"2026-03-05" (a hand-written --filter-file) parsed to None, so that bound
was ignored and the filter let everything through.

Expected: "2026-03-01T12:00:00+05:30" and "...+0530" are 06:30 UTC;
"2026-03-05" is 2026-03-05 00:00 UTC; an event at 06:00Z fails a
date_from of 12:00+05:30 and one at 07:00Z passes; with date_from
"2026-03-05" an event on 2026-03-01 is rejected.  Synthetic values.
"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.filters import _parse_ts, compile_filter, passes_filter, empty_filter
    want = datetime(2026, 3, 1, 6, 30, tzinfo=timezone.utc)
    for s in ("2026-03-01T12:00:00+05:30", "2026-03-01T12:00:00+0530", "2026-03-01 12:00:00+05:30"):
        check(f"{s} is 06:30 UTC", _parse_ts(s) == want, str(_parse_ts(s)))
    check("2026-03-01T01:00:00-05:00 is 06:00 UTC",
          _parse_ts("2026-03-01T01:00:00-05:00") == datetime(2026, 3, 1, 6, 0, tzinfo=timezone.utc))
    check("a bare date is midnight UTC", _parse_ts("2026-03-05") == datetime(2026, 3, 5, tzinfo=timezone.utc),
          str(_parse_ts("2026-03-05")))
    check("a plain Z time is unchanged",
          _parse_ts("2026-03-01T12:00:00.123456Z") == datetime(2026, 3, 1, 12, tzinfo=timezone.utc))
    ev = lambda ts: {"event_id": 1, "timestamp": ts, "event_data": {}}
    fc = empty_filter()
    fc["date_from"] = "2026-03-01T12:00:00+05:30"
    for f_name, f in (("passes_filter", lambda e: passes_filter(e, fc)), ("compile_filter", compile_filter(fc))):
        check(f"{f_name}: 06:00Z is before 12:00+05:30", not f(ev("2026-03-01T06:00:00.000000Z")))
        check(f"{f_name}: 07:00Z is after 12:00+05:30", f(ev("2026-03-01T07:00:00.000000Z")))
    fc2 = empty_filter()
    fc2["date_from"] = "2026-03-05"
    check("a bare-date From rejects an earlier event (no fail-open)",
          not compile_filter(fc2)(ev("2026-03-01T07:00:00.000000Z")))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
