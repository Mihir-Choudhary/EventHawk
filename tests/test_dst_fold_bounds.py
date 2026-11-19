"""Date-and-time range bounds in a repeated or skipped DST hour (Gemini audit 4-09).

On the night clocks go back, 01:00-02:00 is shown twice.  Both engines read
every bound as the FIRST pass, so To = 01:30 ended at 01:30 summer time and the
events the table shows at 01:00-01:30 the second time (winter time) were
silently left out of the filter.  Expected: a lower bound takes the first
instant of a repeated wall time, an upper bound the last, so every event the
table shows inside the window passes; a skipped wall time (spring forward)
lands on the change itself.  Normal and JM, include and exclude, and the UTC
bound written into a saved preset.  The expected sets are computed here with
zoneinfo only, independently of the product.  Synthetic events only.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_around_pivot as T                                       # noqa: E402
from test_jm_export_text_filter import write_jm                     # noqa: E402
from test_partial_date_modes_tz import normal_ids, jm_ids           # noqa: E402

CHECKS = []
UTC = timezone.utc


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events():
    out, n = [], 0
    # Every 5 minutes around New York's 2024 changes: fall back 2024-11-03
    # 06:00 UTC (01:00-02:00 shown twice), spring forward 2024-03-10 07:00 UTC
    # (02:00-03:00 never shown).
    for start in (datetime(2024, 11, 3, 3, 0, 7, tzinfo=UTC), datetime(2024, 3, 10, 4, 0, 7, tzinfo=UTC)):
        t = start
        while t < start + timedelta(hours=6):
            n += 1
            out.append({"event_id": 4624, "level": 4, "level_name": "Information", "provider": "P",
                        "channel": "C", "computer": "PC", "record_id": n, "source_file": r"C:\a\s.evtx",
                        "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000000Z"), "event_data": {"N": str(n)}})
            t += timedelta(minutes=5)
    return out


def utc_of(e):
    return datetime.strptime(e["timestamp"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)


def instants(wall, zone):
    """Every UTC second (whole) shown as *wall* in *zone*: zoneinfo directly."""
    out = []
    for fold in (0, 1):
        u = wall.replace(tzinfo=zone, fold=fold).astimezone(UTC)
        if u.astimezone(zone).replace(tzinfo=None) == wall:
            out.append(u)
    return out


def bounds(f, t, zone):
    lo = instants(f, zone)
    hi = instants(t, zone)
    # A skipped wall time: walk second by second from the side shown before it.
    if lo:
        lo_u = min(lo)
    else:                              # the first second shown at or after f
        lo_u = min(f.replace(tzinfo=zone, fold=k).astimezone(UTC) for k in (0, 1))
        while lo_u.astimezone(zone).replace(tzinfo=None) < f:
            lo_u += timedelta(seconds=1)
    if hi:
        hi_u = max(hi)
    else:                              # the last second shown at or before t
        hi_u = max(t.replace(tzinfo=zone, fold=k).astimezone(UTC) for k in (0, 1))
        while hi_u.astimezone(zone).replace(tzinfo=None) > t:
            hi_u -= timedelta(seconds=1)
    return lo_u, hi_u


def expected(evs, zone, f, t, exclude):
    lo_u, hi_u = bounds(f, t, zone)
    return {e["record_id"] for e in evs if (lo_u <= utc_of(e).replace(microsecond=0) <= hi_u) != exclude}


def shown_inside(evs, zone, f, t):
    """Events the table shows at a wall time inside [f, t] (either pass)."""
    return {e["record_id"] for e in evs
            if f <= utc_of(e).astimezone(zone).replace(tzinfo=None) <= t}


def cfg_for(f, t, exclude):
    from evtx_tool.core.filters import empty_filter
    return dict(empty_filter(), date_from=f.strftime("%Y-%m-%d %H:%M:%S"),
                date_to=t.strftime("%Y-%m-%d %H:%M:%S"),
                date_enabled=True, time_enabled=True, separately_enabled=False, date_exclude=exclude)


def main() -> int:
    from zoneinfo import ZoneInfo
    from evtx_tool.gui import models
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    zone = ZoneInfo("America/New_York")
    evs = events()
    tmp = tempfile.mkdtemp(prefix="dstfold_")
    jm = ArrowTableModel(write_jm(evs, tmp), parquet_dir=tmp)
    T.wait_for(lambda: not jm.filter_pending(), 30)
    windows = [
        ("To inside the repeated hour", datetime(2024, 11, 3, 0, 30), datetime(2024, 11, 3, 1, 30)),
        ("From inside the repeated hour", datetime(2024, 11, 3, 1, 30), datetime(2024, 11, 3, 3, 0)),
        ("both bounds in the repeated hour", datetime(2024, 11, 3, 1, 10), datetime(2024, 11, 3, 1, 40)),
        ("To inside the skipped hour", datetime(2024, 3, 10, 1, 0), datetime(2024, 3, 10, 2, 30)),
        ("From inside the skipped hour", datetime(2024, 3, 10, 2, 30), datetime(2024, 3, 10, 3, 30)),
        ("an ordinary night (control)", datetime(2024, 3, 10, 0, 0), datetime(2024, 3, 10, 1, 0)),
    ]
    try:
        models.set_tz_config("specific", "America/New_York", 0)
        for name, f, t in windows:
            inside = shown_inside(evs, zone, f, t)
            for exclude in (False, True):
                want = expected(evs, zone, f, t, exclude)
                cfg = cfg_for(f, t, exclude)
                label = f"[{name}]{' exclude' if exclude else ''}"
                if not exclude:
                    check(f"{label}: expected set holds every event shown inside the window",
                          inside <= want and 0 < len(want) < len(evs), f"{len(inside)} shown, {len(want)} expected")
                got = normal_ids(evs, cfg)
                check(f"{label}: Normal", got == want,
                      f"{len(got)} vs {len(want)}; missing {len(want - got)} extra {len(got - want)}")
                got = jm_ids(jm, cfg)
                check(f"{label}: JM", got == want,
                      f"{len(got)} vs {len(want)}; missing {len(want - got)} extra {len(got - want)}")
        # The UTC bound a saved preset records (filter_dialog, Gemini 4-05).
        up = models.display_naive_to_utc(datetime(2024, 11, 3, 1, 30), upper=True)
        lo = models.display_naive_to_utc(datetime(2024, 11, 3, 1, 30))
        check("preset: upper bound 01:30 in the repeated hour = the second pass (06:30Z)",
              up == datetime(2024, 11, 3, 6, 30, tzinfo=UTC), str(up))
        check("preset: lower bound 01:30 in the repeated hour = the first pass (05:30Z)",
              lo == datetime(2024, 11, 3, 5, 30, tzinfo=UTC), str(lo))
        gap_up = models.display_naive_to_utc(datetime(2024, 3, 10, 2, 30), upper=True)
        gap_lo = models.display_naive_to_utc(datetime(2024, 3, 10, 2, 30))
        check("preset: skipped 02:30 as lower bound = the change (07:00Z)",
              gap_lo == datetime(2024, 3, 10, 7, 0, tzinfo=UTC), str(gap_lo))
        check("preset: skipped 02:30 as upper bound = one second before the change",
              gap_up == datetime(2024, 3, 10, 6, 59, 59, tzinfo=UTC), str(gap_up))
        models.set_tz_config("custom", "Asia/Kolkata", 330)
        check("fixed offset unchanged: 01:30 +05:30 = 20:00Z the day before",
              models.display_naive_to_utc(datetime(2024, 11, 3, 1, 30), upper=True)
              == datetime(2024, 11, 2, 20, 0, tzinfo=UTC))
    finally:
        models.set_tz_config("utc")
        jm.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
