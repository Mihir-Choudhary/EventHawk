"""Date-only, Time-only and Separately filters use the DISPLAYED date and clock (Codex DF-1).

In any display zone other than UTC both engines turned these three modes into
one continuous datetime range: Date-only From Jan 2 To Jan 3 ended at Jan 3
00:00 (the rest of Jan 3 lost), Time-only 05:00-06:00 kept everything between
the two full datetimes, Separately ignored the daily clock window.  On real
timestamps in UTC+05:30: Date-only 313 of 511, Time-only 340 instead of 36.
Expected: an event matches by the date and clock time the table shows for it
-- in UTC, a fixed offset and a DST zone across its change -- in Normal and
JM, include and exclude.  The expected set is computed here with zoneinfo,
independently of the product.  Synthetic events only.
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

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events():
    out, n = [], 0
    # Every 50 minutes over 2024-03-08..2024-03-12 UTC: crosses New York's
    # DST start (2024-03-10 07:00 UTC) and every clock time of day.
    t = datetime(2024, 3, 8, 0, 7, 0, tzinfo=timezone.utc)
    while t < datetime(2024, 3, 12, 12, 0, tzinfo=timezone.utc):
        n += 1
        out.append({"event_id": 4624, "level": 4, "level_name": "Information", "provider": "P",
                    "channel": "C", "computer": "PC", "record_id": n, "source_file": r"C:\a\s.evtx",
                    "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.000000Z"), "event_data": {"N": str(n)}})
        t += timedelta(minutes=50)
    return out


def shown(ev, zone):
    t = datetime.strptime(ev["timestamp"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return t.astimezone(zone).replace(tzinfo=None) if zone else t.replace(tzinfo=None)


def expected(evs, zone, mode, f, t, exclude):
    out = set()
    for e in evs:
        s = shown(e, zone)
        d_ok = f.date() <= s.date() <= t.date()
        t_ok = f.time() <= s.time() <= t.time()
        hit = {"date_only": d_ok, "time_only": t_ok, "separate": d_ok and t_ok}[mode]
        if hit != exclude:
            out.add(e["record_id"])
    return out


def cfg_for(mode, f, t, exclude):
    from evtx_tool.core.filters import empty_filter
    return dict(empty_filter(), date_from=f.strftime("%Y-%m-%d %H:%M:%S"), date_to=t.strftime("%Y-%m-%d %H:%M:%S"),
                date_enabled=mode in ("date_only", "separate"), time_enabled=mode in ("time_only", "separate"),
                separately_enabled=mode == "separate", date_exclude=exclude)


def normal_ids(evs, cfg):
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    m = EventTableModel()
    m.set_events(evs) if hasattr(m, "set_events") else m.load_events(evs)
    p = EventFilterProxyModel()
    p.setSourceModel(m)
    p.set_advanced_filter(cfg)
    return {evs[p.mapToSource(p.index(r, 0)).row()]["record_id"] for r in range(p.rowCount())}


def jm_ids(model, cfg):
    model.apply_filter(cfg)
    T.wait_for(lambda: not model.filter_pending(), 30); T.pump(50)
    return set(model._display_table.column("record_id").to_pylist())


def main() -> int:
    from zoneinfo import ZoneInfo
    from evtx_tool.gui import models
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    evs = events()
    tmp = tempfile.mkdtemp(prefix="pdm_")
    jm = ArrowTableModel(write_jm(evs, tmp), parquet_dir=tmp)
    T.wait_for(lambda: not jm.filter_pending(), 30)
    zones = [("UTC", ("utc",), None),
             ("UTC+05:30", ("custom", "Asia/Kolkata", 330), timezone(timedelta(minutes=330))),
             ("New York (DST change)", ("specific", "America/New_York", 0), ZoneInfo("America/New_York"))]
    f = datetime(2024, 3, 9, 5, 0, 0)
    t = datetime(2024, 3, 10, 6, 0, 0)
    try:
        for zname, tzcfg, zone in zones:
            models.set_tz_config(*tzcfg)
            for mode in ("date_only", "time_only", "separate"):
                for exclude in (False, True):
                    want = expected(evs, zone, mode, f, t, exclude)
                    cfg = cfg_for(mode, f, t, exclude)
                    label = f"[{zname}] {mode}{' exclude' if exclude else ''}"
                    got = normal_ids(evs, cfg)
                    check(f"{label}: Normal = the shown dates/times", got == want and 0 < len(want) < len(evs),
                          f"{len(got)} vs {len(want)} of {len(evs)}; missing {len(want - got)} extra {len(got - want)}")
                    got = jm_ids(jm, cfg)
                    check(f"{label}: JM = the shown dates/times", got == want,
                          f"{len(got)} vs {len(want)}; missing {len(want - got)} extra {len(got - want)}")
        # System-local display with a 1601 (zero FILETIME) timestamp: Windows
        # cannot convert it, so the table shows it unconverted; the filter
        # must match what the table shows and must not fail.
        models.set_tz_config("local")
        old = dict(evs[0], record_id=9001, timestamp="1601-01-01T00:10:00.000000Z")
        evs2 = evs + [old]
        jm2 = ArrowTableModel(write_jm(evs2, tempfile.mkdtemp(prefix="pdm2_")), parquet_dir="")
        T.wait_for(lambda: not jm2.filter_pending(), 30)
        tf, tt = datetime(2024, 1, 1, 0, 0, 0), datetime(2024, 1, 1, 0, 30, 0)
        want = {e["record_id"] for e in evs2
                if tf.time() <= datetime.strptime(models.apply_tz(e["timestamp"])[:19],
                                                  "%Y-%m-%d %H:%M:%S").time() <= tt.time()}
        cfg = cfg_for("time_only", tf, tt, False)
        check("[local] time_only incl. a 1601 timestamp: Normal = the table's shown times",
              normal_ids(evs2, cfg) == want and 9001 in want, f"{len(want)} expected")
        check("[local] time_only incl. a 1601 timestamp: JM = the table's shown times",
              jm_ids(jm2, cfg) == want)
        jm2.close()
    finally:
        models.set_tz_config("utc")
        jm.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
