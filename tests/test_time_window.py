"""Time-window helpers for the "Around this event" pivot.

Every event timestamp shape the two modes store must parse to the same
instant, the window must be inclusive at both ends to the microsecond, and
Juggernaut's string BETWEEN must agree with the Python check exactly -- a
mismatch would silently show different events in the two modes.
"""
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    from evtx_tool.core.time_window import (
        MAX_SIDE, PRESETS, in_window, jm_bound, parse_event_ts, window_bounds,
    )
    utc = timezone.utc
    inst = datetime(2022, 2, 7, 10, 54, 25, 366021, tzinfo=utc)

    print("=== timestamp shapes ===")
    for raw in ("2022-02-07T10:54:25.366021Z", "2022-02-07T10:54:25.3660219Z",
                "2022-02-07T10:54:25.366021+00:00", "2022-02-07 10:54:25.366021"):
        got = parse_event_ts(raw)
        check(f"{raw!r} is the instant", got == inst, str(got))
    whole = datetime(2022, 2, 7, 10, 54, 25, tzinfo=utc)
    for raw in ("2022-02-07T10:54:25Z", "2022-02-07 10:54:25", "2022-02-07T10:54:25.0000000Z"):
        got = parse_event_ts(raw)
        check(f"{raw!r} (no fraction) is the whole second", got == whole, str(got))
    check("short fraction .5 is 500000 us",
          parse_event_ts("2022-02-07T10:54:25.5Z") == whole.replace(microsecond=500000))
    check("result is UTC-aware", (parse_event_ts("2022-02-07T10:54:25Z") or whole).tzinfo is not None)
    for raw in ("", None, "   ", "not a time", "2022-13-45T99:99:99Z"):
        check(f"{raw!r} is None", parse_event_ts(raw) is None)

    print("\n=== window edges ===")
    five = timedelta(minutes=5)
    lo, hi = window_bounds(inst, five, five)
    check("bounds are anchor -/+ the sides", (lo, hi) == (inst - five, inst + five))
    check("exactly anchor - 5 min is in", in_window(inst - five, lo, hi))
    check("exactly anchor + 5 min is in", in_window(inst + five, lo, hi))
    us = timedelta(microseconds=1)
    check("5 min + 1 us before is out", not in_window(inst - five - us, lo, hi))
    check("5 min + 1 us after is out", not in_window(inst + five + us, lo, hi))
    check("a missing timestamp is out", not in_window(None, lo, hi))
    z_lo, z_hi = window_bounds(inst, timedelta(0), timedelta(0))
    check("a zero window holds the anchor itself", in_window(inst, z_lo, z_hi))
    check("...and nothing a microsecond off", not in_window(inst + us, z_lo, z_hi))

    print("\n=== Juggernaut bound ===")
    check("jm_bound form", jm_bound(inst) == "2022-02-07 10:54:25.366021", jm_bound(inst))
    check("jm_bound of a whole second keeps six digits",
          jm_bound(whole) == "2022-02-07 10:54:25.000000", jm_bound(whole))
    ist = timezone(timedelta(hours=5, minutes=30))
    check("jm_bound converts to UTC", jm_bound(inst.astimezone(ist)) == "2022-02-07 10:54:25.366021")
    rng = random.Random(20221025)
    s_lo, s_hi = jm_bound(lo), jm_bound(hi)
    disagree = 0
    for _ in range(1000):
        t = inst + timedelta(microseconds=rng.randint(-400_000_000, 400_000_000))
        if rng.random() < 0.05:
            t = rng.choice([lo, hi, lo - us, hi + us])
        jm_ts = t.strftime("%Y-%m-%d %H:%M:%S.%f")
        if (s_lo <= jm_ts <= s_hi) != in_window(t, lo, hi):
            disagree += 1
    check("string BETWEEN agrees with in_window on 1,000 instants", disagree == 0, str(disagree))

    print("\n=== presets ===")
    check("presets", PRESETS == [("±1 min", timedelta(minutes=1)), ("±5 min", timedelta(minutes=5)),
                                 ("±15 min", timedelta(minutes=15)), ("±1 hour", timedelta(hours=1)),
                                 ("±1 day", timedelta(days=1))], str(PRESETS))
    check("MAX_SIDE is 365 days", MAX_SIDE == timedelta(days=365))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
