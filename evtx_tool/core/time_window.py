"""Time windows around an event, for the "Around this event" pivot.

Normal mode stores ISO timestamps (``...Z`` or ``+00:00``, up to seven
fractional digits from the EVTX FILETIME); Juggernaut stores
``YYYY-MM-DD HH:MM:SS.ffffff`` strings.  Both parse to one UTC instant here,
the window is inclusive at both ends, and ``jm_bound`` renders a bound in
Juggernaut's own form so its string ``BETWEEN`` selects exactly the events
``in_window`` does.  Pure logic, no Qt.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

PRESETS: list[tuple[str, timedelta]] = [
    ("±1 min", timedelta(minutes=1)),
    ("±5 min", timedelta(minutes=5)),
    ("±15 min", timedelta(minutes=15)),
    ("±1 hour", timedelta(hours=1)),
    ("±1 day", timedelta(days=1)),
]
MAX_SIDE = timedelta(days=365)

_TS = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?"
    r"(Z|[+-]\d{2}:?\d{2})?"
)


def parse_event_ts(raw) -> datetime | None:
    """A stored event timestamp as a UTC-aware datetime; None if blank or bad.

    Fractions past six digits are truncated (EVTX keeps 100 ns ticks; both
    modes keep microseconds).  A timestamp without an offset is UTC.
    """
    m = _TS.fullmatch(str(raw or "").strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, off = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s),
                      int(((frac or "") + "000000")[:6]), tzinfo=timezone.utc)
    except ValueError:
        return None
    if off and off != "Z":
        sign = -1 if off[0] == "-" else 1
        digits = off[1:].replace(":", "")
        dt -= sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return dt


def window_bounds(anchor: datetime, before: timedelta,
                  after: timedelta) -> tuple[datetime, datetime]:
    return anchor - before, anchor + after


def in_window(ts: datetime | None, start: datetime, end: datetime) -> bool:
    """Inclusive at both ends; an event without a timestamp is never in."""
    return ts is not None and start <= ts <= end


def jm_bound(dt: datetime) -> str:
    """*dt* in Juggernaut's ``timestamp_utc`` form, for ``BETWEEN``."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")


def window_test(start: datetime, end: datetime):
    """A per-event check for Normal mode's raw timestamps, fast on big scans.

    Returns ``test(raw) -> True | False | None`` (None: no usable timestamp).
    EVTX SystemTime is almost always ``YYYY-MM-DDTHH:MM:SS.ffffffZ``; that
    fixed-width shape compares as a string, exactly like the instant.  Any
    other shape is parsed.
    """
    lo = start.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    hi = end.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def test(raw):
        if (raw.__class__ is str and len(raw) == 27 and raw[26] == "Z"
                and raw[10] == "T" and raw[19] == "."):
            return lo <= raw <= hi
        t = parse_event_ts(raw)
        return None if t is None else start <= t <= end
    return test
