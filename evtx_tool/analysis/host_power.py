"""When each host was shut down and started again, and what that means for a session.

A connection or remote session cannot survive its host being switched off.
Windows logs both ends of a clean restart:

  shutdown  Kernel-General 13 (with StopTime), EventLog 6006, Kernel-Power 109,
            Security 1100 / 4609, User32 1074 (initiated)
  startup   Kernel-General 12 (with StartTime), Security 4608
  unexpected shutdown (logged at the next startup): EventLog 6008, Kernel-Power 41

A Kernel-General record's StartTime / StopTime can differ from the time the
record was written (one StartTime on the corpus sat exactly an hour before its
record with nothing logged between), so each such moment is a window from the
earlier to the later of the two (ruling R19).

assess() answers, for one session of one host from *start* to *end*:
  None          no restart touches the session
  "uncertain"   a startup window reaches across the start or the end
  "restarted"   a restart lies inside, but its downtime cannot be measured
                (shutdown not logged, unexpected shutdown, or a window too wide)
  "subtracted"  every restart inside has a logged shutdown and startup: the
                connected time is the span minus the downtime.  The time after a
                restart is NOT proven -- no reconnect was logged -- and the note
                says so (user decision 2026-11-05: show the subtracted figure,
                marked, with the parts in the notes).
  "open"        the session has no end and a restart follows: it ended by the
                shutdown at the latest
"""
from __future__ import annotations

from datetime import datetime, timezone

# A window wider than this is not a usable moment for subtracting downtime.
_MAX_WINDOW_SECS = 60.0
# Startup records this close together, with no shutdown between, are one startup.
_MERGE_SECS = 300.0

_POWER_EIDS = frozenset({12, 13, 41, 109, 1074, 1100, 4608, 4609, 6006, 6008})

# The Juggernaut WHERE that loads exactly the events classify() can use.
POWER_SQL = (
    "((event_id IN (12, 13) AND provider = 'Microsoft-Windows-Kernel-General')"
    " OR (event_id IN (41, 109) AND provider = 'Microsoft-Windows-Kernel-Power')"
    " OR (event_id IN (6006, 6008) AND lower(provider) = 'eventlog')"
    " OR (event_id = 1074 AND lower(provider) = 'user32')"
    " OR (event_id IN (4608, 4609, 1100) AND lower(channel) = 'security'))"
)

_SHUTDOWN_RANK = {"Kernel-General 13": 5, "EventLog 6006": 4, "Security 1100": 3,
                  "Security 4609": 3, "Kernel-Power 109": 2, "User32 1074": 1}

_KG = "microsoft-windows-kernel-general"
_KP = "microsoft-windows-kernel-power"


def _dt(value) -> "datetime | None":
    """A naive UTC datetime from an event time string or datetime, else None."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        d = value
    else:
        s = str(value).strip()
        if not s:
            return None
        s = s.replace(" ", "T", 1) if "T" not in s else s
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None
    if d.tzinfo is not None:
        d = d.astimezone(timezone.utc).replace(tzinfo=None)
    return d


def _eid(ev) -> int:
    try:
        return int(ev.get("event_id") or ev.get("EventID") or 0)
    except (TypeError, ValueError):
        return 0


def _host(ev) -> str:
    return str(ev.get("computer") or ev.get("Computer") or "").strip().lower()


def _data(ev) -> dict:
    d = ev.get("event_data")
    return d if isinstance(d, dict) else {}


def classify(ev) -> "tuple | None":
    """("boot" | "shutdown", lo, hi, label) or ("unexpected", t, t, label), else None."""
    eid = _eid(ev)
    if eid not in _POWER_EIDS:
        return None
    prov = str(ev.get("provider") or "").strip().lower()
    chan = str(ev.get("channel") or "").strip().lower()
    t = _dt(ev.get("timestamp") or ev.get("Timestamp"))
    if t is None:
        return None

    def window(field):
        alt = _dt(_data(ev).get(field)) if isinstance(_data(ev).get(field), str) else None
        return (min(t, alt), max(t, alt)) if alt is not None else (t, t)

    if eid == 12 and prov == _KG:
        return ("boot",) + window("StartTime") + ("Kernel-General 12",)
    if eid == 4608 and chan == "security":
        return ("boot", t, t, "Security 4608")
    if eid == 13 and prov == _KG:
        return ("shutdown",) + window("StopTime") + ("Kernel-General 13",)
    if eid == 6006 and prov == "eventlog":
        return ("shutdown", t, t, "EventLog 6006")
    if eid == 109 and prov == _KP:
        return ("shutdown", t, t, "Kernel-Power 109")
    if eid in (1100, 4609) and chan == "security":
        return ("shutdown", t, t, f"Security {eid}")
    if eid == 1074 and prov == "user32":
        return ("shutdown", t, t, "User32 1074")
    if eid == 6008 and prov == "eventlog":
        return ("unexpected", t, t, "EventLog 6008")
    if eid == 41 and prov == _KP:
        return ("unexpected", t, t, "Kernel-Power 41")
    return None


def fmt_secs(total: float) -> str:
    h, rem = divmod(int(total), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s" if m else f"{s}s"


def _ts(d: datetime) -> str:
    return d.strftime("%Y-%m-%d %H:%M:%S") + " UTC"


class HostPower:
    """Restarts per host, each: dict(boot=(lo, hi, label), shutdown=(lo, hi, label) | None,
    unexpected=label | None)."""

    def __init__(self, events):
        marks: dict[str, list] = {}
        for ev in events:
            c = classify(ev)
            if c is None:
                continue
            h = _host(ev)
            if h:
                marks.setdefault(h, []).append(c)
        self.restarts: dict[str, list[dict]] = {}
        for h, ms in marks.items():
            downs = [m for m in ms if m[0] == "shutdown"]
            # One startup can be several records: copies of the same log, and
            # Kernel-General 12 plus Security 4608 a few seconds apart.  Records
            # within _MERGE_SECS of each other with no shutdown record between
            # them are one startup, spanning all of them (never narrower).
            boots = []
            for m in sorted((m for m in ms if m[0] == "boot"), key=lambda m: (m[1], m[2])):
                if boots:
                    p = boots[-1]
                    if ((m[1] - p[2]).total_seconds() <= _MERGE_SECS
                            and not any(p[2] < d[1] <= m[1] for d in downs)):
                        lbl = p[3] if p[3] == m[3] or m[3] in p[3].split(" + ") else f"{p[3]} + {m[3]}"
                        boots[-1] = ("boot", min(p[1], m[1]), max(p[2], m[2]), lbl)
                        continue
                boots.append(m)
            unexp = [m for m in ms if m[0] == "unexpected"]
            out = []
            prev_hi = None
            for i, b in enumerate(boots):
                nxt = boots[i + 1][1] if i + 1 < len(boots) else None
                # The shutdown before this startup: logged after the previous
                # startup and before this one; the latest is closest to power-off.
                cands = [d for d in downs if d[2] <= b[1] and (prev_hi is None or d[1] > prev_hi)]
                # Ties (13 and 6006 written together) go to the record that
                # carries the exact stop time, so both modes name the same one.
                sd = max(cands, key=lambda d: (d[2], _SHUTDOWN_RANK.get(d[3], 0), d[3])) if cands else None
                # 6008 / 41 are written at the startup that follows the crash.
                ux = next((u for u in unexp if u[1] >= b[1] and (nxt is None or u[1] < nxt)), None)
                out.append({"boot": b[1:], "shutdown": sd[1:] if sd else None,
                            "unexpected": ux[3] if ux else None})
                prev_hi = b[2]
            self.restarts[h] = out

    def assess(self, host: str, start, end) -> "dict | None":
        s, e = _dt(start), _dt(end)
        if s is None:
            return None
        inside, uncertain = [], []
        for r in self.restarts.get(str(host or "").strip().lower(), ()):
            lo, hi, _lbl = r["boot"]
            if hi <= s or (e is not None and lo >= e):
                continue                                  # wholly before / after
            if lo > s and (e is None or hi < e):
                inside.append(r)
            else:
                uncertain.append(r)
        if uncertain:
            r = uncertain[0]
            return {"kind": "uncertain",
                    "note": (f"Host started between {_ts(r['boot'][0])} and {_ts(r['boot'][1])} "
                             f"({r['boot'][2]}); that reaches across this session's "
                             f"{'start' if r['boot'][0] <= s else 'end'}, so whether it restarted "
                             f"during the session is uncertain. No duration.")}
        if not inside:
            return None
        if e is None:
            r = inside[0]
            sd = r["shutdown"]
            if sd and sd[0] > s and not r["unexpected"]:
                note = (f"Host shut down at {_ts(sd[0])} ({sd[2]}) and started at {_ts(r['boot'][1])}: "
                        f"connected until the shutdown at the latest ({fmt_secs((sd[0] - s).total_seconds())}).")
            else:
                note = (f"Host started again at {_ts(r['boot'][1])} ({r['boot'][2]}); "
                        + ("the shutdown was unexpected and its time is not logged."
                           if r["unexpected"] else "its shutdown time is not logged."))
            return {"kind": "open", "note": note}
        # Every restart inside needs a measurable downtime.
        periods = []
        for r in inside:
            sd, (blo, bhi, blabel) = r["shutdown"], r["boot"]
            why = None
            if r["unexpected"]:
                why = f"the shutdown was unexpected ({r['unexpected']}) and its time is not logged"
            elif (bhi - blo).total_seconds() > _MAX_WINDOW_SECS:
                why = (f"its startup time is uncertain ({blabel}: {_ts(blo)} to {_ts(bhi)})")
            elif sd is None:
                why = "its shutdown is not logged"
            elif sd[0] <= s:
                why = f"its shutdown record ({sd[2]}, {_ts(sd[0])}) is not after the session's start"
            elif (sd[1] - sd[0]).total_seconds() > _MAX_WINDOW_SECS:
                why = f"its shutdown time is uncertain ({sd[2]}: {_ts(sd[0])} to {_ts(sd[1])})"
            if why:
                return {"kind": "restarted",
                        "note": f"Host restarted during the session (started {_ts(bhi)}), but {why}: "
                                f"no duration."}
            periods.append((sd[0], bhi, sd[2], blabel))
        total = (e - s).total_seconds()
        down = sum((b - a).total_seconds() for a, b, _x, _y in periods)
        connected = total - down
        if connected < 0 or any(periods[i][1] > periods[i + 1][0] for i in range(len(periods) - 1)):
            return {"kind": "restarted",
                    "note": "Host restarted during the session, but its shutdown and startup times "
                            "do not fit inside the session: no duration."}
        parts = [f"{fmt_secs((periods[0][0] - s).total_seconds())} before the shutdown "
                 f"(until the shutdown at the latest)"]
        for i, (a, b, _sa, _sb) in enumerate(periods):
            parts.append(f"{fmt_secs((b - a).total_seconds())} down (subtracted)")
            if i + 1 < len(periods):
                parts.append(f"{fmt_secs((periods[i + 1][0] - b).total_seconds())} between restarts "
                             f"(not proven: no reconnect was logged)")
        parts.append(f"{fmt_secs((e - periods[-1][1]).total_seconds())} after the restart "
                     f"(not proven: no reconnect was logged after the restart)")
        downs = "; ".join(f"{_ts(a)} ({sa}) to {_ts(b)} ({sb})" for a, b, sa, sb in periods)
        return {"kind": "subtracted", "seconds": connected, "downtime": down,
                "note": (f"{fmt_secs(down)} subtracted: host was down {downs}. "
                         f"Span {fmt_secs(total)} = " + " + ".join(parts) + ".")}
