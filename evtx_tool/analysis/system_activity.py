"""System activity per computer: on, screen on/off, sleep, hibernate, shut down, locked.

User request (2026-11-07): a tool like Logon Sessions / WiFi / Remote sessions
that shows "the system was on from this time to this time, then in sleep from
this time to this time, shut down from this time to this time", and the
screen, lock and idle activity in between.

Evidence (research 2026-11-07; codes checked by rendering the test logs'
events with Windows' own message tables, Get-WinEvent):

  power on / off   Kernel-General 12 (StartTime) / 13 (StopTime), EventLog
                   6005/6006, Security 4608/4609/1100, Kernel-Power 109 (action),
                   User32 1074 (who/what started a shutdown or restart);
                   unexpected: Kernel-Power 41, EventLog 6008 (Windows' own text
                   of when).  Restarts are paired by host_power.HostPower, the
                   same analysis the WiFi / Remote Assistance downtime uses.
  sleep/hibernate  Power-Troubleshooter 1: exact SleepTime and WakeTime, target
                   power state (SYSTEM_POWER_STATE: 2-4 = S1-S3 sleep, 5 =
                   hibernate) and wake source.  A zero-length one with wake
                   source "S4 Doze to Hibernate" marks a sleep turning into
                   hibernation.  Kernel-Power 42 = going to sleep (reason, target).
                   Kernel-Power 107 ("resumed") is written with the clock as it
                   was BEFORE the sleep (one test-log sleep from 14:03 to 14:18
                   has its 107 at 14:03:09): its time is never used as the wake.
  screen           Kernel-Power 566 (Windows 10 2004+ / 11): "the system session
                   has transitioned", with the previous session's length in
                   microseconds.  Session type 0 = screen on, 1 = screen off,
                   3 = sleep.  Windows does not name the types; the meaning is
                   inferred from the test logs (ruling R32): every 1->3 / 0->3
                   coincides with a sleep start (46/46), every 3->x with a
                   Power-Troubleshooter wake (47/47), the first session after a
                   start is type 0 and lasts from the start (38/39), and 1->0 is
                   caused by keyboard/mouse, movement or power changes.  The type
                   numbers are shown next to the label.
  modern standby   Kernel-Power 506 (entering) / 507 (exiting).
  lock             Security 4800/4801 (locked/unlocked), 4802/4803 (screen saver),
                   4624 logon type 7 (unlock).  Needs "Audit Other Logon/Logoff
                   Events"; off by default.
  moments          Kernel-Boot 27 (boot type), Diagnostics-Performance 100/200
                   (boot / shutdown start and end), Kernel-General 1 and Security
                   4616 (clock changed), Kernel-Power 105 (AC / battery),
                   Winlogon 7001/7002 (console logon / logoff).

Nothing is invented: a time the events do not prove is None and the notes say
why.  Copies of the same log count once.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from evtx_tool.analysis.host_power import HostPower, _dt, fmt_secs

KG = "microsoft-windows-kernel-general"
KP = "microsoft-windows-kernel-power"
PT = "microsoft-windows-power-troubleshooter"
KB = "microsoft-windows-kernel-boot"
WL = "microsoft-windows-winlogon"
DP = "microsoft-windows-diagnostics-performance"

# (provider, event IDs) the tool reads.  Security-channel events by channel.
PROVIDER_EIDS = {
    KG: (1, 12, 13),
    KP: (41, 42, 105, 107, 109, 506, 507, 566),
    PT: (1,),
    KB: (27,),
    "eventlog": (6005, 6006, 6008, 6013),
    "user32": (1074,),
    WL: (7001, 7002),
    DP: (100, 200),
}
SECURITY_EIDS = (1100, 4608, 4609, 4616, 4800, 4801, 4802, 4803)

# The Juggernaut WHERE for exactly the events relevant() accepts.
ACTIVITY_SQL = "(" + " OR ".join(
    [f"(lower(provider) = '{p}' AND event_id IN ({', '.join(map(str, ids))}))"
     for p, ids in PROVIDER_EIDS.items()]
    + [f"(lower(channel) = 'security' AND event_id IN ({', '.join(map(str, SECURITY_EIDS))}))",
       "(lower(channel) = 'security' AND event_id = 4624 AND ed_logon_type = '7')"]) + ")"

# Codes as Windows renders them (Get-WinEvent on the test logs), else "code N".
SLEEP_REASON = {0: "Button or Lid", 2: "Battery", 6: "Hibernate from Sleep - Fixed Timeout",
                7: "System Idle"}
POWER_ACTION = {4: "Shutdown", 5: "Reboot", 6: "Shutdown (power off)"}
ACTION_REASON = {0: "Button or Lid", 5: "Kernel API"}
SESSION_REASON = {1: "Unknown", 5: "AcDcBurst", 12: "SessionUnlock", 15: "PolicyChange",
                  17: "ScreenOffGracePeriod", 20: "SxTransition", 31: "InputAccelerometer",
                  32: "InputHid", 33: "InputPoUserPresent", 53: "Austerity Battery Drain Budget Exceeded"}
WAKE_SOURCE = {0: "Unknown", 1: "Power Button", 3: "S4 Doze to Hibernate", 5: "Device"}
SESSION_TYPE = {0: "Screen on", 1: "Screen off", 3: "Sleep"}
# Community references, not Microsoft documentation; the code is always shown.
BOOT_TYPE = {0: "cold boot (full shutdown or restart)", 1: "fast startup (hybrid boot)",
             2: "resume from hibernation"}

_TRANSITION = timedelta(seconds=30)


def _prov(ev) -> str:
    return str(ev.get("provider") or "").strip().lower()


def _int(v, default=None):
    try:
        return int(str(v).strip(), 0) if isinstance(v, str) and str(v).strip().lower().startswith("0x") \
            else int(v)
    except (TypeError, ValueError):
        return default


def relevant(ev) -> bool:
    """The Normal-mode twin of ACTIVITY_SQL."""
    eid = _int(ev.get("event_id"), -1)
    if eid in PROVIDER_EIDS.get(_prov(ev), ()):
        return True
    if str(ev.get("channel") or "").strip().lower() == "security":
        if eid in SECURITY_EIDS:
            return True
        if eid == 4624:
            ed = ev.get("event_data") or {}
            return str(ed.get("LogonType", "")).strip() == "7" if isinstance(ed, dict) else False
    return False


def _data(ev) -> dict:
    d = ev.get("event_data")
    return d if isinstance(d, dict) else {}


def _params(ev) -> list:
    """The unnamed <Data> values of a classic event (User32 1074, EventLog 6008)."""
    d = _data(ev).get("Data")
    if isinstance(d, dict):
        d = d.get("#text")
    if isinstance(d, list):
        return ["" if x is None else str(x).replace("‎", "").replace("‏", "") for x in d]
    return [] if d is None else [str(d)]


def _label(ev) -> str:
    p = _prov(ev)
    short = {KG: "Kernel-General", KP: "Kernel-Power", PT: "Power-Troubleshooter", KB: "Kernel-Boot",
             WL: "Winlogon", DP: "Diagnostics-Performance", "eventlog": "EventLog",
             "user32": "User32"}.get(p)
    if short is None:
        short = "Security" if str(ev.get("channel") or "").lower() == "security" else (ev.get("provider") or "?")
    return f"{short} {_int(ev.get('event_id'), '?')}"


def _code(mapping, v) -> str:
    n = _int(v)
    if n is None:
        return f"code {v}" if v not in (None, "") else "not given"
    return f"{mapping[n]} ({n})" if n in mapping else f"code {n}"


def _key(ev) -> tuple:
    """Content identity, so copies of the same log count once."""
    return (str(ev.get("computer") or "").strip().lower(), _prov(ev), _int(ev.get("event_id")),
            str(_dt(ev.get("timestamp"))), json.dumps(_data(ev), sort_keys=True, default=str))


class _Host:
    def __init__(self, name):
        self.name = name
        self.events: list[tuple[datetime, dict]] = []


def build(events) -> dict:
    """{"hosts": [names], "rows": [...], "points": [...]} - see module doc.

    row:   host, layer (Power | Screen | Lock), state, start, end (naive UTC
           datetimes or None), duration (timedelta or None), started_by,
           ended_by (evidence labels), start_ev, end_ev (event dicts for the
           Around pivot), notes
    point: host, time, what, details, evidence, ev
    """
    hosts: dict[str, _Host] = {}
    seen = set()
    for ev in events:
        if not relevant(ev):
            continue
        t = _dt(ev.get("timestamp"))
        if t is None:
            continue
        k = _key(ev)
        if k in seen:
            continue
        seen.add(k)
        h = str(ev.get("computer") or "").strip()
        hosts.setdefault(h.lower(), _Host(h)).events.append((t, ev))
    rows, points = [], []
    for hk, host in sorted(hosts.items()):
        host.events.sort(key=lambda x: (x[0], _int(x[1].get("record_id"), 0) or 0))
        evs = [e for _, e in host.events]
        power = _power_rows(host, evs)
        screen = _screen_rows(host, power)
        _flag_conflicts(sorted(screen, key=_order))
        mine = power + screen + _lock_rows(host)
        _clock_checks(host, mine)
        rows.extend(mine)
        points.extend(_points(host))
    rows.sort(key=lambda r: (r["host"].lower(), r["layer"] != "Power", _order(r)))
    points.sort(key=lambda p: (p["host"].lower(), p["time"]))
    return {"hosts": sorted({h.name for h in hosts.values()}, key=str.lower), "rows": rows, "points": points}


def _order(r):
    """Chronological; a period with an unknown start (it ends at T) before one starting at T."""
    return (r["start"] or r["end"] or datetime.max, r["start"] is not None)


def _row(host, layer, state, start, end, started_by, ended_by, start_ev=None, end_ev=None, notes=()):
    return {"host": host.name, "layer": layer, "state": state, "start": start, "end": end,
            "duration": (end - start) if start is not None and end is not None else None,
            "started_by": started_by, "ended_by": ended_by, "start_ev": start_ev, "end_ev": end_ev,
            "notes": "; ".join(n for n in notes if n)}


def _find(host, label, lo, hi, slack=timedelta(seconds=2)):
    """The event carrying *label* (e.g. "Kernel-General 12") logged in [lo, hi]."""
    first = label.split(" + ")[0]
    for t, ev in host.events:
        if lo - slack <= t <= hi + slack and _label(ev) == first:
            return ev
    return None


def _window_note(what, lo, hi):
    return "" if lo == hi else f"{what} logged between {_fmt(lo)} and {_fmt(hi)}"


def _fmt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") + (f".{d.microsecond:06d}".rstrip("0") if d.microsecond else "") \
        + " UTC" if d else "?"


# ── power: on / off / sleep / hibernate / modern standby ─────────────────────

def _low_power(host):
    """Sleep / hibernate rows from Power-Troubleshooter 1, Kernel-Power 566 and 42."""
    out = []
    pts = [(t, e) for t, e in host.events if _prov(e) == PT]
    dozes = []
    for t, e in pts:
        d = _data(e)
        a, b = _dt(d.get("SleepTime")), _dt(d.get("WakeTime"))
        if a is None or b is None:
            continue
        if b <= a:
            if _int(d.get("WakeSourceType")) == 3 or "doze" in str(d.get("WakeSourceText") or "").lower():
                dozes.append((a, e))
            continue
        tgt = _int(d.get("TargetState"))
        state = "Hibernate" if tgt == 5 else "Sleep" if tgt in (1, 2, 3, 4) else f"Low power (target state {tgt})"
        src = str(d.get("WakeSourceText") or "").strip()
        wake = _code(WAKE_SOURCE, d.get("WakeSourceType")) + (f": {src}" if src else "")
        out.append(_row(host, "Power", state, a, b, "Power-Troubleshooter 1 (SleepTime)",
                        "Power-Troubleshooter 1 (WakeTime)", e, e, [f"Woken by {wake}"]))
    entries = [(t, e) for t, e in host.events
               if (_prov(e) == KP and _int(e.get("event_id")) == 566
                   and _int(_data(e).get("NextSessionType")) == 3)
               or (_prov(e) == KP and _int(e.get("event_id")) == 42)]
    # A sleep that turned into hibernation: the sleep part, before the doze.
    for doze_t, doze_ev in dozes:
        hib = next((r for r in out if r["state"] == "Hibernate" and abs(r["start"] - doze_t) <= timedelta(seconds=2)),
                   None)
        prev_end = max((r["end"] for r in out if r["end"] <= doze_t - timedelta(seconds=2)), default=None)
        cands = [(t, e) for t, e in entries if t < doze_t and (prev_end is None or t > prev_end)]
        st, sev = cands[0] if cands else (None, None)
        notes = ["the sleep turned into hibernation"]
        if st is None:
            notes.append("the moment it went to sleep is not logged")
        out.append(_row(host, "Power", "Sleep", st, doze_t, _label(sev) if sev else "Unavailable",
                        "Power-Troubleshooter 1 (S4 Doze to Hibernate)", sev, doze_ev, notes))
        if hib is not None:
            hib["notes"] = "; ".join(x for x in ("after sleep", hib["notes"]) if x)

    def covered(t):
        return any(r["start"] is not None and r["start"] - _TRANSITION <= t <= r["end"] + _TRANSITION
                   for r in out if r["end"] is not None)
    # Kernel-Power 566 low-power sessions no Power-Troubleshooter event covers.
    for t, e in host.events:
        if _prov(e) == KP and _int(e.get("event_id")) == 566 and _int(_data(e).get("PreviousSessionType")) == 3:
            dur = timedelta(microseconds=_int(_data(e).get("PreviousSessionDurationInUs"), 0) or 0)
            a = t - dur
            if covered(a) or covered(t):
                continue
            k42 = next((x for x in host.events if _prov(x[1]) == KP and _int(x[1].get("event_id")) == 42
                        and abs(x[0] - a) <= _TRANSITION), None)
            tgt = _int(_data(k42[1]).get("TargetState")) if k42 else None
            state = "Hibernate" if tgt == 5 else "Sleep" if tgt in (1, 2, 3, 4) else "Sleep or hibernate"
            out.append(_row(host, "Power", state, a, t, "Kernel-Power 566 (session length)", "Kernel-Power 566",
                            k42[1] if k42 else e, e, ["no Power-Troubleshooter 1 for this sleep"]))
    # Going to sleep with no logged wake time.
    for t, e in host.events:
        if _prov(e) == KP and _int(e.get("event_id")) == 42 and not covered(t):
            d = _data(e)
            tgt = _int(d.get("TargetState"))
            state = "Hibernate" if tgt == 5 else "Sleep"
            k107 = next((x for x in host.events if x[0] >= t and _prov(x[1]) == KP
                         and _int(x[1].get("event_id")) == 107), None)
            notes = ["wake time not logged (no Power-Troubleshooter 1 or Kernel-Power 566)"]
            if k107:
                notes.append(f"Kernel-Power 107 (resumed) was written at {_fmt(k107[0])}, but it carries the "
                             "clock from before the sleep, so it is not used as the wake time")
            out.append(_row(host, "Power", state, t, None, "Kernel-Power 42", "Unavailable", e, None, notes))
    return out


def _modern_standby(host):
    out, open_ = [], None
    for t, e in host.events:
        if _prov(e) != KP:
            continue
        eid = _int(e.get("event_id"))
        if eid == 506:
            if open_ is not None:
                out.append(_row(host, "Power", "Modern Standby", open_[0], None, "Kernel-Power 506",
                                "Unavailable", open_[1], None, ["no exit (507) logged before the next entry"]))
            open_ = (t, e)
        elif eid == 507 and open_ is not None:
            out.append(_row(host, "Power", "Modern Standby", open_[0], t, "Kernel-Power 506", "Kernel-Power 507",
                            open_[1], e))
            open_ = None
    if open_ is not None:
        out.append(_row(host, "Power", "Modern Standby", open_[0], None, "Kernel-Power 506", "Unavailable",
                        open_[1], None, ["no exit (507) logged"]))
    return out


def _power_rows(host, evs):
    hp = HostPower(evs)
    restarts = hp.restarts.get(host.name.strip().lower(), [])
    low = _low_power(host) + _modern_standby(host)
    off, on = [], []
    shutdowns_after = []
    if restarts:
        last_hi = restarts[-1]["boot"][1]
        from evtx_tool.analysis.host_power import classify
        shutdowns_after = sorted((c for c in (classify(e) for e in evs) if c and c[0] == "shutdown"
                                  and c[1] > last_hi), key=lambda c: c[2])
    for i, r in enumerate(restarts):
        b_lo, b_hi, b_lbl = r["boot"]
        b_ev = _find(host, b_lbl, b_lo, b_hi)
        sd, ux = r["shutdown"], r["unexpected"]
        notes = [_window_note("start", b_lo, b_hi)]
        bt = _boot_type(host, b_lo, b_hi)
        if bt:
            notes.append(f"boot type {bt}")
        if sd:
            s_lo, s_hi, s_lbl = sd
            off.append(_row(host, "Power", "Shut down", s_hi, b_lo, s_lbl, b_lbl,
                            _find(host, s_lbl, s_lo, s_hi), b_ev,
                            [_window_note("shutdown", s_lo, s_hi)] + notes))
        elif ux:
            txt = _crash_text(host, b_lo)
            off.append(_row(host, "Power", "Off (unexpected shutdown)", None, b_lo, "Unavailable", b_lbl,
                            None, b_ev,
                            [f"Windows reported an unexpected shutdown at the next start ({ux})"
                             + (f"; it gives the time as \"{txt}\" (that machine's local time)" if txt else "")
                             + "; the moment it stopped is not in these events"] + notes))
        elif i > 0:
            off.append(_row(host, "Power", "Off", None, b_lo, "Unavailable", b_lbl, None, b_ev,
                            ["no shutdown is logged before this start (logs missing, logging stopped, "
                             "or a power loss Windows did not report)"] + notes))
        # On: from this start to the next shutdown.  With no shutdown logged
        # before the next start, it stopped at an unknown moment before that
        # start (never later: it once swallowed every later period).
        nxt_boot = restarts[i + 1]["boot"][0] if i + 1 < len(restarts) else None
        if i + 1 < len(restarts):
            nsd = restarts[i + 1]["shutdown"]
            end, end_lbl, end_ev = ((nsd[0], nsd[2], _find(host, nsd[2], nsd[0], nsd[1])) if nsd
                                    else (None, "Unavailable", None))
        elif shutdowns_after:
            c = shutdowns_after[0]
            end, end_lbl, end_ev = c[1], c[3], _find(host, c[3], c[1], c[2])
        else:
            end, end_lbl, end_ev = None, "Unavailable", None
        if end is not None:
            note = ""
        elif nxt_boot is not None:
            note = f"it stopped without a logged shutdown, before the next start at {_fmt(nxt_boot)}"
        else:
            note = "no later shutdown is logged"
        on.append((b_lo, b_lbl, b_ev, end, end_lbl, end_ev, note, end if end is not None else nxt_boot))
    if shutdowns_after:
        c = shutdowns_after[-1]
        off.append(_row(host, "Power", "Shut down", c[2], None, c[3], "Unavailable",
                        _find(host, c[3], c[1], c[2]), None, ["no later start is logged"]))
    # Before the first logged start (or with none at all) the machine is
    # still proven running from each logged wake.
    if restarts:
        b0 = restarts[0]["boot"][0]
        sd0 = restarts[0]["shutdown"]
        on.insert(0, (None, None, None, sd0[0] if sd0 else None, sd0[2] if sd0 else "Unavailable",
                      _find(host, sd0[2], sd0[0], sd0[1]) if sd0 else None,
                      "" if sd0 else f"it stopped without a logged shutdown, before the start at {_fmt(b0)}",
                      sd0[0] if sd0 else b0))
    else:
        on.append((None, None, None, None, "Unavailable", None, "no start or shutdown is logged", None))
    # Split each on-period around the low-power periods inside it.
    out = []
    for start, s_lbl, s_ev, end, e_lbl, e_ev, note, bound in on:
        cur, cur_lbl, cur_ev = start, s_lbl, s_ev
        inside = sorted((r for r in low if r["start"] is not None and (start is None or r["start"] >= start)
                         and (bound is None or r["start"] < bound)), key=lambda r: r["start"])
        for r in inside:
            # After a sleep with no logged wake, the machine is next proven
            # running at a later logged wake (it once stopped here for good).
            if cur is not None and r["start"] > cur:
                out.append(_row(host, "Power", "On", cur, r["start"], cur_lbl, r["started_by"], cur_ev,
                                r["start_ev"]))
            if r["end"] is None:
                cur = None
                continue
            if cur is None or r["end"] > cur:
                cur, cur_lbl, cur_ev = r["end"], r["ended_by"], r["end_ev"]
        # Never past this period's own end or the next start (a wake logged
        # after the next start belongs to that start, not to this one).
        if cur is not None and (end is None or end > cur) and (bound is None or cur < bound):
            out.append(_row(host, "Power", "On", cur, end, cur_lbl, e_lbl, cur_ev, e_ev, [note]))
    rows = sorted(out + off + low, key=_order)
    _flag_conflicts(rows)
    for r in rows:                       # a period the events place across a logged start
        if r["start"] is None or r["end"] is None:
            continue
        for x in restarts:
            b = x["boot"][0]
            if r["start"] + timedelta(seconds=1) < b < r["end"] - timedelta(seconds=1):
                r["notes"] = "; ".join(n for n in (r["notes"], f"a start is logged at {_fmt(b)} inside this "
                                                   "period: the logged events disagree") if n)
    return rows


def _flag_conflicts(rows):
    """Periods the events place on top of each other: both stay, both say so."""
    known = [r for r in rows if r["start"] is not None and r["end"] is not None]
    for i, a in enumerate(known):
        for b in known[i + 1:]:
            if b["start"] >= a["end"] - timedelta(seconds=1):
                break
            if b["end"] <= a["start"] + timedelta(seconds=1):
                continue
            for x, y in ((a, b), (b, a)):
                x["notes"] = "; ".join(n for n in (x["notes"], f"overlaps {y['state']} from {_fmt(y['start'])} "
                                                   f"to {_fmt(y['end'])}: the logged events disagree") if n)


_CLOCK_SLACK = timedelta(minutes=2)       # the correction Windows makes just after a wake
_CLOCK_MIN = timedelta(seconds=60)        # smaller changes are routine time synchronisation


def _clock_changes(host):
    out = []
    for t, e in host.events:
        d = _data(e)
        if _prov(e) == KG and _int(e.get("event_id")) == 1:
            a, b = _dt(d.get("OldTime")), _dt(d.get("NewTime"))
        elif str(e.get("channel") or "").lower() == "security" and _int(e.get("event_id")) == 4616:
            a, b = _dt(d.get("PreviousTime")), _dt(d.get("NewTime"))
        else:
            continue
        if a is not None and b is not None and abs(b - a) >= _CLOCK_MIN:
            out.append((t, b - a, _label(e)))
    return out


def _uptime(e):
    """EventLog 6013: Windows' uptime in seconds (its 5th parameter), else None."""
    p = _params(e)
    return _int(p[4]) if len(p) > 4 else None


def _clock_checks(host, rows):
    """A length measured with a clock that was moved inside the period is not a length."""
    # The correction Windows makes on waking is written with the clock that
    # stood still during the sleep, so its time falls inside the sleep: it is
    # the resume itself, not a change of the clock while running (every
    # Hibernate row on the test logs was wrongly made Unavailable by it).
    asleep = [(r["start"], r["end"] + _CLOCK_SLACK) for r in rows
              if r["layer"] == "Power" and r["state"] in ("Sleep", "Hibernate", "Sleep or hibernate")
              and r["start"] is not None and r["end"] is not None]
    changes = [c for c in _clock_changes(host) if not any(a <= c[0] <= b for a, b in asleep)]
    ups =[(t, _uptime(e), e) for t, e in host.events if _prov(e) == "eventlog" and _int(e.get("event_id")) == 6013]
    for r in rows:
        if r["duration"] is None:
            continue
        lo, hi = r["start"] + _CLOCK_SLACK, r["end"]
        moved = [c for c in changes if lo < c[0] < hi]
        why = [f"the system clock was changed by {'+' if c[1] >= timedelta(0) else '-'}{fmt_secs(abs(c[1]))} "
               f"at {_fmt(c[0])} ({c[2]})" for c in moved]
        if r["state"] == "On" and r["started_by"].startswith(("Kernel-General 12", "EventLog 6005", "Security 4608")):
            for t, up, _e in ups:
                if up is not None and r["start"] < t <= r["end"]:
                    clock = (t - r["start"]).total_seconds()
                    if abs(clock - up) > 600:
                        why.append(f"Windows' uptime counter (EventLog 6013 at {_fmt(t)}) says "
                                   f"{fmt_secs(up)} since the start, the clock says {fmt_secs(clock)}")
                        break
        if why:
            r["notes"] = "; ".join(n for n in (r["notes"], f"length Unavailable as measured by the clock "
                                               f"({r['end'] - r['start']} by the clock): " + "; ".join(why)) if n)
            r["duration"] = None


def _boot_type(host, lo, hi):
    for t, e in host.events:
        if _prov(e) == KB and _int(e.get("event_id")) == 27 and lo - timedelta(minutes=5) <= t <= hi + timedelta(minutes=5):
            return _code(BOOT_TYPE, _data(e).get("BootType"))
    return ""


def _crash_text(host, boot_t):
    for t, e in host.events:
        if _prov(e) == "eventlog" and _int(e.get("event_id")) == 6008 and abs(t - boot_t) <= timedelta(minutes=10):
            p = _params(e)
            return " ".join(x for x in p[:2] if x).strip()
    return ""


# ── screen (Kernel-Power 566) ────────────────────────────────────────────────

def _screen_rows(host, power):
    """Screen on / off periods.  Consecutive 566 records are the transition
    moments, so each one ends a period the previous one started; the session
    length Windows gives is used where there is no previous transition (the
    first after a start or a wake) and otherwise only checked against."""
    s566 = [(t, e) for t, e in host.events if _prov(e) == KP and _int(e.get("event_id")) == 566]

    def length(e):
        return timedelta(microseconds=_int(_data(e).get("PreviousSessionDurationInUs"), 0) or 0)

    def chained(i):
        """True when 566 number i continues the session the one before it started."""
        if i == 0:
            return False
        (tp, ep), (t, e) = s566[i - 1], s566[i]
        return (_int(_data(ep).get("NextSessionType")) == _int(_data(e).get("PreviousSessionType"))
                and abs((t - tp) - length(e)) <= timedelta(seconds=60))

    raw = []
    for i, (t, e) in enumerate(s566):
        d = _data(e)
        pv, nx = _int(d.get("PreviousSessionType")), _int(d.get("NextSessionType"))
        reason = _code(SESSION_REASON, d.get("Reason"))
        if pv != 3:                      # sleep is in the Power layer
            notes = [f"ended: {reason}"]
            if chained(i):
                a, by, sev = s566[i - 1][0], "Kernel-Power 566", s566[i - 1][1]
                gap = abs((t - a) - length(e))
                if gap > timedelta(seconds=5):
                    notes.append(f"Windows gives the session length as {fmt_secs(length(e))}, "
                                 f"{fmt_secs(gap)} different from the time between the transitions")
            else:
                a, by, sev = t - length(e), "Kernel-Power 566 (session length)", e
            raw.append({"a": a, "b": t, "type": pv, "sev": sev, "eev": e, "by": by,
                        "end_by": "Kernel-Power 566", "notes": notes})
        # The session that follows, when no later 566 continues it (a shutdown
        # or a sleep came first).
        if nx in (0, 1) and not (i + 1 < len(s566) and chained(i + 1)):
            nxt_t = s566[i + 1][0] if i + 1 < len(s566) else None
            # The first power change after it: a period starting later, or one
            # whose start is unknown but which ends later (a crash before a start).
            cands = [(r["start"] if r["start"] is not None else r["end"], r) for r in power
                     if r["state"] != "On" and ((r["start"] is not None and r["start"] > t)
                                                or (r["start"] is None and r["end"] is not None and r["end"] > t))]
            cands = [c for c in cands if nxt_t is None or c[0] <= nxt_t]
            stop = min(cands, key=lambda c: c[0])[1] if cands else None
            if stop is not None and stop["start"] is not None:
                b, eev, end_by, extra = stop["start"], stop["start_ev"], stop["started_by"], []
            elif stop is not None:
                b, eev, end_by = None, None, "Unavailable"
                extra = [f"it ended at an unknown time before the start at {_fmt(stop['end'])} "
                         f"({stop['state']})"]
            else:
                b, eev, end_by, extra = None, None, "Unavailable", ["no later screen or power change is logged"]
            raw.append({"a": t, "b": b, "type": nx, "sev": e, "eev": eev, "by": "Kernel-Power 566",
                        "end_by": end_by, "notes": [f"started: {reason}"] + extra})
    # Back-to-back sessions of the same type (battery-saver changes) are one period.
    merged = []
    for r in sorted(raw, key=lambda r: r["a"]):
        m = merged[-1] if merged else None
        if m and m["type"] == r["type"] and m["b"] is not None and abs(r["a"] - m["b"]) <= timedelta(seconds=2):
            m["b"], m["eev"], m["end_by"] = r["b"], r["eev"], r["end_by"]
            m["notes"] = m["notes"] + r["notes"]
            continue
        merged.append(dict(r))
    out = []
    for r in merged:
        typ = r["type"]
        state = (f"{SESSION_TYPE[typ]} (session type {typ})" if typ in SESSION_TYPE
                 else f"Session type {typ} (meaning not known)")
        out.append(_row(host, "Screen", state, r["a"], r["b"], r["by"], r["end_by"], r["sev"], r["eev"],
                        r["notes"]))
    return out


# ── lock / screen saver (Security) ───────────────────────────────────────────

def _lock_rows(host):
    out = []
    for begin, finish, state in ((4800, 4801, "Locked"), (4802, 4803, "Screen saver")):
        open_: dict = {}
        for t, e in host.events:
            if str(e.get("channel") or "").lower() != "security":
                continue
            eid = _int(e.get("event_id"))
            lid = str(_data(e).get("TargetLogonId") or _data(e).get("SessionId") or "")
            user = str(_data(e).get("TargetUserName") or "")
            if eid == begin:
                if lid in open_:
                    pt, pe = open_.pop(lid)
                    out.append(_row(host, "Lock", state, pt, None, f"Security {begin}", "Unavailable", pe, None,
                                    [f"user {user}" if user else "", f"no {finish} logged before the next {begin}"]))
                open_[lid] = (t, e)
            elif eid == finish and lid in open_:
                pt, pe = open_.pop(lid)
                out.append(_row(host, "Lock", state, pt, t, f"Security {begin}", f"Security {finish}", pe, e,
                                [f"user {user}" if user else ""]))
        for pt, pe in open_.values():
            u = str(_data(pe).get("TargetUserName") or "")
            out.append(_row(host, "Lock", state, pt, None, f"Security {begin}", "Unavailable", pe, None,
                            [f"user {u}" if u else "", f"no {finish} logged"]))
    return out


# ── moments ──────────────────────────────────────────────────────────────────

def _points(host):
    out = []
    for t, e in host.events:
        p, eid, d = _prov(e), _int(e.get("event_id")), _data(e)
        what, det = None, ""
        if p == KG and eid == 12:
            what, det = "Windows started", f"StartTime {d.get('StartTime', 'not given')}"
        elif p == KG and eid == 13:
            what, det = "Windows shutting down", f"StopTime {d.get('StopTime', 'not given')}"
        elif p == KG and eid == 1:
            a, b = _dt(d.get("OldTime")), _dt(d.get("NewTime"))
            what = "System time changed"
            det = (f"from {_fmt(a)} to {_fmt(b)} ({'+' if b >= a else '-'}{fmt_secs(abs(b - a))})"
                   if a and b else f"OldTime {d.get('OldTime')}, NewTime {d.get('NewTime')}")
        elif p == KP and eid == 41:
            what, det = "Unexpected shutdown reported (Kernel-Power 41)", \
                "the previous run ended without a clean shutdown"
        elif p == KP and eid == 42:
            what = "Going to sleep"
            det = f"reason {_code(SLEEP_REASON, d.get('Reason'))}, target state {d.get('TargetState', '?')}"
        elif p == KP and eid == 107:
            what, det = "Resumed (Kernel-Power 107)", \
                "written with the clock from before the sleep; see the Power-Troubleshooter wake time"
        elif p == KP and eid == 105:
            what = "Power source changed"
            ac = str(d.get("AcOnline", "")).lower()
            det = "on AC power" if ac == "true" else "on battery" if ac == "false" else f"AcOnline {d.get('AcOnline')}"
        elif p == KP and eid == 109:
            what = "Shutdown transition started"
            det = (f"action {_code(POWER_ACTION, d.get('ShutdownActionType'))}, "
                   f"reason {_code(ACTION_REASON, d.get('ShutdownReason'))}")
        elif p == KP and eid in (506, 507):
            what = "Entering Modern Standby" if eid == 506 else "Exiting Modern Standby"
            det = f"reason code {d.get('Reason', '?')}"
        elif p == KP and eid == 566:
            what = "Screen / session change"
            pv, nx = _int(d.get("PreviousSessionType")), _int(d.get("NextSessionType"))
            det = (f"{SESSION_TYPE.get(pv, f'type {pv}')} -> {SESSION_TYPE.get(nx, f'type {nx}')}, "
                   f"reason {_code(SESSION_REASON, d.get('Reason'))}")
        elif p == PT and eid == 1:
            src = str(d.get("WakeSourceText") or "").strip()
            what = "Woke up"
            det = (f"slept {d.get('SleepTime')} to {d.get('WakeTime')}, wake source "
                   f"{_code(WAKE_SOURCE, d.get('WakeSourceType'))}" + (f": {src}" if src else ""))
        elif p == KB and eid == 27:
            what, det = "Boot type", _code(BOOT_TYPE, d.get("BootType"))
        elif p == "eventlog" and eid == 6005:
            what, det = "Event log service started", "at start-up"
        elif p == "eventlog" and eid == 6006:
            what, det = "Event log service stopped", "clean shutdown"
        elif p == "eventlog" and eid == 6013:
            up = _uptime(e)
            what, det = "System uptime reported", (f"{fmt_secs(up)} since the start (Windows' uptime counter)"
                                                   if up is not None else "uptime not given")
        elif p == "eventlog" and eid == 6008:
            what, det = "Previous shutdown was unexpected", \
                "Windows gives: " + " ".join(x for x in _params(e)[:2] if x)
        elif p == "user32" and eid == 1074:
            x = _params(e) + [""] * 7
            what = "Shutdown or restart requested"
            det = f"by process {x[0]}, user {x[6]}, type {x[4]}, reason {x[2]} ({x[3]})" + \
                (f", comment {x[5]}" if x[5] else "")
        elif p == WL and eid in (7001, 7002):
            what = "User logon notification" if eid == 7001 else "User logoff notification"
            det = f"user SID {d.get('UserSid', '?')}, session {d.get('TSId', '?')}"
        elif p == DP and eid == 100:
            what = "Boot performance"
            det = (f"boot from {d.get('BootStartTime')} to {d.get('BootEndTime')} "
                   f"({_int(d.get('BootTime'), 0):,} ms)")
        elif p == DP and eid == 200:
            what = "Shutdown performance"
            det = (f"shutdown from {d.get('ShutdownStartTime')} to {d.get('ShutdownEndTime')} "
                   f"({_int(d.get('ShutdownTime'), 0):,} ms)")
        elif str(e.get("channel") or "").lower() == "security":
            names = {1100: "Event logging service shut down", 4608: "Windows starting up",
                     4609: "Windows shutting down", 4616: "System time changed", 4800: "Workstation locked",
                     4801: "Workstation unlocked", 4802: "Screen saver started", 4803: "Screen saver dismissed",
                     4624: "Unlocked (logon type 7)"}
            what = names.get(eid)
            if eid == 4616:
                det = f"from {d.get('PreviousTime')} to {d.get('NewTime')}, by {d.get('ProcessName', '?')}"
            elif eid in (4800, 4801, 4802, 4803, 4624):
                det = f"user {d.get('TargetDomainName', '')}\\{d.get('TargetUserName', '')}".replace("\\\\", "\\")
        if what:
            out.append({"host": host.name, "time": t, "what": what, "details": det, "evidence": _label(e),
                        "ev": e})
    return out
