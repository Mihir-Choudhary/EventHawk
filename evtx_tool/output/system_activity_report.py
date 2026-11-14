"""System Activity as one self-contained HTML report.

User request (2026-11-14): "a beautiful html report ... for system analytics,
properly showing every raw event and everything", fast to search.

The report is a single offline file: no network requests (a Content Security
Policy forbids them), no external fonts or scripts, so it can be attached to a
case and opened on an air-gapped examiner machine.  It holds:

  * an overview: computers, log span, totals per layer (Power / Screen / Lock)
  * a day-by-day timeline (24 h strip per day; power, screen and lock lanes,
    moment ticks)
  * every period, every moment and every raw event the analysis read, each
    searchable, sortable, and open in an inspector with all of its fields
  * links both ways: a period names its start / end evidence events, an
    event lists the periods and moments it proves

Times are UTC, like the System Activity window; tables show the analyst's
display precision, the inspector shows exact values.  Event text from the
logs is attacker-controllable: the page never inserts it as markup (every
value is escaped) and the embedded JSON cannot close its <script> element.

Performance: tables are virtualised (only the visible rows exist in the
DOM), the search index is built once on first use, and typing is debounced,
so tens of thousands of rows filter in milliseconds.
"""
from __future__ import annotations

import html as _html
import json
import os
from datetime import datetime, timedelta, timezone

from evtx_tool.analysis.host_power import _dt, fmt_secs
from evtx_tool.analysis import system_activity as _sa
from evtx_tool.analysis.system_activity import _int, _key, _label, _prov
from evtx_tool.output.exporters import event_data_text

COVERAGE = ("Screen on/off comes from Kernel-Power 566 (Windows 10 2004 and later, Windows 11); its session "
            "types (0 screen on, 1 screen off, 3 sleep) are inferred from the logs, not documented by Microsoft. "
            "Lock and screen saver need the Security policy \"Audit Other Logon/Logoff Events\", off by default. "
            "A time the events do not prove reads Unavailable.")

SHORT_PERIOD_US = 1_000_000

# (label, event key) for the System part of the inspector, in reading order.
_SYSTEM_FIELDS = (("Provider", "provider"), ("Event ID", "event_id"), ("Level", "level_name"),
                  ("Channel", "channel"), ("Computer", "computer"), ("Event record ID", "event_record_id"),
                  ("Task", "task"), ("Opcode", "opcode"), ("Keywords", "keywords"),
                  ("Version", "version"), ("Process ID", "process_id"), ("Thread ID", "thread_id"),
                  ("User SID", "user_id"), ("Provider GUID", "provider_guid"),
                  ("Correlation ID", "correlation_id"), ("Event source", "event_source_name"),
                  ("Qualifiers", "qualifiers"))

# Field meanings shown beside the raw value in the inspector, from the same
# code tables the analysis uses (the value itself is never changed).
_MEANINGS = {
    (_sa.KP, 42): {"Reason": (_sa.SLEEP_REASON, "")},
    (_sa.KP, 109): {"ShutdownActionType": (_sa.POWER_ACTION, ""), "ShutdownReason": (_sa.ACTION_REASON, "")},
    (_sa.KP, 566): {"Reason": (_sa.SESSION_REASON, ""),
                    "PreviousSessionType": (_sa.SESSION_TYPE, " (inferred from the logs)"),
                    "NextSessionType": (_sa.SESSION_TYPE, " (inferred from the logs)")},
    (_sa.PT, 1): {"WakeSourceType": (_sa.WAKE_SOURCE, "")},
    (_sa.KB, 27): {"BootType": (_sa.BOOT_TYPE, " (community reference)")},
    (_sa.KG, 1): {"Reason": (_sa.CLOCK_REASON, "")},
}


def _meaning(ev, field, value) -> str:
    m = _MEANINGS.get((_prov(ev), _int(ev.get("event_id"))), {}).get(field)
    if not m:
        return ""
    n = _int(value)
    return (m[0][n] + m[1]) if n is not None and n in m[0] else ""


_STATE_ORDER = ["On", "Screen on", "Screen off", "Sleep", "Hibernate", "Sleep or hibernate", "Low power",
                "Modern Standby", "Locked", "Screen saver", "Shut down", "Off"]


def fmt_time(d, digits: int) -> str:
    if d is None:
        return "Unavailable"
    s = d.strftime("%Y-%m-%d %H:%M:%S")
    return s + (f".{d.microsecond:06d}"[:digits + 1] if digits else "")


def fmt_total(us: int) -> str:
    secs = us / 1_000_000
    if secs < 60:
        return f"{secs:.1f} s" if secs < 10 else f"{int(secs)} s"
    mins = int(secs // 60)
    if mins < 60:
        return f"{mins} m {int(secs % 60):02d} s"
    h, m = divmod(mins, 60)
    return f"{h} h {m:02d} m"


def fmt_duration(us, digits: int) -> str:
    if us is None:
        return "Unavailable"
    if digits < 6:
        step = 10 ** (6 - digits)
        us = us - us % step
    return fmt_secs(timedelta(microseconds=us))


_EPOCH = datetime(1970, 1, 1)


def _us(d) -> int | None:
    """Naive-UTC datetime -> epoch microseconds (exact; JSON / JS safe)."""
    if d is None:
        return None
    if d.tzinfo is not None:
        d = d.astimezone(timezone.utc).replace(tzinfo=None)
    td = d - _EPOCH
    return (td.days * 86400 + td.seconds) * 1_000_000 + td.microseconds


def _td_us(td) -> int | None:
    if td is None:
        return None
    return (td.days * 86400 + td.seconds) * 1_000_000 + td.microseconds


def _text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    return event_data_text(v) if isinstance(v, (dict, list, tuple)) else str(v)


def _base_state(state: str) -> str:
    return str(state).split(" (")[0]


def _display_path(f: str) -> str:
    """A log file as one clean, full path.  A relative path with mixed
    separators (as given on the command line) read as a typo in an evidence
    report."""
    if not f:
        return ""
    try:
        return os.path.normpath(os.path.abspath(f))
    except (OSError, ValueError):
        return f


def _describe(ev) -> str:
    try:
        from evtx_tool.analysis.event_descriptions import get_event_description
        return get_event_description(ev) or ""
    except Exception:                                             # noqa: BLE001
        return ""


def build_payload(result: dict, events=None, digits: int = 0, generated: datetime | None = None) -> dict:
    """Everything the page shows, as compact JSON-ready lists."""
    from evtx_tool import __version__
    hosts = list(result.get("hosts", []))
    host_i = {h: i for i, h in enumerate(hosts)}

    def hi(name):
        if name not in host_i:
            host_i[name] = len(hosts)
            hosts.append(name)
        return host_i[name]

    # Raw events: the ones the analysis read, plus any evidence event that
    # was not passed in (so every link resolves).
    raw = list(events or [])
    seen_ids = {id(e) for e in raw}
    for r in result.get("rows", []):
        for k in ("start_ev", "end_ev"):
            e = r.get(k)
            if e is not None and id(e) not in seen_ids:
                seen_ids.add(id(e))
                raw.append(e)
    for p in result.get("points", []):
        e = p.get("ev")
        if e is not None and id(e) not in seen_ids:
            seen_ids.add(id(e))
            raw.append(e)
    dated = []
    for e in raw:
        t = _dt(e.get("timestamp"))
        dated.append((t, e))
    dated.sort(key=lambda x: (x[0] is None, x[0] or _EPOCH, _int(x[1].get("record_id"), 0) or 0))

    files: list[str] = []
    file_i: dict = {}
    ev_index: dict = {}
    out_events = []
    first_of: dict = {}                  # content identity -> index of its first copy
    nth: dict = {}
    for t, e in dated:
        f = str(e.get("source_file") or "")
        if f not in file_i:
            file_i[f] = len(files)
            files.append(_display_path(f))
        # Copies of the same log count once (the analysis's own rule).
        try:
            c = _key(e)
        except Exception:                                         # noqa: BLE001
            c = (id(e),)
        n = nth.get((f, c), 0)
        nth[(f, c)] = n + 1
        dup = first_of.get((c, n))
        idx = len(out_events)
        if dup is None:
            first_of[(c, n)] = idx
        ev_index[id(e)] = idx
        # System fields as values in _SYSTEM_FIELDS order (labels once in
        # "meta"), None when absent: a third of the file size at 100k events.
        sysf = [None if e.get(k) is None or e.get(k) == "" else _text(e.get(k)) for _label_, k in _SYSTEM_FIELDS]
        while sysf and sysf[-1] is None:
            sysf.pop()
        data = e.get("event_data")
        dataf = []
        if isinstance(data, dict):
            for k, v in data.items():
                if k == "#attributes":
                    continue
                row = [str(k) if k != "#text" else "Data", _text(v)]
                note = _meaning(e, k, v)
                if note:
                    row.append(note)
                dataf.append(row)
        elif data not in (None, ""):
            dataf.append(["Data", _text(data)])
        out_events.append([
            _us(t), fmt_time(t, 6), hi(str(e.get("computer") or "").strip()), _label(e), _describe(e),
            file_i[f], _text(e.get("event_record_id") if e.get("event_record_id") not in (None, "")
                             else e.get("record_id")), -1 if dup is None else dup, sysf, dataf,
            fmt_time(t, digits)])

    def ref(e):
        return ev_index.get(id(e), -1) if e is not None else -1

    periods = []
    for r in result.get("rows", []):
        dur = _td_us(r.get("duration"))
        periods.append([
            hi(r["host"]), r["layer"], r["state"], _us(r.get("start")), _us(r.get("end")), dur,
            fmt_time(r.get("start"), digits), fmt_time(r.get("end"), digits), fmt_duration(dur, digits),
            fmt_secs(r["duration"]) if r.get("duration") is not None else "Unavailable",
            r.get("started_by") or "", r.get("ended_by") or "", r.get("notes") or "",
            ref(r.get("start_ev")), ref(r.get("end_ev")),
            fmt_time(r.get("start"), 6), fmt_time(r.get("end"), 6)])
    moments = []
    for p in result.get("points", []):
        moments.append([hi(p["host"]), _us(p.get("time")), fmt_time(p.get("time"), digits), p.get("what") or "",
                        p.get("details") or "", p.get("evidence") or "", ref(p.get("ev")),
                        fmt_time(p.get("time"), 6)])

    # Clock changes of a minute or more: [time, change (us), reason, event,
    # computer, made on waking].  A change at a wake (inside a sleep or within
    # the analysis's slack after it) is Windows catching up with the hardware
    # clock; one made while running moves every later timestamp.
    sleeps = [(r[0], r[3], r[4]) for r in periods
              if r[1] == "Power" and r[3] is not None and r[4] is not None
              and _base_state(r[2]) in ("Sleep", "Hibernate", "Sleep or hibernate", "Low power")]
    slack = int(_sa._CLOCK_SLACK.total_seconds() * 1_000_000)
    clock = []
    for t, e in dated:
        d = e.get("event_data") if isinstance(e.get("event_data"), dict) else {}
        if _prov(e) == _sa.KG and _int(e.get("event_id")) == 1:
            a, b = _dt(d.get("OldTime")), _dt(d.get("NewTime"))
        elif str(e.get("channel") or "").lower() == "security" and _int(e.get("event_id")) == 4616:
            a, b = _dt(d.get("PreviousTime")), _dt(d.get("NewTime"))
        else:
            continue
        idx = ev_index[id(e)]
        if a is None or b is None or t is None or out_events[idx][7] >= 0:
            continue
        delta = _td_us(b - a)
        if abs(delta) < 60_000_000:
            continue
        tu, h = _us(t), out_events[idx][2]
        wake = any(hh == h and s <= tu <= en + slack for hh, s, en in sleeps)
        if _prov(e) == _sa.KG:
            n = _int(d.get("Reason"))
            reason = (_sa.CLOCK_REASON.get(n, f"reason {d.get('Reason')}")
                      if d.get("Reason") not in (None, "") else "")
        else:
            reason = f"by {d.get('ProcessName') or 'an unnamed process'}"
        clock.append([tu, delta, reason, idx, h, wake])

    times = [e[0] for e in out_events if e[0] is not None]
    gen = generated or datetime.now(timezone.utc)
    return {
        "meta": {"version": __version__, "generated": gen.strftime("%Y-%m-%d %H:%M:%S UTC"),
                 "digits": digits, "coverage": COVERAGE,
                 "first": fmt_time(_EPOCH + timedelta(microseconds=min(times)), 0) if times else "",
                 "last": fmt_time(_EPOCH + timedelta(microseconds=max(times)), 0) if times else "",
                 "first_us": min(times) if times else None, "last_us": max(times) if times else None,
                 "short_us": SHORT_PERIOD_US, "sys": [lbl for lbl, _k in _SYSTEM_FIELDS]},
        "hosts": hosts, "files": files, "periods": periods, "moments": moments, "events": out_events,
        "order": _STATE_ORDER, "clock": clock,
    }


def _json_for_script(obj) -> str:
    # "<" is escaped everywhere so no value can close the <script> element
    # ("</script>") or open a comment; U+2028/9 are escaped for old parsers.
    s = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)
    return s.replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def render_html(result: dict, events=None, digits: int = 0, generated: datetime | None = None) -> str:
    payload = build_payload(result, events, digits, generated)
    hosts = [h or "(no computer name)" for h in payload["hosts"]]
    title = "System Activity" + (f" \u2014 {hosts[0]}" if len(hosts) == 1 else
                                 f" \u2014 {len(hosts)} computers" if hosts else "")
    from evtx_tool.output.system_activity_template import TEMPLATE
    # One pass each side of the data, so no log value can inject a placeholder.
    head, tail = TEMPLATE.split("__DATA__")
    head = head.replace("__TITLE__", _html.escape(title)).replace("__LOGO__", _logo_data_uri())
    return head + _json_for_script(payload) + tail


def _logo_data_uri() -> str:
    """The EventHawk logo, embedded (the page makes no network requests)."""
    import base64
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "resources", "images", "eventhawk_logo_report.png")
    try:
        with open(path, "rb") as fh:
            return "data:image/png;base64," + base64.b64encode(fh.read()).decode("ascii")
    except OSError:
        # 1x1 transparent PNG: the header still reads "EventHawk".
        return ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8"
                "AAAAASUVORK5CYII=")


def write_html_report(path: str, result: dict, events=None, digits: int = 0) -> dict:
    """Write the report; returns counts for the confirmation message."""
    doc = render_html(result, events, digits)
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(doc)
    os.replace(tmp, path)
    return {"periods": len(result.get("rows", [])), "moments": len(result.get("points", [])),
            "bytes": len(doc.encode("utf-8"))}


