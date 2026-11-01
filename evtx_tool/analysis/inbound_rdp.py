"""Evidence-bounded inbound session intervals, with no proximity-based merges.

An LSM SessionID and a Security logon LUID are different namespaces. A new
logon/reconnect always opens a row; a disconnect closes a connected interval,
not the lifetime of the Windows logon. Continuity is a reference, never a join.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import PureWindowsPath

LSM_IDS = frozenset({21, 22, 23, 24, 25, 39, 40, 41})
RCM_IDS = frozenset({261, 1149})


def _eid(event):
    try:
        return int(event.get("event_id") or 0)
    except (TypeError, ValueError):
        return 0


def is_inbound_event(event, fields):
    channel = str(event.get("channel") or "").casefold()
    eid = _eid(event)
    if "rdpclient" in channel:
        return False
    if "terminalservices" in channel:
        return eid in LSM_IDS | RCM_IDS
    return channel == "security" and (
        eid in (4778, 4779) or
        (eid in (4624, 4634) and str(fields(event).get("LogonType", "")) == "10")
    )


def _time(event):
    try:
        value = datetime.fromisoformat(str(event.get("timestamp") or "").strip().replace("Z", "+00:00"))
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def _host(event):
    return (str(event.get("computer") or "").strip().casefold()
            or str(event.get("source_file") or "").strip().casefold())


def _user(data, security):
    if not security:
        return str(data.get("User") or "").strip()
    name = str(data.get("TargetUserName") or data.get("AccountName") or "").strip()
    domain = str(data.get("TargetDomainName") or data.get("AccountDomain") or "").strip()
    return f"{domain}\\{name}" if domain and name and "\\" not in name else name


def build_inbound_sessions(events, fields):
    """Return rows and private continuation references for the dialog to number.

    The field adapter is shared with the browser so Normal and Arrow payload
    shapes receive identical treatment. No Qt, database, or file writes here.
    """
    selected = []
    copies = {}
    for event in events:
        eid = _eid(event)
        boot = ((str(event.get("channel") or "").casefold() == "security" and eid == 4608)
                or (eid == 12 and event.get("provider") == "Microsoft-Windows-Kernel-General"))
        if not boot and not is_inbound_event(event, fields):
            continue
        data = fields(event)
        # Require a host or source and a record ID before treating two inputs as
        # copies. Include the payload: conflicting exports are separate evidence.
        rid = event.get("record_id")
        identity = (_host(event), str(event.get("channel") or "").casefold(), eid,
                    # Identity uses all raw timestamp digits, independently of
                    # the datetime/display precision used to order intervals.
                    str(event.get("timestamp") or "").strip(), str(rid),
                    json.dumps(data, sort_keys=True, default=str))
        if _host(event) and rid is not None and identity in copies:
            copies[identity]["events"].append(event)
            continue
        record = dict(event=event, data=data, time=_time(event), boot=boot, events=[event])
        selected.append(record)
        if _host(event) and rid is not None:
            copies[identity] = record

    selected.sort(key=lambda r: (r["time"] or datetime.max.replace(tzinfo=timezone.utc),
                                  str(r["event"].get("channel") or ""),
                                  _record_id(r["event"]) or 0))
    rows = []
    active = {}
    disconnected = {}
    # Security 4624->4634 can measure a logon lifetime even with connection
    # gaps, but a 4778/4779 interval must never be merged into that lifetime.
    security_logons = {}

    def new(record, key, user, start=False, previous=None):
        row = dict(key=key, records=[], start=record if start else None, end=None,
                   user=user, flags=[], previous=previous, closed=False)
        rows.append(row)
        return row

    for record in selected:
        event, data, time = record["event"], record["data"], record["time"]
        host = _host(event)
        if record["boot"]:
            for mapping in (active, disconnected, security_logons):
                for key in list(mapping):
                    if key[0] == host:
                        mapping[key]["flags"].append("BOOT_BOUNDARY")
                        del mapping[key]
            continue
        eid = _eid(event)
        channel = str(event.get("channel") or "").casefold()
        security = channel == "security"
        lsm = "localsessionmanager" in channel
        user = _user(data, security)
        if security:
            namespace = "Security LUID"
            sid = str(data.get("LogonID") if eid in (4778, 4779) else data.get("TargetLogonId") or "").strip()
            if sid.casefold() in ("none", "0", "0x0", "-"):
                sid = ""
        elif lsm:
            namespace = "LSM SessionID"
            sid = str(data.get("SessionID") or data.get("TargetSession") or data.get("Session") or "").strip()
        else:
            namespace, sid = "Authentication / diagnostic", ""
        # A missing key/time is a separate observation, never a guessed pair.
        key = (host, namespace, sid)
        usable = bool(str(event.get("computer") or "").strip() and sid and time)
        start = (lsm and eid in (21, 25)) or (security and eid in (4624, 4778))
        end = (lsm and eid in (23, 24, 39, 40)) or (security and eid in (4634, 4779))
        reconnect = eid in (25, 4778)
        disconnect = eid in (24, 39, 40, 4779)
        logoff = eid in (23, 4634)
        mapping = security_logons if security and eid in (4624, 4634) else active
        previous = None
        if start:
            if usable and security and eid == 4624:
                prior = active.pop(key, None)
                if prior:
                    prior["flags"].append("NO_END_BEFORE_NEW_START")
            candidate = disconnected.pop(key, None) if usable else None
            if reconnect and candidate and user and candidate["user"].casefold() == user.casefold():
                previous = candidate
            if usable and key in mapping:
                mapping[key]["flags"].append("NO_END_BEFORE_NEW_START")
            row = new(record, key, user, True, previous)
            if usable:
                mapping[key] = row
        else:
            row = mapping.get(key) if usable else None
            # Domain-qualified identities are compared whole, not just username.
            mismatch = bool(row and user and row["user"] and user.casefold() != row["user"].casefold())
            if mismatch:
                row["flags"].append("IDENTITY_CONFLICT")
                mapping.pop(key, None)
                row = None
            if not row:
                row = new(record, key, user)
                if usable and not end and lsm and eid == 22:
                    mapping[key] = row
            if end:
                row["end"] = record
                row["closed"] = True
                if usable:
                    mapping.pop(key, None)
                    if disconnect:
                        # A later 39/40 diagnostic carries no user; it cannot
                        # replace a user-attributed 24 as the reconnect parent.
                        if user or key not in disconnected:
                            disconnected[key] = row
                    elif logoff:
                        disconnected.pop(key, None)
                        # A terminated LUID cannot retain an open connection
                        # interval that could consume a later disconnect.
                        if security:
                            active.pop(key, None)
                if mismatch:
                    row["flags"].append("IDENTITY_CONFLICT")
        row["records"].append(record)
        if not usable:
            row["flags"].append("MISSING_ID_HOST_OR_TIME")
        # 39/40 contain session numbers, not a peer IP. Never copy Source into
        # Remote Host: for 39 it is the disconnecting session's integer ID.
        if lsm and eid in (39, 40):
            row["flags"].append("DISCONNECT_DIAGNOSTIC")

    result = []
    rowmap = {}
    for row in rows:
        records = row["records"]
        a, b = row["start"], row["end"]
        at, bt = (a["time"] if a else None), (b["time"] if b else None)
        proved = bool(at and bt and bt >= at and "IDENTITY_CONFLICT" not in row["flags"])
        # SessionID matching without any user corroboration is disclosed; a
        # conflicting identity above always splits instead of closing a row.
        if proved and (not _user(a["data"], row["key"][1] == "Security LUID") or not _user(b["data"], row["key"][1] == "Security LUID")):
            row["flags"].append("USER_NOT_CORROBORATED")
        seconds = (bt-at).total_seconds() if proved else -1.0
        duration = "Unavailable"
        if proved:
            h, rem = divmod(int(seconds), 3600); m, s = divmod(rem, 60)
            duration = f"{h}h {m:02d}m {s:02d}s" if h else f"{m}m {s:02d}s" if m else f"{s}s"
        physical = [e for r in records for e in r["events"]]
        pairs = frozenset((str(e.get("source_file") or ""), _record_id(e)) for e in physical if _record_id(e) is not None)
        unfilterable = sum(_record_id(r["event"]) is None for r in records)
        flags = list(dict.fromkeys(row["flags"]))
        if unfilterable:flags.append(f"UNFILTERABLE_EVENTS:{unfilterable}")
        if any(str(r["data"].get("Address", "")).upper() == "LOCAL" for r in records):flags.append("LOCAL_CONSOLE")
        if any(str(r["data"].get("SessionName", "")).casefold() == "console" for r in records):flags.append("LOCAL_CONSOLE")
        remote = next((str(r["data"].get("Address") or r["data"].get("IpAddress") or r["data"].get("ClientAddress") or "").strip() for r in records if r["data"].get("Address") or r["data"].get("IpAddress") or r["data"].get("ClientAddress")), "")
        if remote.upper() in ("LOCAL", "-", "::1", "127.0.0.1"):remote = ""
        display = str(records[0]["event"].get("computer") or "").strip() or "(unknown)"
        label = lambda r: f"EID {_eid(r['event'])} ({row['key'][1]})"
        proof = f"Start: {label(a) if a else 'not logged'}; End: {label(b) if b else 'not logged'}"
        proof += f"; {row['key'][1]} {row['key'][2] or 'Unavailable'}"
        if a and _eid(a['event'])==4624:proof += "; logon lifetime (may include disconnected time)"
        elif a:proof += "; connected interval"
        else:proof += "; observation only"
        out = dict(type="RDP Session",session_key=f"{row['key'][1]}:{row['key'][2]}",computer=display,
                   start_ts=_fmt(at),end_ts=_fmt(bt),start_ts_full=_fmt(at,True),end_ts_full=_fmt(bt,True),
                   duration=duration,duration_secs=seconds,user=row["user"],remote_host=remote,remote_ip=remote,
                   control="Unknown",status="Completed" if proved else "Partial (no start)" if b else "Start logged (no end)" if a else "Detected",
                   event_count=len(records),filterable_event_count=len(pairs),unfilterable_event_count=unfilterable,
                   flags=flags,evidence=proof,source_log="; ".join(sorted({PureWindowsPath(str(e.get('source_file') or '')).name for e in physical if e.get('source_file')})),related_keys=pairs,
                   _observed_order=_fmt(records[0]["time"],True),_previous=row["previous"])
        result.append(out);rowmap[id(row)] = out
    for out in result:
        parent = out.pop("_previous")
        out["_continuation_row"] = rowmap.get(id(parent)) if parent else None
    return result


def _record_id(event):
    try:
        value = event.get("record_id")
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _fmt(time, full=False):
    return time.strftime("%Y-%m-%d %H:%M:%S.%f" if full else "%Y-%m-%d %H:%M:%S") if time else "Unavailable"
