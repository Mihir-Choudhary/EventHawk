"""
PowerShell forensic extraction — session builder.

Correlates EID 400/403/600/800/4103/4104 events into PSSession objects
using HostId (primary) and ProcessID (cross-log correlation).
"""

from __future__ import annotations

import logging
from collections import defaultdict

from .constants import ZERO_GUID
from .models import PSSession

logger = logging.getLogger(__name__)


def _best_session_for_event(
    candidates: list[str],
    sessions: dict[str, "PSSession"],
    event_ts: str,
) -> "PSSession":
    """
    Pick the best session for a cross-log PID match.

    Strategy: choose the session whose start_ts is the latest timestamp
    that is still <= the event's timestamp. This ensures we don't assign
    an event to a session that hadn't started yet.

    Fallback: if all sessions started *after* the event (e.g. log rotation
    gap), pick the session with the earliest start_ts (closest in time).
    """
    sess_objs = [sessions[h] for h in candidates]
    if not event_ts:
        # No event timestamp — fall back to latest start
        return max(sess_objs, key=lambda s: s.start_ts)

    before = [s for s in sess_objs if s.start_ts <= event_ts]
    if before:
        return max(before, key=lambda s: s.start_ts)
    # All sessions started after event — pick the earliest
    return min(sess_objs, key=lambda s: s.start_ts)


def build_sessions(buckets: dict[int, list[dict]]) -> list[PSSession]:
    """
    Reconstruct PowerShell session timelines from classic-channel events.

    Correlation strategy (in priority order):
    1. EID 400/403 paired by HostId — defines session boundaries
    2. EID 600 attached to session by HostId — provider capability profile
    3. EID 4103/800 attached to session by PID — cross-log tie
    4. EID 4104 attached to session by PID — only fragment 1 per block (concise timeline)
    5. Unmatched events → session_events of nearest session by PID, else _unsessioned

    Sessions without a matching EID 403 have stop_ts = "" (forced termination
    or log truncation — noted in summary).

    Returns:
        List of PSSession objects sorted by start_ts.
    """
    events_400 = buckets.get(400, [])
    events_403 = buckets.get(403, [])
    events_600 = buckets.get(600, [])
    events_4103 = buckets.get(4103, [])
    events_800 = buckets.get(800, [])

    # Build sessions from EID 400 records (one per HostId)
    # HostId is the most reliable session key; use it as primary dict key.
    sessions_by_host_id: dict[str, PSSession] = {}

    for ev400 in sorted(events_400, key=lambda e: e.get("timestamp", "")):
        host_id = ev400.get("host_id", "").strip("{}")
        if not host_id:
            # Corrupt record — synthesise a key from PID + timestamp
            host_id = f"_pid{ev400.get('pid', '?')}_{ev400.get('timestamp', '')}"

        session = PSSession(
            host_id=host_id,
            pid=ev400.get("pid", ""),
            computer=ev400.get("computer", ""),
            start_ts=ev400.get("timestamp", ""),
            stop_ts="",
            host_name=ev400.get("host_name", ""),
            host_version=ev400.get("host_version", ev400.get("engine_version", "")),
            host_application=ev400.get("host_application", ""),
            encoded_command=ev400.get("encoded_command", ""),
            runspace_id=ev400.get("runspace_id", ""),
            user_sid=ev400.get("user_sid", ""),
        )
        session.session_events.append(ev400)

        if host_id in sessions_by_host_id:
            # Two EID 400 events with same HostId (genuine PS restart or log artifact).
            # Treat as separate by appending a counter suffix.
            suffix = 2
            while f"{host_id}_{suffix}" in sessions_by_host_id:
                suffix += 1
            host_id = f"{host_id}_{suffix}"
            session.host_id = host_id

        sessions_by_host_id[host_id] = session

    # PID → list of session host_ids for cross-log correlation
    pid_to_host_ids: dict[str, list[str]] = defaultdict(list)
    for host_id, sess in sessions_by_host_id.items():
        if sess.pid:
            pid_to_host_ids[sess.pid].append(host_id)

    # Attach EID 403 (engine stop) — match by HostId
    for ev403 in events_403:
        host_id = ev403.get("host_id", "").strip("{}")
        if host_id in sessions_by_host_id:
            sess = sessions_by_host_id[host_id]
            if not sess.stop_ts:
                sess.stop_ts = ev403.get("timestamp", "")
                sess.session_events.append(ev403)
        else:
            # No matching session — orphan stop event; log it
            logger.debug("EID 403 HostId=%s has no matching EID 400", host_id)

    # Attach EID 600 (provider start) — match by HostId
    for ev600 in events_600:
        host_id = ev600.get("host_id", "").strip("{}")
        if host_id in sessions_by_host_id:
            sess = sessions_by_host_id[host_id]
            pname = ev600.get("provider_name", "")
            if pname and pname not in sess.providers:
                sess.providers.append(pname)
            sess.session_events.append(ev600)

    # Attach EID 4103 (command exec) — match by PID then by HostId from ContextInfo
    for ev4103 in events_4103:
        pid = ev4103.get("pid", "")
        host_id_ctx = ev4103.get("host_id", "").strip("{}")
        matched = False

        # Try ContextInfo HostId first (most precise)
        if host_id_ctx and host_id_ctx in sessions_by_host_id:
            sess = sessions_by_host_id[host_id_ctx]
            sess.session_events.append(ev4103)
            # Backfill user_name from 4103 ContextInfo if session doesn't have it yet
            if not sess.user_name:
                sess.user_name = ev4103.get("user", "")
            matched = True

        if not matched and pid and pid in pid_to_host_ids:
            candidates = pid_to_host_ids[pid]
            event_ts = ev4103.get("timestamp", "")
            best = _best_session_for_event(candidates, sessions_by_host_id, event_ts)
            best.session_events.append(ev4103)
            matched = True

        if not matched:
            # No session: create a synthetic "unsessioned" entry
            _ensure_unsessioned(sessions_by_host_id, ev4103)

    # Attach EID 800 (pipeline details) — match by HostId, then PID
    for ev800 in events_800:
        pid = ev800.get("pid", "")
        host_id = ev800.get("host_id", "").strip("{}")
        matched = False

        if host_id and host_id in sessions_by_host_id:
            sessions_by_host_id[host_id].session_events.append(ev800)
            matched = True

        if not matched and pid and pid in pid_to_host_ids:
            candidates = pid_to_host_ids[pid]
            event_ts = ev800.get("timestamp", "")
            best = _best_session_for_event(candidates, sessions_by_host_id, event_ts)
            best.session_events.append(ev800)
            matched = True

        if not matched:
            _ensure_unsessioned(sessions_by_host_id, ev800)

    # Attach EID 4104 (script block logging) — operational channel only, no HostId
    # field; correlate via PID (the most reliable cross-log tie for 4104).
    # Only the FIRST fragment of each block is attached to keep the timeline concise;
    # full script content is in the individual scriptblock_<GUID>.txt files.
    events_4104 = buckets.get(4104, [])
    seen_4104_keys: set[str] = set()  # avoid duplicate timeline entries per block
    for ev4104 in sorted(events_4104, key=lambda e: e.get("timestamp", "")):
        pid = ev4104.get("pid", "")
        sbid = ev4104.get("script_block_id", "")
        record_id = ev4104.get("event_record_id", 0)
        # Build the dedup key — matches reassembler.py key strategy:
        # ZERO_GUID blocks each get a unique key so they are never merged.
        dedup_key = f"{sbid}_{record_id}" if not sbid or sbid == ZERO_GUID else sbid
        # Only add the FIRST fragment we encounter for each block (avoids N entries
        # per multi-fragment block in the timeline). Sorting by timestamp means we
        # naturally encounter the earliest fragment first — even if fragment 1 was
        # lost to log rotation, we still add the next available fragment so the
        # block is visible in the session timeline.
        if dedup_key in seen_4104_keys:
            continue
        seen_4104_keys.add(dedup_key)

        matched = False
        if pid and pid in pid_to_host_ids:
            candidates = pid_to_host_ids[pid]
            event_ts = ev4104.get("timestamp", "")
            best = _best_session_for_event(candidates, sessions_by_host_id, event_ts)
            best.session_events.append(ev4104)
            matched = True

        if not matched:
            _ensure_unsessioned(sessions_by_host_id, ev4104)

    # Sort session_events within each session by timestamp
    for sess in sessions_by_host_id.values():
        sess.session_events.sort(key=lambda e: e.get("timestamp", ""))

    # Return sessions sorted by start_ts, with _unsessioned always last
    real = [s for s in sessions_by_host_id.values() if s.host_id != _UNSESSIONED_KEY]
    real.sort(key=lambda s: s.start_ts)
    unsessioned = sessions_by_host_id.get(_UNSESSIONED_KEY)
    result = real + ([unsessioned] if unsessioned else [])
    logger.debug(
        "build_sessions: %d sessions (%d with stop event, %d orphaned)",
        len(result),
        sum(1 for s in result if s.stop_ts),
        sum(1 for s in result if not s.stop_ts),
    )
    return result


_UNSESSIONED_KEY = "_unsessioned"


def _ensure_unsessioned(
    sessions: dict[str, PSSession], ev: dict
) -> None:
    """
    Add an event to the synthetic '_unsessioned' bucket for events with no
    matching EID 400 session.
    """
    if _UNSESSIONED_KEY not in sessions:
        sessions[_UNSESSIONED_KEY] = PSSession(
            host_id=_UNSESSIONED_KEY,
            pid="",
            computer="",
            start_ts="",
            stop_ts="",
            host_name="",
            host_version="",
            host_application="",
            encoded_command="",
            runspace_id="",
        )
    sessions[_UNSESSIONED_KEY].session_events.append(ev)
