"""
Process lineage reconstruction and PPID spoofing detection.

Maintains a live process state table as events stream through.
For Sysmon events: uses ProcessGuid (no PID recycling possible).
For Security log events: uses PID + create_time compound key.

PPID spoofing: if the reported parent PID belongs to a process that terminated
before the child was created, the PPID_MISMATCH flag is set on the event and
the parent name is returned as None (forcing lineage depth score to maximum).

Multi-host support: use PerHostLineageTracker when handling events from multiple
hosts in a single analysis run to prevent PID-space bleed between hosts.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING

from sentinel.analysis.normalizer import normalize_procname
from sentinel.models import RawEvent

logger = logging.getLogger(__name__)

# Maximum ancestry depth to reconstruct (proc + parent + grandparent + ...)
MAX_ANCESTRY_DEPTH = 5


@dataclass
class _ProcEntry:
    name: str
    path: str
    guid: str
    parent_guid: str  # B26: needed for ancestry chain walk beyond depth 2
    create_time: datetime
    exit_time: datetime | None = None
    parent_name: str = ""  # resolved parent name, stored for chain reconstruction


class LineageTracker:
    """
    Stateful per-host, per-analysis-run tracker.  Feed events in timestamp order.

    For multi-host analysis runs use PerHostLineageTracker instead, which
    partitions state by hostname to prevent PID-space bleed across hosts.
    """

    def __init__(self) -> None:
        # Sysmon path: guid → _ProcEntry
        self._by_guid: dict[str, _ProcEntry] = {}
        # Security log path: pid → _ProcEntry  (latest entry wins on recycle)
        self._by_pid: dict[int, _ProcEntry] = {}

    def process_event(self, ev: RawEvent) -> str | None:
        """
        Update tracker with event and return resolved parent name (or None).

        Sets ev.flags.add('PPID_MISMATCH') if spoofing is detected.
        Returns None if parent cannot be resolved (lineage score = max).
        """
        if ev.event_id in (4689, 5):
            # Process terminate — record exit time
            self._record_exit(ev)
            return None

        # Process create — resolve parent, then register this process
        parent_name = self._resolve_parent(ev)
        self._register(ev, parent_name)
        return parent_name

    def get_ancestry_chain(self, ev: RawEvent, proc_norm: str, parent_norm: str) -> list[str]:
        """Reconstruct ancestry chain up to MAX_ANCESTRY_DEPTH levels.

        Returns [proc, parent, grandparent, ...] using stored _ProcEntry data.
        The normalized proc and parent names are passed in (already computed
        by the caller); the rest of the chain is reconstructed from raw names.
        """
        chain = [proc_norm]
        if not parent_norm:
            return chain

        chain.append(parent_norm)

        # Walk up via PID or GUID registry to recover grandparent+
        current_pid = ev.ppid
        current_guid = ev.parent_guid
        for _ in range(MAX_ANCESTRY_DEPTH - 2):  # already have proc + parent
            entry = self._lookup_entry(current_guid, current_pid)
            if entry is None or not entry.parent_name:
                break
            gp_norm = normalize_procname(entry.parent_name)
            if not gp_norm or gp_norm in chain:
                break
            chain.append(gp_norm)
            # B26: Walk up using the entry's parent_guid (not its own guid)
            current_guid = entry.parent_guid
            current_pid = 0  # GUID-free fallback stops here for Security logs
            if not current_guid:
                break

        return chain

    def _lookup_entry(self, guid: str, pid: int) -> _ProcEntry | None:
        if guid:
            return self._by_guid.get(guid)
        return self._by_pid.get(pid)

    def _resolve_parent(self, ev: RawEvent) -> str | None:
        if ev.process_guid:
            # Sysmon: parent identified by ParentProcessGuid
            entry = self._by_guid.get(ev.parent_guid)
            if entry:
                return entry.name
            # Parent GUID unseen — may be a system process started before tracing
            return ev.parent_name if ev.parent_name else None

        # Security log: resolve by PPID
        # B16: PPID 0 is the System Idle Process / kernel — never a real parent.
        # Looking it up would hit leftover entries from _from_minimal and produce
        # false PPID_MISMATCH flags on every OS boot process.
        if ev.ppid == 0:
            return ev.parent_name if ev.parent_name else None

        entry = self._by_pid.get(ev.ppid)
        if entry is None:
            return ev.parent_name if ev.parent_name else None

        # Check for PPID recycling / spoofing
        if entry.exit_time is not None and entry.exit_time < ev.timestamp:
            ev.flags.add('PPID_MISMATCH')
            logger.debug(
                "PPID_MISMATCH: pid=%d (%s) exited at %s before child %s created at %s",
                ev.ppid, entry.name, entry.exit_time, ev.process_name, ev.timestamp,
            )
            return None

        return entry.name

    def _register(self, ev: RawEvent, resolved_parent_name: str | None) -> None:
        entry = _ProcEntry(
            name=ev.process_name,
            path=ev.process_path,
            guid=ev.process_guid,
            parent_guid=ev.parent_guid,  # B26: store for ancestry chain walk
            create_time=ev.timestamp,
            parent_name=resolved_parent_name or ev.parent_name,
        )
        if ev.process_guid:
            self._by_guid[ev.process_guid] = entry
        if ev.pid:
            self._by_pid[ev.pid] = entry

    def _record_exit(self, ev: RawEvent) -> None:
        if ev.process_guid:
            entry = self._by_guid.get(ev.process_guid)
            if entry:
                entry.exit_time = ev.timestamp
        elif ev.pid:  # B15: PID 0 is never a real process — don't clobber
            entry = self._by_pid.get(ev.pid)
            if entry:
                entry.exit_time = ev.timestamp


class PerHostLineageTracker:
    """
    Multi-host wrapper around LineageTracker.

    Routes each event to the per-host tracker identified by ev.host,
    preventing PID-space bleed between hosts in a single analysis run.
    """

    def __init__(self) -> None:
        self._trackers: dict[str, LineageTracker] = {}

    def _tracker_for(self, host: str) -> LineageTracker:
        if host not in self._trackers:
            self._trackers[host] = LineageTracker()
        return self._trackers[host]

    def process_event(self, ev: RawEvent) -> str | None:
        """Route to per-host tracker. Returns resolved parent name or None."""
        return self._tracker_for(ev.host).process_event(ev)

    def get_ancestry_chain(
        self, ev: RawEvent, proc_norm: str, parent_norm: str
    ) -> list[str]:
        """Delegate ancestry chain reconstruction to the per-host tracker."""
        return self._tracker_for(ev.host).get_ancestry_chain(ev, proc_norm, parent_norm)

    @property
    def host_count(self) -> int:
        return len(self._trackers)
