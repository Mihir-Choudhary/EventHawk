"""
Tests for sentinel.analysis.lineage.

Q5 — specifically covers:
  - PPID spoofing detection path (PPID_MISMATCH flag set when parent exited first)
  - Normal parent resolution (Security log PID-based and Sysmon GUID-based)
  - PerHostLineageTracker isolates state per host
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

import pytest

from sentinel.analysis.lineage import LineageTracker, PerHostLineageTracker
from sentinel.models import RawEvent


def _ts(offset_seconds: int = 0) -> datetime:
    return datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)


def _raw(
    event_id: int = 4688,
    pid: int = 100,
    ppid: int = 4,
    process_name: str = "cmd.exe",
    parent_name: str = "explorer.exe",
    ts_offset: int = 0,
    host: str = "HOST1",
    process_guid: str = "",
    parent_guid: str = "",
) -> RawEvent:
    return RawEvent(
        timestamp=_ts(ts_offset),
        host=host,
        event_id=event_id,
        process_guid=process_guid,
        pid=pid,
        ppid=ppid,
        parent_guid=parent_guid,
        process_name=process_name,
        process_path=f"C:\\Windows\\{process_name}",
        parent_name=parent_name,
        parent_path=f"C:\\Windows\\{parent_name}",
        cmdline=f"{process_name} /c whoami",
        user="SYSTEM",
        integrity_level="High",
        image_hash="",
        attck_tags=[],
        flags=set(),
    )


class TestLineageTrackerPPIDSpoofing:
    """PPID spoofing detection path."""

    def test_ppid_mismatch_flag_set_when_parent_exited_before_child(self):
        """When the parent process (PID=4) exits BEFORE the child is created,
        PPID_MISMATCH must be added to the child's flags."""
        tracker = LineageTracker()

        # Register parent process (PID=4) — create at t=0
        parent = _raw(event_id=4688, pid=4, ppid=0, process_name="explorer.exe",
                       parent_name="", ts_offset=0)
        tracker.process_event(parent)

        # Parent exits at t=5
        exit_ev = _raw(event_id=4689, pid=4, ppid=0, process_name="explorer.exe",
                        parent_name="", ts_offset=5)
        tracker.process_event(exit_ev)

        # Child created at t=10, reports ppid=4 (recycled or spoofed)
        child = _raw(event_id=4688, pid=200, ppid=4, process_name="evil.exe",
                      parent_name="explorer.exe", ts_offset=10)
        tracker.process_event(child)

        assert "PPID_MISMATCH" in child.flags

    def test_no_ppid_mismatch_when_parent_still_alive(self):
        """If the parent is still alive when child spawns, no flag is set."""
        tracker = LineageTracker()

        parent = _raw(event_id=4688, pid=4, ppid=0, process_name="explorer.exe",
                       ts_offset=0)
        tracker.process_event(parent)

        child = _raw(event_id=4688, pid=100, ppid=4, process_name="cmd.exe",
                      ts_offset=5)
        tracker.process_event(child)

        assert "PPID_MISMATCH" not in child.flags

    def test_ppid_mismatch_resolves_parent_as_none(self):
        """When PPID_MISMATCH is detected, process_event should return None."""
        tracker = LineageTracker()

        parent = _raw(event_id=4688, pid=4, ppid=0, process_name="svchost.exe", ts_offset=0)
        tracker.process_event(parent)

        exit_ev = _raw(event_id=4689, pid=4, ppid=0, process_name="svchost.exe", ts_offset=1)
        tracker.process_event(exit_ev)

        child = _raw(event_id=4688, pid=500, ppid=4, process_name="injected.exe", ts_offset=10)
        result = tracker.process_event(child)

        assert result is None

    def test_unknown_ppid_falls_back_to_raw_parent_name(self):
        """If the PPID was never registered, fall back to the event's parent_name."""
        tracker = LineageTracker()
        ev = _raw(event_id=4688, pid=100, ppid=9999, process_name="cmd.exe",
                   parent_name="unknown_parent.exe", ts_offset=0)
        result = tracker.process_event(ev)
        assert result == "unknown_parent.exe"

    def test_terminate_event_returns_none(self):
        """Terminate events (4689/5) return None from process_event."""
        tracker = LineageTracker()
        ev = _raw(event_id=4689, pid=100)
        result = tracker.process_event(ev)
        assert result is None


class TestLineageTrackerSysmon:
    """Sysmon GUID-based parent resolution."""

    def test_sysmon_parent_resolved_by_guid(self):
        tracker = LineageTracker()

        # Register parent with a process GUID
        parent = _raw(event_id=1, pid=4, ppid=0, process_name="lsass.exe",
                       process_guid="{PARENT-GUID-1}", parent_guid="", ts_offset=0)
        tracker.process_event(parent)

        # Child references parent GUID
        child = _raw(event_id=1, pid=100, ppid=4, process_name="mimikatz.exe",
                      process_guid="{CHILD-GUID-1}", parent_guid="{PARENT-GUID-1}", ts_offset=5)
        result = tracker.process_event(child)

        assert result == "lsass.exe"


class TestPerHostIsolation:
    """PerHostLineageTracker keeps per-host state isolated."""

    def test_pid_space_isolated_per_host(self):
        """Same PID=100 on two different hosts must not share state."""
        tracker = PerHostLineageTracker()

        # HOST-A: registers PID=100 as explorer.exe, then it exits
        ev_a_create = _raw(event_id=4688, pid=100, ppid=4, process_name="explorer.exe",
                            host="HOST-A", ts_offset=0)
        tracker.process_event(ev_a_create)
        ev_a_exit = _raw(event_id=4689, pid=100, host="HOST-A", ts_offset=5)
        tracker.process_event(ev_a_exit)

        # HOST-B: PID=100 is created fresh — parent PID=100 was never registered on HOST-B
        ev_b_child = _raw(event_id=4688, pid=200, ppid=100, process_name="legit.exe",
                           parent_name="winlogon.exe", host="HOST-B", ts_offset=10)
        tracker.process_event(ev_b_child)

        # Should NOT get PPID_MISMATCH — HOST-A's exit state must not leak to HOST-B
        assert "PPID_MISMATCH" not in ev_b_child.flags

    def test_host_count_property(self):
        tracker = PerHostLineageTracker()
        assert tracker.host_count == 0
        ev = _raw(host="HOST-X")
        tracker.process_event(ev)
        assert tracker.host_count == 1

        ev2 = _raw(host="HOST-Y")
        tracker.process_event(ev2)
        assert tracker.host_count == 2
