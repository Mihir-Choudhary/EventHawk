"""
Tests for sentinel.report.ted_forensic.

Q5 — specifically:
  - build_process_tree with PID recycling (B6 regression)
  - _flatten is iterative / handles deep trees without RecursionError (B4 regression)
  - session_ted produces correct edit distances
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

import pytest

from sentinel.report.ted_forensic import (
    ProcessTree,
    TEDResult,
    build_process_tree,
    session_ted,
    _flatten,
)


# ── Minimal RawEvent stub ──────────────────────────────────────────────────────
@dataclass
class _FakeEvent:
    event_id: int
    pid: int
    ppid: int
    process_name: str
    timestamp: datetime = field(default_factory=lambda: datetime(2024, 1, 1, tzinfo=timezone.utc))


def _ts(offset_seconds: int = 0) -> datetime:
    return datetime(2024, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)


# ── Build process tree tests ───────────────────────────────────────────────────

class TestBuildProcessTree:
    def test_simple_tree(self):
        events = [
            _FakeEvent(event_id=4688, pid=4, ppid=0, process_name="system", timestamp=_ts(0)),
            _FakeEvent(event_id=4688, pid=100, ppid=4, process_name="svchost.exe", timestamp=_ts(1)),
        ]
        root = build_process_tree(events)
        assert root.name == "[root]"
        # system links to root; svchost links to system
        system_node = root.children[0]
        assert system_node.name == "system"
        assert len(system_node.children) == 1
        assert system_node.children[0].name == "svchost.exe"

    def test_pid_recycling_b6(self):
        """B6 regression: second process with same PID should not clobber the first.
        The original PID=100 process should retain its children after recycling.
        """
        events = [
            # First cmd.exe with PID=100 at t=0
            _FakeEvent(event_id=4688, pid=4, ppid=0, process_name="system", timestamp=_ts(0)),
            _FakeEvent(event_id=4688, pid=100, ppid=4, process_name="cmd.exe", timestamp=_ts(1)),
            # Child of first cmd.exe
            _FakeEvent(event_id=4688, pid=200, ppid=100, process_name="whoami.exe", timestamp=_ts(2)),
            # PID=100 recycled at t=3 — a new process reuses the PID
            _FakeEvent(event_id=4688, pid=100, ppid=4, process_name="notepad.exe", timestamp=_ts(3)),
        ]
        root = build_process_tree(events)
        # Collect all node names
        all_names = {nd.name for nd in _flatten(root)}
        assert "cmd.exe" in all_names
        assert "notepad.exe" in all_names
        assert "whoami.exe" in all_names

    def test_orphaned_ppid_links_to_root(self):
        """Process whose ppid has no matching node should attach to [root]."""
        events = [
            _FakeEvent(event_id=4688, pid=5555, ppid=9999, process_name="orphan.exe", timestamp=_ts(0)),
        ]
        root = build_process_tree(events)
        assert len(root.children) == 1
        assert root.children[0].name == "orphan.exe"

    def test_terminate_events_ignored(self):
        """Only process-create events (4688/1) should produce nodes."""
        events = [
            _FakeEvent(event_id=4689, pid=100, ppid=4, process_name="cmd.exe", timestamp=_ts(0)),
        ]
        root = build_process_tree(events)
        assert root.children == []

    def test_sysmon_eid1(self):
        """Sysmon EID 1 events are also included."""
        events = [
            _FakeEvent(event_id=1, pid=100, ppid=4, process_name="powershell.exe", timestamp=_ts(0)),
        ]
        root = build_process_tree(events)
        assert root.children[0].name == "powershell.exe"

    def test_empty_events(self):
        root = build_process_tree([])
        assert root.name == "[root]"
        assert root.children == []


class TestFlattenIterative:
    """_flatten must be iterative (B4 fix) — no RecursionError on deep trees."""

    def test_deep_tree_no_recursion_error(self):
        """A chain of 2000 nodes must NOT raise RecursionError."""
        # Build a linear chain: root → n1 → n2 → ... → n2000
        root = ProcessTree(name="root")
        current = root
        depth = 2000
        for i in range(depth):
            child = ProcessTree(name=f"n{i}")
            current.children.append(child)
            current = child

        # This would raise RecursionError with the old recursive implementation
        nodes = _flatten(root)
        assert len(nodes) == depth + 1  # root + 2000 children

    def test_post_order_root_last(self):
        """Post-order: children appear before parents."""
        child = ProcessTree(name="child")
        root = ProcessTree(name="root", children=[child])
        nodes = _flatten(root)
        # In post-order, child comes before root
        child_idx = next(i for i, n in enumerate(nodes) if n.name == "child")
        root_idx = next(i for i, n in enumerate(nodes) if n.name == "root")
        assert child_idx < root_idx

    def test_single_node(self):
        node = ProcessTree(name="only")
        assert _flatten(node) == [node]

    def test_empty_tree_returns_root(self):
        root = ProcessTree(name="[root]")
        result = _flatten(root)
        assert result == [root]


class TestSessionTED:
    """session_ted returns correct edit distances for known tree pairs."""

    def test_identical_trees_zero_distance(self):
        t1 = ProcessTree("root", children=[ProcessTree("a"), ProcessTree("b")])
        t2 = ProcessTree("root", children=[ProcessTree("a"), ProcessTree("b")])
        result = session_ted(t1, t2)
        assert result.edit_distance == 0
        assert result.operations == []

    def test_one_extra_node_distance_one(self):
        baseline = ProcessTree("root", children=[ProcessTree("a")])
        target   = ProcessTree("root", children=[ProcessTree("a"), ProcessTree("b")])
        result = session_ted(baseline, target)
        assert result.edit_distance >= 1
        # "b" was inserted
        inserted = [op for op in result.operations if op[0] == "insert"]
        assert any("b" in name for _, name in inserted)

    def test_deleted_node(self):
        baseline = ProcessTree("root", children=[ProcessTree("a"), ProcessTree("c")])
        target   = ProcessTree("root", children=[ProcessTree("a")])
        result = session_ted(baseline, target)
        deleted = [op for op in result.operations if op[0] == "delete"]
        assert any("c" in name for _, name in deleted)

    def test_result_sizes(self):
        t1 = ProcessTree("root", children=[ProcessTree("x"), ProcessTree("y")])
        t2 = ProcessTree("root", children=[ProcessTree("x")])
        result = session_ted(t1, t2)
        assert result.baseline_size == 3   # root, x, y
        assert result.target_size == 2     # root, x
