"""
Tests for sentinel.baseline.stability.

Key invariant: stability scoring must ONLY consider process-creation events
(event_id in {4688, 1}).  Non-create events (terminations, access events)
must not inflate volatility.
"""
import pytest
from unittest.mock import MagicMock

from sentinel.baseline.stability import baseline_stability


def _make_event(event_id: int, process_name: str, cmdline: str = ""):
    ev = MagicMock()
    ev.event_id = event_id
    ev.process_name = process_name
    ev.cmdline = cmdline
    return ev


class TestStabilityCreateEventsOnly:
    def test_non_create_events_ignored(self):
        """Termination (4689) and access events (10) must not affect score."""
        create = [
            _make_event(4688, "cmd.exe", "cmd /c whoami"),
            _make_event(4688, "cmd.exe", "cmd /c whoami"),
        ]
        non_create = [
            _make_event(4689, "cmd.exe", ""),   # termination — empty cmdline
            _make_event(10, "lsass.exe", ""),    # process access — empty cmdline
            _make_event(5, "svchost.exe", ""),   # process terminate
        ]
        score_with = baseline_stability(create + non_create)
        score_without = baseline_stability(create)
        assert score_with == score_without, (
            f"Non-create events changed stability: {score_without} → {score_with}"
        )

    def test_empty_create_events_returns_zero(self):
        """If there are no create events at all, return 0.0."""
        events = [
            _make_event(4689, "cmd.exe", ""),
            _make_event(5, "svchost.exe", ""),
        ]
        score = baseline_stability(events)
        assert score == 0.0

    def test_empty_input_returns_zero(self):
        assert baseline_stability([]) == 0.0

    def test_highly_stable_baseline(self):
        """Identical cmdlines → very high stability (close to 1.0 but not exact, formula gives 1-1/N)."""
        events = [
            _make_event(4688, "svchost.exe", "C:\\Windows\\System32\\svchost.exe -k netsvcs")
            for _ in range(50)
        ]
        score = baseline_stability(events)
        # volatility = 1/50 = 0.02, stability = 0.98
        assert score >= 0.95, f"Expected high stability, got {score}"

    def test_volatile_baseline(self):
        """All unique cmdlines → low stability."""
        events = [
            _make_event(4688, "cmd.exe", f"cmd /c command_{i}")
            for i in range(50)
        ]
        score = baseline_stability(events)
        assert score < 0.5

    def test_sysmon_event_1_counted(self):
        """Sysmon process create (event_id=1) must also be counted."""
        events = [
            _make_event(1, "cmd.exe", "cmd /c whoami"),
            _make_event(1, "cmd.exe", "cmd /c whoami"),
        ]
        score = baseline_stability(events)
        # 1 unique / 2 total → volatility=0.5, stability=0.5
        assert score == pytest.approx(0.5, abs=1e-6)
