"""
Tests for sentinel.baseline.freq_model.

Verifies Laplace-smoothed surprisal math, edge cases, and model building.
"""
import math
import pytest
from collections import Counter

from sentinel.baseline.freq_model import (
    FrequencyModel,
    build_freq_model,
    surprisal_cmdline,
    surprisal_lineage,
    MAX_SURPRISAL,
)


def _make_norm_event(proc: str, parent: str, cmdline: str):
    from unittest.mock import MagicMock
    ev = MagicMock()
    ev.proc_norm = proc
    ev.parent_norm = parent
    ev.cmdline_norm = cmdline
    return ev


class TestSurprisalMath:
    def test_seen_proc_cmdline_gives_low_surprisal(self):
        """A frequent (proc, cmdline) should have low surprisal."""
        events = [
            _make_norm_event("svchost.exe", "services.exe", "svchost -k netsvcs")
            for _ in range(100)
        ]
        model = build_freq_model(events)
        s = surprisal_cmdline(model, "svchost.exe", "svchost -k netsvcs")
        assert s < 5.0, f"Expected low surprisal for common event, got {s}"

    def test_unseen_proc_returns_max(self):
        """A process never seen in baseline should return MAX_SURPRISAL."""
        model = FrequencyModel()
        s = surprisal_cmdline(model, "unknown.exe", "unknown.exe /foo")
        assert s == MAX_SURPRISAL

    def test_unseen_cmdline_for_known_proc_is_bounded(self):
        """A new cmdline for a known process: should be capped at MAX_SURPRISAL."""
        events = [_make_norm_event("cmd.exe", "explorer.exe", "cmd /c whoami")]
        model = build_freq_model(events)
        s = surprisal_cmdline(model, "cmd.exe", "cmd /c completely_new_payload")
        assert s <= MAX_SURPRISAL

    def test_laplace_smoothing_nonzero_denominator(self):
        """Surprisal must always be a finite non-negative number."""
        events = [_make_norm_event("notepad.exe", "explorer.exe", "notepad.exe")]
        model = build_freq_model(events)
        s = surprisal_cmdline(model, "notepad.exe", "notepad.exe")
        assert math.isfinite(s)
        assert s >= 0  # known event with 1 sample: Laplace p=2/2=1.0 → surprisal=0.0

    def test_lineage_surprisal_unseen_parent(self):
        """Parent entirely unseen → MAX_SURPRISAL."""
        model = FrequencyModel()
        s = surprisal_lineage(model, "cmd.exe", "unknown_parent.exe")
        assert s == MAX_SURPRISAL

    def test_lineage_surprisal_seen_pair(self):
        """Known (proc, parent) should have lower surprisal than unseen."""
        events = [
            _make_norm_event("cmd.exe", "explorer.exe", "cmd /c whoami")
            for _ in range(50)
        ]
        model = build_freq_model(events)
        seen = surprisal_lineage(model, "cmd.exe", "explorer.exe")
        unseen = surprisal_lineage(model, "mimikatz.exe", "explorer.exe")
        assert seen < unseen

    def test_surprisal_is_positive(self):
        """Surprisal values must always be >= 0."""
        events = [_make_norm_event("p.exe", "q.exe", "p q r") for _ in range(10)]
        model = build_freq_model(events)
        assert surprisal_cmdline(model, "p.exe", "p q r") >= 0
        assert surprisal_lineage(model, "p.exe", "q.exe") >= 0
