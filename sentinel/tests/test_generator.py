"""
Tests for sentinel.report.generator.

Q5 — covers:
  - Tier 4 grouping-by-ATT&CK-technique (_build_critical_section)
  - _build_metrics_section computes max_score / mean_score from all_scored (Q1)
  - input_file_hashes flows into report header (F11/S5)
  - generate_csv_report only exports Tier 3+ events
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pytest

from sentinel.models import (
    BaselineMeta,
    NormalizedEvent,
    RawEvent,
    ScoredEvent,
    TierBoundaries,
)
from sentinel.report.generator import (
    generate_report,
    generate_csv_report,
    _build_critical_section,
    _build_metrics_section,
)


# ── Fixture helpers ────────────────────────────────────────────────────────────

def _raw(host="HOST1", process="cmd.exe", parent="explorer.exe",
         attck_tags=None, tier=4, ts=None):
    return RawEvent(
        timestamp=ts or datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc),
        host=host,
        event_id=4688,
        process_guid="",
        pid=1000,
        ppid=4,
        parent_guid="",
        process_name=process,
        process_path=f"C:\\Windows\\{process}",
        parent_name=parent,
        parent_path=f"C:\\Windows\\{parent}",
        cmdline=f"{process} /c whoami",
        user="SYSTEM",
        integrity_level="High",
        image_hash="",
        attck_tags=attck_tags or [],
        flags=set(),
    )


def _norm(raw):
    return NormalizedEvent(
        raw=raw,
        proc_norm=raw.process_name.lower(),
        parent_norm=raw.parent_name.lower(),
        cmdline_norm=raw.cmdline.lower(),
        ancestry_chain=[raw.process_name.lower(), raw.parent_name.lower()],
    )


def _scored(raw, score=75.0, tier=4, justification=""):
    n = _norm(raw)
    return ScoredEvent(
        normalized=n,
        surprisal_cmdline=10.0,
        surprisal_lineage=8.0,
        trie_depth_score=0.9,
        ppid_flag=0.0,
        host_drift=0.1,
        composite=score,
        tier=tier,
        justification_text=justification,
    )


def _meta(input_file_hashes=None):
    return BaselineMeta(
        host="HOST1",
        start_ts="2024-01-01T00:00:00+00:00",
        end_ts="2024-01-07T00:00:00+00:00",
        stability_score=0.85,
        event_count=10000,
        build_ts="2024-01-07T12:00:00+00:00",
        tier_boundaries={"suppress_max": 20.0, "aggregate_max": 45.0, "highlight_max": 70.0},
        baseline_process_dist={"cmd.exe": 0.01},
        input_file_hashes=input_file_hashes or {},
    )


# ── Tests ──────────────────────────────────────────────────────────────────────

class TestBuildCriticalSection:
    """Tier 4 events are grouped correctly by ATT&CK technique."""

    def test_grouped_by_technique(self):
        ev1 = _scored(_raw(attck_tags=["T1059"]))
        ev2 = _scored(_raw(attck_tags=["T1059"]))
        ev3 = _scored(_raw(attck_tags=["T1003"]))

        sections = _build_critical_section([ev1, ev2, ev3])
        by_tech = {s["technique"]: s for s in sections}

        assert "T1059" in by_tech
        assert by_tech["T1059"]["event_count"] == 2
        assert "T1003" in by_tech
        assert by_tech["T1003"]["event_count"] == 1

    def test_no_attck_tags_grouped_as_untagged(self):
        ev = _scored(_raw(attck_tags=[]))
        sections = _build_critical_section([ev])
        assert sections[0]["technique"] == "UNTAGGED"

    def test_sorted_by_technique_id(self):
        events = [
            _scored(_raw(attck_tags=["T1059"])),
            _scored(_raw(attck_tags=["T1003"])),
            _scored(_raw(attck_tags=["T1055"])),
        ]
        sections = _build_critical_section(events)
        techniques = [s["technique"] for s in sections]
        assert techniques == sorted(techniques)

    def test_empty_returns_empty(self):
        assert _build_critical_section([]) == []

    def test_multi_technique_event(self):
        """An event with multiple ATT&CK tags appears in EACH technique group."""
        ev = _scored(_raw(attck_tags=["T1059", "T1003"]))
        sections = _build_critical_section([ev])
        by_tech = {s["technique"]: s for s in sections}
        assert "T1059" in by_tech
        assert "T1003" in by_tech


class TestBuildMetricsSection:
    """_build_metrics_section adds max_score / mean_score from all_scored (Q1)."""

    def test_empty_all_scored_no_extra_keys(self):
        metrics = {"events_scored": 0}
        out = _build_metrics_section(metrics, [])
        assert out["events_scored"] == 0
        assert "max_score" not in out  # only added when all_scored is non-empty

    def test_max_and_mean_computed(self):
        events = [
            _scored(_raw(), score=30.0),
            _scored(_raw(), score=50.0),
            _scored(_raw(), score=80.0),
        ]
        metrics = {"events_scored": 3}
        out = _build_metrics_section(metrics, events)
        assert out["max_score"] == 80.0
        assert abs(out["mean_score"] - 53.3) < 0.2  # (30+50+80)/3 = 53.3...

    def test_original_metrics_preserved(self):
        metrics = {"events_scored": 5, "tier4_critical": 2}
        out = _build_metrics_section(metrics, [])
        assert out["tier4_critical"] == 2


class TestInputFileHashes:
    """F11/S5: input_file_hashes flows into the report header."""

    def test_hashes_in_report_header(self, tmp_path):
        ev = _scored(_raw())
        hashes = {"Security.evtx": "abc123deadbeef"}
        meta = _meta(input_file_hashes=hashes)
        metrics = {
            "events_scored": 1, "tier1_suppressed": 0, "tier2_aggregate": 0,
            "tier3_highlight": 0, "tier4_critical": 1, "suppression_rate_pct": 0.0,
            "top10_suppressed_processes": [], "input_file_hashes": hashes,
        }
        report = generate_report([ev], metrics, meta)
        assert report["header"]["input_file_hashes"] == hashes

    def test_missing_hashes_returns_empty_dict(self, tmp_path):
        ev = _scored(_raw())
        meta = _meta()
        metrics = {"events_scored": 1, "input_file_hashes": {}}
        report = generate_report([ev], metrics, meta)
        assert report["header"]["input_file_hashes"] == {}


class TestGenerateCsvReport:
    """CSV export includes only Tier 3+ events."""

    def test_only_tier3_plus_exported(self, tmp_path):
        t1 = _scored(_raw(), score=10.0, tier=1)
        t3 = _scored(_raw(process="evil.exe"), score=72.0, tier=3, justification="anomalous")
        t4 = _scored(_raw(process="superbad.exe"), score=90.0, tier=4, justification="critical")

        meta = _meta()
        metrics = {}
        out_path = tmp_path / "report.csv"
        generate_csv_report([t1, t3, t4], metrics, meta, out_path)

        rows = list(csv.DictReader(out_path.read_text(encoding="utf-8").splitlines()))
        names = {r["process"] for r in rows}
        assert "evil.exe" in names
        assert "superbad.exe" in names
        # Tier 1 must NOT appear
        assert all(r["process"] != "cmd.exe" for r in rows)

    def test_sorted_by_tier_then_score(self, tmp_path):
        t3 = _scored(_raw(process="t3_low.exe"), score=55.0, tier=3)
        t3_high = _scored(_raw(process="t3_high.exe"), score=69.0, tier=3)
        t4 = _scored(_raw(process="t4.exe"), score=88.0, tier=4)

        meta = _meta()
        out_path = tmp_path / "sorted.csv"
        generate_csv_report([t3, t3_high, t4], {}, meta, out_path)

        rows = list(csv.DictReader(out_path.read_text(encoding="utf-8").splitlines()))
        # Tier 3 events come before tier 4 (sorted by tier ascending, score descending)
        tiers = [int(r["tier"]) for r in rows]
        assert tiers == sorted(tiers)

    def test_justification_included(self, tmp_path):
        ev = _scored(_raw(process="sus.exe"), score=72.0, tier=3,
                     justification="PPID spoofing detected")
        meta = _meta()
        out_path = tmp_path / "just.csv"
        generate_csv_report([ev], {}, meta, out_path)
        rows = list(csv.DictReader(out_path.read_text(encoding="utf-8").splitlines()))
        assert rows[0]["justification"] == "PPID spoofing detected"
