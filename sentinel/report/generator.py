"""
Differential Threat Report generator.

Produces a structured report dict from analysis results:
  Section 1 — Critical alerts (Tier 4), grouped by ATT&CK technique
  Section 2 — Edge case review (Tier 3) with justification strings
  Section 3 — Suppression metrics

Export formats:
  generate_report()      → JSON (full report)
  generate_csv_report()  → CSV (flat table of Tier 3+ events for SIEM import)
"""
from __future__ import annotations

import csv
import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models import BaselineMeta, ScoredEvent


def generate_report(
    scored_events: list["ScoredEvent"],
    metrics: dict,
    meta: "BaselineMeta",
    output_path: Path | None = None,
) -> dict:
    """
    Build the full report dict.

    Args:
        scored_events: Output of run_analysis().
        metrics:       Metrics dict from run_analysis().
        meta:          BaselineMeta from baseline build.
        output_path:   If given, write JSON report to this file.

    Returns:
        Report dict with keys: header, critical_alerts, edge_cases, metrics.
    """
    tier4 = [e for e in scored_events if e.tier == 4]
    tier3 = [e for e in scored_events if e.tier == 3]

    report = {
        "header": _build_header(meta, metrics, scored_events),
        "critical_alerts": _build_critical_section(tier4),
        "edge_cases": _build_edge_section(tier3),
        "metrics": _build_metrics_section(metrics, scored_events),
    }

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

    return report


def generate_csv_report(
    scored_events: list["ScoredEvent"],
    metrics: dict,
    meta: "BaselineMeta",
    output_path: Path,
) -> None:
    """
    Export a flat CSV of all Tier 3+ events for SIEM import or analyst review.

    Only Tier 3 and Tier 4 events are exported (Tier 1/2 are suppressed/aggregated
    and do not carry enough signal to be useful in a CSV review workflow).
    """
    fieldnames = [
        "timestamp", "host", "tier", "score",
        "process", "parent", "user", "integrity_level",
        "cmdline_raw", "cmdline_norm",
        "ancestry_chain", "attck_tags",
        "ppid_flag", "host_drift_jsd",
        "surprisal_cmd", "surprisal_lin", "trie_depth",
        "flags", "justification",
    ]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    events_to_export = [e for e in scored_events if e.tier >= 3]
    events_to_export.sort(key=lambda e: (e.tier, -e.composite))

    with open(output_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for ev in events_to_export:
            raw = ev.raw
            writer.writerow({
                "timestamp":       raw.timestamp.isoformat() if raw.timestamp else "",
                "host":            raw.host,
                "tier":            ev.tier,
                "score":           ev.composite,
                "process":         ev.normalized.proc_norm,
                "parent":          ev.normalized.parent_norm,
                "user":            raw.user,
                "integrity_level": raw.integrity_level,
                "cmdline_raw":     raw.cmdline,
                "cmdline_norm":    ev.normalized.cmdline_norm,
                "ancestry_chain":  " > ".join(ev.normalized.ancestry_chain),
                "attck_tags":      "|".join(raw.attck_tags) if raw.attck_tags else "",
                "ppid_flag":       ev.ppid_flag,
                "host_drift_jsd":  ev.host_drift,
                "surprisal_cmd":   ev.surprisal_cmdline,
                "surprisal_lin":   ev.surprisal_lineage,
                "trie_depth":      ev.trie_depth_score,
                "flags":           "|".join(raw.flags) if raw.flags else "",
                "justification":   ev.justification_text,
            })


def _build_header(meta: "BaselineMeta", metrics: dict, scored_events: list | None = None) -> dict:
    return {
        "report_generated": datetime.now(tz=timezone.utc).isoformat(),
        "baseline_host": meta.host,
        "baseline_period": f"{meta.start_ts} → {meta.end_ts}",
        "baseline_events": meta.event_count,
        "baseline_stability": meta.stability_score,
        "tier_boundaries": meta.tier_boundaries,
        "target_events_scored": metrics.get("events_scored", 0),
        "suppression_rate_pct": metrics.get("suppression_rate_pct", 0.0),
        # F11/S5: input file hashes for forensic chain-of-custody
        "input_file_hashes": metrics.get("input_file_hashes", {}),
    }


def _build_critical_section(tier4: list["ScoredEvent"]) -> list[dict]:
    """
    Group Tier 4 events by ATT&CK technique.
    Returns list of {technique, events[]} sorted by technique ID.
    """
    by_technique: dict[str, list[dict]] = defaultdict(list)

    for ev in sorted(tier4, key=lambda e: e.composite, reverse=True):
        raw = ev.raw
        techniques = raw.attck_tags if raw.attck_tags else ["UNTAGGED"]
        entry = {
            "timestamp":        raw.timestamp.isoformat() if raw.timestamp else "",
            "host":             raw.host,
            "user":             raw.user,
            "integrity_level":  raw.integrity_level,
            "process":          ev.normalized.proc_norm,
            "parent":           ev.normalized.parent_norm,
            "cmdline_raw":      raw.cmdline,
            "cmdline_norm":     ev.normalized.cmdline_norm,
            "ancestry_chain":   ev.normalized.ancestry_chain,
            "score":            ev.composite,
            "sub_scores": {
                "cmdline_surprisal": ev.surprisal_cmdline,
                "lineage_surprisal": ev.surprisal_lineage,
                "trie_depth":        ev.trie_depth_score,
                "ppid_flag":         ev.ppid_flag,
                "host_drift_jsd":    ev.host_drift,
            },
            "flags":            list(raw.flags),
            "justification":    ev.justification_text,
        }
        for tech in techniques:
            by_technique[tech].append(entry)

    return [
        {"technique": tech, "event_count": len(evts), "events": evts}
        for tech, evts in sorted(by_technique.items())
    ]


def _build_edge_section(tier3: list["ScoredEvent"]) -> list[dict]:
    """Tier 3 — edge cases with per-event justification."""
    result = []
    for ev in sorted(tier3, key=lambda e: e.composite, reverse=True):
        raw = ev.raw
        result.append({
            "timestamp":       raw.timestamp.isoformat() if raw.timestamp else "",
            "host":            raw.host,
            "process":         ev.normalized.proc_norm,
            "parent":          ev.normalized.parent_norm,
            "cmdline_norm":    ev.normalized.cmdline_norm,
            "score":           ev.composite,
            "attck_tags":      raw.attck_tags,
            "justification":   ev.justification_text,
            "flags":           list(raw.flags),
        })
    return result


def _build_metrics_section(metrics: dict, all_scored: list["ScoredEvent"]) -> dict:
    # Q1: Use all_scored to compute additional statistics
    out = dict(metrics)
    if all_scored:
        scores = [e.composite for e in all_scored]
        out["max_score"] = round(max(scores), 1)
        out["mean_score"] = round(sum(scores) / len(scores), 1)
    return out
