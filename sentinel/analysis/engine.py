"""
Analysis pipeline engine (Phase 1).

Loads all baseline artifacts and streams target EVTX events through:
  - Sigma pre-tagging (raw)
  - Normalization
  - Fuse filter pre-screen
  - Frequency model surprisal scoring
  - Ancestry trie depth scoring
  - PPID mismatch flag
  - Host-level JS divergence drift bonus
  - Image hash mismatch bonus (Sysmon only)
  - Composite score + tier classification
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Callable

from sentinel.analysis.drift_monitor import HostDriftMonitor
from sentinel.analysis.lineage import PerHostLineageTracker
from sentinel.analysis.normalizer import normalize_cmdline, normalize_procname
from sentinel.analysis.scorer import composite_score, trie_depth_score, image_hash_bonus
from sentinel.baseline.freq_model import surprisal_cmdline, surprisal_lineage
from sentinel.baseline.persistence import load_artifacts
from sentinel.config import SentinelConfig, load_config
from sentinel.models import BaselineMeta, NormalizedEvent, ScoredEvent, TierBoundaries

logger = logging.getLogger(__name__)


def run_analysis(
    target_paths: list[Path],
    baseline_dir: Path,
    sigma_rules_dir: Path | None = None,
    progress_cb: Callable[[str, float], None] | None = None,
    config_path: Path | None = None,
) -> tuple[list[ScoredEvent], dict]:
    """
    Full Phase 1 analysis pipeline.

    Args:
        target_paths:   .evtx files from the target system to analyze.
        baseline_dir:   Directory containing baseline artifacts.
        sigma_rules_dir: Optional path for Sigma pre-tagging.
        progress_cb:    Optional (step_name, 0.0–1.0) callback.
        config_path:    Optional path to a SentinelConfig JSON file.

    Returns:
        (scored_events, metrics_dict)
    """
    def _cb(step: str, pct: float) -> None:
        if progress_cb:
            progress_cb(step, pct)

    # ── Load config ───────────────────────────────────────────────────────────
    cfg = load_config(config_path)

    # ── Load baseline artifacts ───────────────────────────────────────────────
    _cb("Loading baseline artifacts", 0.0)
    meta, freq_model, trie, fuse = load_artifacts(baseline_dir)
    tier_bounds = TierBoundaries(**meta.tier_boundaries)

    # ── Parse target events ───────────────────────────────────────────────────
    _cb("Hashing input EVTX files", 0.04)
    from sentinel.analysis.parser import hash_evtx_files, parse_evtx_files, parse_evtx_files_parallel
    input_file_hashes = hash_evtx_files(target_paths)
    logger.info("Input file hashes: %s", input_file_hashes)

    _cb("Parsing target EVTX files", 0.05)
    def _parse_cb(step: str, pct: float) -> None:
        _cb(step, 0.05 + 0.10 * pct)

    # F4: Use parallel parsing for multiple files; fall back to serial for one
    if len(target_paths) > 1:
        raw_events = parse_evtx_files_parallel(target_paths, progress_cb=_parse_cb)
    else:
        raw_events = parse_evtx_files(target_paths, progress_cb=_parse_cb)
    # Sort by timestamp for correct lineage tracking
    raw_events.sort(key=lambda e: e.timestamp)
    logger.info("Parsed %d target events", len(raw_events))

    if not raw_events:
        _cb("Done", 1.0)
        return [], {"events_raw_total": 0, "events_scored": 0,
                    "tier1_suppressed": 0, "tier2_aggregate": 0,
                    "tier3_highlight": 0, "tier4_critical": 0,
                    "suppression_rate_pct": 0.0,
                    "top10_suppressed_processes": [],
                    "input_file_hashes": {},
                    "drift_mild_threshold": cfg.drift_mild_threshold,
                    "drift_significant_threshold": cfg.drift_significant_threshold}

    # ── Sigma pre-tagging (on raw events before normalization) ─────────────────
    _cb("Sigma pre-tagging", 0.10)
    sigma_tagger = None
    if sigma_rules_dir and sigma_rules_dir.exists():
        from sentinel.analysis.sigma_tagger import SigmaTagger
        sigma_tagger = SigmaTagger(sigma_rules_dir)
        for ev in raw_events:
            ev.attck_tags = sigma_tagger.tag(ev)

    # ── Set up per-host trackers ───────────────────────────────────────────────
    baseline_dist = meta.baseline_process_dist
    # B13: Eagerly bind captured values to avoid stale-closure issues
    _bd, _wm = baseline_dist, cfg.drift_window_minutes
    drift_monitors: dict[str, HostDriftMonitor] = defaultdict(
        lambda _bd=_bd, _wm=_wm: HostDriftMonitor(_bd, window_minutes=_wm)
    )
    # PerHostLineageTracker prevents PID-state bleed across different hosts
    lineage_tracker = PerHostLineageTracker()

    # Build a seen-hash table for image_hash_bonus: maps proc_norm → set of hashes
    # seen so far in this run (populated from baseline events via SQLite if available,
    # or accumulated live from scored events).
    known_hashes: dict[str, set[str]] = defaultdict(set)

    # ── Stream events through scoring pipeline ────────────────────────────────
    _cb("Scoring events", 0.15)
    scored: list[ScoredEvent] = []
    total = len(raw_events)

    for i, ev in enumerate(raw_events):
        if i % 5000 == 0:
            _cb("Scoring events", 0.15 + 0.75 * (i / total))

        # Resolve parent via per-host lineage tracker (also sets PPID_MISMATCH flag)
        resolved_parent = lineage_tracker.process_event(ev)

        # Skip non-create events for scoring
        if ev.event_id not in (4688, 1):
            continue

        # Normalize
        proc_norm = normalize_procname(ev.process_name)
        parent_norm = normalize_procname(resolved_parent or ev.parent_name)
        cmdline_norm = normalize_cmdline(ev.cmdline)

        # Reconstruct deep ancestry chain using lineage tracker state (up to 5 levels)
        chain = lineage_tracker.get_ancestry_chain(ev, proc_norm, parent_norm)

        norm_ev = NormalizedEvent(
            raw=ev,
            proc_norm=proc_norm,
            parent_norm=parent_norm,
            cmdline_norm=cmdline_norm,
            ancestry_chain=chain,
        )

        # Fuse filter pre-screen: skip aggressive cap when context is anomalous
        in_baseline = fuse.contains(proc_norm, parent_norm, cmdline_norm)

        # Sub-scores
        s_cmd = surprisal_cmdline(freq_model, proc_norm, cmdline_norm)
        s_lin = surprisal_lineage(freq_model, proc_norm, parent_norm)
        depth, _ = trie.query(chain)
        t_score = trie_depth_score(depth, len(chain))
        ppid_flag = 1.0 if 'PPID_MISMATCH' in ev.flags else 0.0

        # Image hash mismatch bonus (Sysmon events only, when hash is available)
        hash_bonus = image_hash_bonus(proc_norm, ev.image_hash, known_hashes)
        if ev.image_hash:
            known_hashes[proc_norm].add(ev.image_hash)

        # Host drift
        drift_jsd = drift_monitors[ev.host].update(ev.timestamp, proc_norm)

        # Composite score (includes hash bonus) — uses cfg weights
        score = composite_score(s_cmd, s_lin, t_score, ppid_flag, drift_jsd, hash_bonus, cfg=cfg)

        # Fuse cap: only suppress if context is truly non-anomalous.
        # Do NOT cap when PPID spoofing is detected or when host drift is significant —
        # an adversary could replay a known-baseline command in an anomalous context.
        if in_baseline and ppid_flag < 1.0 and drift_jsd < cfg.drift_significant_threshold:
            score = min(score * 0.5, tier_bounds.aggregate_max)

        tier = tier_bounds.classify(score)

        scored_ev = ScoredEvent(
            normalized=norm_ev,
            surprisal_cmdline=round(s_cmd, 3),
            surprisal_lineage=round(s_lin, 3),
            trie_depth_score=round(t_score, 3),
            ppid_flag=ppid_flag,
            host_drift=round(drift_jsd, 4),
            composite=score,
            tier=tier,
        )
        scored.append(scored_ev)

    _cb("Building justifications", 0.90)
    from sentinel.report.justification import build_justification
    for ev in scored:
        if ev.tier >= 3:
            ev.justification_text = build_justification(ev, trie)

    _cb("Done", 1.0)

    metrics = _build_metrics(scored, len(raw_events), input_file_hashes, cfg)
    logger.info(
        "Analysis complete: %d events scored, tier4=%d, tier3=%d, hosts=%d",
        len(scored),
        sum(1 for e in scored if e.tier == 4),
        sum(1 for e in scored if e.tier == 3),
        lineage_tracker.host_count,
    )
    return scored, metrics


def _build_metrics(scored: list[ScoredEvent], raw_total: int, input_file_hashes: dict | None = None, cfg=None) -> dict:
    from collections import Counter
    tier_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    for ev in scored:
        tier_counts[ev.tier] = tier_counts.get(ev.tier, 0) + 1

    suppressed = tier_counts[1]
    total = len(scored)
    suppression_rate = suppressed / total if total else 0.0

    top_suppressed = Counter(
        ev.normalized.proc_norm
        for ev in scored
        if ev.tier == 1
    ).most_common(10)

    return {
        "events_raw_total": raw_total,
        "events_scored": total,
        "tier1_suppressed": tier_counts[1],
        "tier2_aggregate": tier_counts[2],
        "tier3_highlight": tier_counts[3],
        "tier4_critical": tier_counts[4],
        "suppression_rate_pct": round(suppression_rate * 100, 1),
        "top10_suppressed_processes": [
            {"process": name, "count": count}
            for name, count in top_suppressed
        ],
        # F11/S5: forensic chain-of-custody hashes for all input EVTX files
        "input_file_hashes": input_file_hashes or {},
        # Drift thresholds from config — used by MetricsTab for correct level labels
        "drift_mild_threshold": cfg.drift_mild_threshold if cfg else 0.15,
        "drift_significant_threshold": cfg.drift_significant_threshold if cfg else 0.35,
    }
