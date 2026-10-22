"""
Baseline build orchestrator (Phase 0).

Coordinates:
  0.1  Parser (via sentinel.analysis.parser)
  0.2  Stability validation
  0.3  Sigma pre-tagging
  0.4  Normalization
  0.5  Frequency model construction
  0.6  Ancestry trie construction
  0.7  Fuse filter construction
  0.8  Artifact persistence

Progress is reported via an optional callback: progress_cb(step: str, pct: float)
where pct is 0.0–1.0.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sentinel.analysis.normalizer import normalize_cmdline, normalize_procname
from sentinel.baseline.freq_model import build_freq_model, build_process_distribution
from sentinel.baseline.fuse_store import FuseStore
from sentinel.baseline.persistence import save_artifacts
from sentinel.baseline.stability import (
    ABORT_THRESHOLD,
    WARN_THRESHOLD,
    baseline_stability,
)
from sentinel.baseline.trie import AncestryTrie
from sentinel.models import BaselineMeta, NormalizedEvent, RawEvent, TierBoundaries

logger = logging.getLogger(__name__)

_MAX_ANCESTRY_DEPTH = 5


def build_baseline(
    evtx_paths: list[Path],
    output_dir: Path,
    sigma_rules_dir: Path | None = None,
    progress_cb: Callable[[str, float], None] | None = None,
) -> BaselineMeta:
    """
    Full Phase 0 pipeline.

    Args:
        evtx_paths:     List of .evtx files to parse as baseline.
        output_dir:     Where to write all artifact files.
        sigma_rules_dir: Optional path to Sigma rules directory for pre-tagging.
        progress_cb:    Optional callback (step_name, 0.0–1.0).

    Returns:
        BaselineMeta describing the built baseline.

    Raises:
        ValueError: if stability is below ABORT_THRESHOLD.
    """
    def _cb(step: str, pct: float) -> None:
        if progress_cb:
            progress_cb(step, pct)
        logger.debug("build_baseline [%.0f%%] %s", pct * 100, step)

    # ── 0.1  Parse ────────────────────────────────────────────────────────────
    # F11/S5: Hash input files before parsing for forensic chain-of-custody
    _cb("Hashing input EVTX files", 0.0)
    from sentinel.analysis.parser import hash_evtx_files, parse_evtx_files
    input_file_hashes = hash_evtx_files(evtx_paths)
    logger.info("Baseline input file hashes: %s", input_file_hashes)

    _cb("Parsing EVTX files", 0.02)
    raw_events: list[RawEvent] = parse_evtx_files(evtx_paths, progress_cb=None)
    logger.info("Parsed %d raw events from %d files", len(raw_events), len(evtx_paths))
    if not raw_events:
        # Run diagnostic to give the user a meaningful error message
        from sentinel.analysis.parser import diagnose_evtx_files
        diag = diagnose_evtx_files(evtx_paths)
        top_ids = diag.get("top_event_ids", [])
        top_str = ", ".join(f"EID {eid}×{cnt}" for eid, cnt in top_ids[:8]) or "none"
        raise ValueError(
            f"No process-creation events found (Event IDs 4688/1) in the provided EVTX files.\n\n"
            f"Top event IDs in your files: {top_str}\n\n"
            f"Sentinel requires Security.evtx (Event ID 4688) or Sysmon.evtx (Event ID 1).\n"
            f"Application.evtx, System.evtx, and other logs are not supported."
        )

    # ── 0.2  Stability validation ──────────────────────────────────────────────
    _cb("Validating baseline stability", 0.05)
    stability = baseline_stability(raw_events, normalize_fn=normalize_cmdline)
    if stability < ABORT_THRESHOLD:
        raise ValueError(
            f"Baseline stability {stability:.2f} is below abort threshold "
            f"{ABORT_THRESHOLD}. Baseline is too short or potentially compromised."
        )

    # ── 0.3  Sigma pre-tagging ────────────────────────────────────────────────
    _cb("Sigma pre-tagging", 0.10)
    if sigma_rules_dir and sigma_rules_dir.exists():
        from sentinel.analysis.sigma_tagger import SigmaTagger
        tagger = SigmaTagger(sigma_rules_dir)
        for ev in raw_events:
            ev.attck_tags = tagger.tag(ev)
        logger.info("Sigma pre-tagging complete")
    else:
        logger.info("No Sigma rules directory provided; skipping pre-tagging")

    # ── 0.4  Normalization ────────────────────────────────────────────────────
    # Filter to process-create events only before building models.
    # Terminate/access events (4689, 5, 8, 10) have no cmdline or parent info;
    # including them pollutes the freq model with empty-parent entries that
    # suppress alerts for processes launched without a resolvable lineage.
    _cb("Normalizing events", 0.15)
    create_events = [ev for ev in raw_events if ev.event_id in {4688, 1}]
    normalized: list[NormalizedEvent] = _normalize_all(create_events)

    # ── 0.5  Frequency model ──────────────────────────────────────────────────
    _cb("Building frequency model", 0.40)
    freq_model = build_freq_model(normalized)

    # ── 0.6  Ancestry trie ────────────────────────────────────────────────────
    _cb("Building ancestry trie", 0.60)
    trie = _build_trie(normalized)

    # ── 0.7  Fuse filter ──────────────────────────────────────────────────────
    _cb("Building fuse filter", 0.75)
    fuse = FuseStore()
    fuse.build(normalized)

    # ── Tier calibration (score baseline events, compute percentiles) ──────────
    _cb("Calibrating tier boundaries", 0.85)
    tier_boundaries = _calibrate_tiers(normalized, freq_model, trie)

    # ── Process distribution for JSD ─────────────────────────────────────────
    process_dist = build_process_distribution(freq_model)

    # ── Timestamps ────────────────────────────────────────────────────────────
    timestamps = sorted(ev.raw.timestamp for ev in normalized)
    start_ts = timestamps[0].isoformat() if timestamps else ""
    end_ts = timestamps[-1].isoformat() if timestamps else ""

    meta = BaselineMeta(
        host=_dominant_host(raw_events),
        start_ts=start_ts,
        end_ts=end_ts,
        stability_score=round(stability, 4),
        event_count=len(normalized),
        build_ts=datetime.now(timezone.utc).isoformat(),
        tier_boundaries={
            "suppress_max":  round(tier_boundaries.suppress_max, 2),
            "aggregate_max": round(tier_boundaries.aggregate_max, 2),
            "highlight_max": round(tier_boundaries.highlight_max, 2),
        },
        baseline_process_dist=process_dist,
        input_file_hashes=input_file_hashes,
    )

    # ── 0.8  Persist ──────────────────────────────────────────────────────────
    _cb("Saving artifacts", 0.90)
    save_artifacts(output_dir, meta, freq_model, trie, fuse, normalized)
    _cb("Done", 1.0)

    logger.info(
        "Baseline build complete. %d events, stability=%.2f, tiers=%s",
        len(normalized), stability, meta.tier_boundaries,
    )
    return meta


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_all(raw_events: list[RawEvent]) -> list[NormalizedEvent]:
    normalized = []
    for ev in raw_events:
        proc_norm = normalize_procname(ev.process_name)
        parent_norm = normalize_procname(ev.parent_name)
        cmdline_norm = normalize_cmdline(ev.cmdline)
        chain = [proc_norm, parent_norm]  # extend with grandparent if available
        normalized.append(NormalizedEvent(
            raw=ev,
            proc_norm=proc_norm,
            parent_norm=parent_norm,
            cmdline_norm=cmdline_norm,
            ancestry_chain=chain,
        ))
    return normalized


def _build_trie(normalized: list[NormalizedEvent]) -> AncestryTrie:
    trie = AncestryTrie()
    # Build ancestry chains: we only have proc + parent from Security logs.
    # Sysmon would provide full chains; for now use depth-2 (proc, parent).
    for ev in normalized:
        chain = ev.ancestry_chain[:_MAX_ANCESTRY_DEPTH]
        if chain:
            trie.insert(chain)
    return trie


def _calibrate_tiers(
    normalized: list[NormalizedEvent],
    freq_model,
    trie: AncestryTrie,
) -> TierBoundaries:
    from sentinel.analysis.scorer import composite_score, trie_depth_score
    from sentinel.baseline.freq_model import surprisal_cmdline, surprisal_lineage

    scores = []
    for ev in normalized:
        s_cmd = surprisal_cmdline(freq_model, ev.proc_norm, ev.cmdline_norm)
        s_lin = surprisal_lineage(freq_model, ev.proc_norm, ev.parent_norm)
        depth, _ = trie.query(ev.ancestry_chain)
        t_score = trie_depth_score(depth, len(ev.ancestry_chain))  # B17: use shared formula
        score = composite_score(s_cmd, s_lin, t_score, 0.0, 0.0)
        scores.append(score)

    if not scores:
        return TierBoundaries()

    arr = sorted(scores)
    n = len(arr)

    def _pct(p: float) -> float:
        idx = min(int(n * p), n - 1)
        return arr[idx]

    return TierBoundaries(
        suppress_max=_pct(0.90),
        aggregate_max=_pct(0.97),
        highlight_max=_pct(0.998),
    )


def _dominant_host(events: list[RawEvent]) -> str:
    if not events:
        return ""
    c: Counter = Counter(ev.host for ev in events)
    return c.most_common(1)[0][0]
