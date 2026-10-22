"""
Shared dataclasses used across sentinel modules.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class RawEvent:
    """Structured event as parsed from EVTX or Sysmon XML, before normalization."""
    timestamp: datetime
    host: str
    event_id: int
    process_guid: str        # Sysmon ProcessGuid (UUID); empty string if Security log
    pid: int
    ppid: int
    parent_guid: str         # Sysmon ParentProcessGuid; empty string if Security log
    process_name: str        # executable filename only, no path
    process_path: str        # full path
    parent_name: str
    parent_path: str
    cmdline: str
    user: str
    integrity_level: str     # High / Medium / Low / System / ""
    image_hash: str          # SHA256 from Sysmon; empty string otherwise
    attck_tags: list[str] = field(default_factory=list)
    flags: set[str] = field(default_factory=set)


@dataclass
class NormalizedEvent:
    """Event after normalization pipeline."""
    raw: RawEvent
    proc_norm: str           # normalized process name
    parent_norm: str         # normalized parent name
    cmdline_norm: str        # normalized cmdline
    ancestry_chain: list[str] = field(default_factory=list)  # [proc, parent, grandparent, ...]


@dataclass
class ScoredEvent:
    """Event with all sub-scores and final composite score."""
    normalized: NormalizedEvent
    surprisal_cmdline: float = 0.0
    surprisal_lineage: float = 0.0
    trie_depth_score: float = 0.0    # 0.0 = baseline match, 1.0 = unseen
    ppid_flag: float = 0.0           # 0.0 or 1.0
    host_drift: float = 0.0          # JSD value at time of event
    composite: float = 0.0           # final 0-100 score
    tier: int = 1                    # 1=suppress, 2=aggregate, 3=highlight, 4=critical
    justification_text: str = ""

    @property
    def raw(self) -> RawEvent:
        return self.normalized.raw


@dataclass
class TierBoundaries:
    """Percentile-calibrated tier thresholds."""
    suppress_max: float = 20.0    # below → tier 1 (suppress)
    aggregate_max: float = 45.0   # below → tier 2 (aggregate)
    highlight_max: float = 70.0   # below → tier 3 (highlight/edge case)
    # above highlight_max → tier 4 (critical alert)

    def classify(self, score: float) -> int:
        if score <= self.suppress_max:
            return 1
        if score <= self.aggregate_max:
            return 2
        if score <= self.highlight_max:
            return 3
        return 4

    def for_scoring(self, drift_bonus_weight: float) -> "TierBoundaries":
        """Return the boundaries to classify analysis scores with.

        Percentile calibration over a small or uniform baseline collapses all
        three boundaries onto the baseline's own top score (seen: 3.5/3.5/3.5).
        Two things then combined: Tiers 2 and 3 had zero width, and the
        baseline was scored with no host drift while analysis adds up to
        ``drift_bonus_weight`` of the score for it.  A baseline-identical boot
        event (autochk.exe <- smss.exe) nudged from 3.5 to 3.6 by drift went
        straight to Tier 4.

        * suppress_max stays baseline-calibrated -- raising it to a fixed
          floor would suppress, e.g., an unseen command line of a known
          process (measured at 11.1) -- plus exactly the headroom the drift
          bonus can add, so drift alone cannot lift a baseline-level event out
          of Tier 1 but anything genuinely new still leaves it.
        * aggregate_max / highlight_max are floored at the documented 45 / 70
          so the bands cannot collapse.  This only moves events among Tiers
          2-4; it never suppresses one.
        """
        d = TierBoundaries()
        suppress = math.ceil(self.suppress_max * (1.0 + drift_bonus_weight) * 10) / 10
        aggregate = max(self.aggregate_max, d.aggregate_max, suppress)
        return TierBoundaries(
            suppress_max=suppress,
            aggregate_max=aggregate,
            highlight_max=max(self.highlight_max, d.highlight_max, aggregate),
        )

    def as_dict(self) -> dict:
        return {"suppress_max": self.suppress_max,
                "aggregate_max": self.aggregate_max,
                "highlight_max": self.highlight_max}


@dataclass
class BaselineMeta:
    """Metadata stored alongside baseline artifacts."""
    host: str
    start_ts: str             # ISO format
    end_ts: str               # ISO format
    stability_score: float
    event_count: int
    build_ts: str             # ISO format
    tier_boundaries: dict     # {"suppress_max": float, ...}
    baseline_process_dist: dict  # {proc_name: float} normalized freq for JSD baseline
    # F11/S5: SHA-256 hashes of all baseline input files (chain-of-custody)
    input_file_hashes: dict = field(default_factory=dict)  # {filename: sha256_hex}
