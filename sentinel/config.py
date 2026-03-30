"""
Sentinel global configuration.

All numeric knobs that drive detection sensitivity are collected here so they
can be tuned via a JSON file rather than requiring code changes.

Usage:
    from sentinel.config import SentinelConfig, load_config

    # Default (all baseline values):
    cfg = SentinelConfig()

    # From a JSON file:
    cfg = load_config(Path("my_sentinel_config.json"))
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class SentinelConfig:
    """All tunable parameters for Sentinel detection and scoring."""

    # ── Surprisal caps ────────────────────────────────────────────────────────
    max_surprisal: float = 20.0
    """Bits of surprisal above which cmdline/lineage scores are capped."""

    # ── Composite score weights (must sum to 1.0) ─────────────────────────────
    weight_cmdline: float = 0.35
    """Weight for command-line surprisal in the composite score."""
    weight_lineage: float = 0.25
    """Weight for parent-lineage surprisal in the composite score."""
    weight_trie: float = 0.25
    """Weight for ancestry-trie depth mismatch in the composite score."""
    weight_ppid: float = 0.15
    """Weight for PPID mismatch (spoofing) signal in the composite score."""

    # ── Bonus signal weights ──────────────────────────────────────────────────
    drift_bonus_weight: float = 0.10
    """Multiplicative host-drift bonus: raw_score × drift_jsd × this weight."""
    hash_bonus_weight: float = 0.10
    """Additive image-hash-mismatch bonus: 0–1 × this weight."""

    # ── Host drift monitor ────────────────────────────────────────────────────
    drift_window_minutes: int = 30
    """Rolling window size (in minutes) for the HostDriftMonitor."""
    drift_mild_threshold: float = 0.15
    """JSD above which drift is labeled 'mild'."""
    drift_significant_threshold: float = 0.35
    """JSD above which drift is labeled 'significant'."""

    # ── Baseline stability gate ───────────────────────────────────────────────
    stability_abort: float = 0.3
    """Baseline stability below this aborts the build."""
    stability_warn: float = 0.6
    """Baseline stability below this triggers a warning."""

    def validate(self) -> None:
        weight_sum = self.weight_cmdline + self.weight_lineage + self.weight_trie + self.weight_ppid
        if abs(weight_sum - 1.0) > 1e-6:
            raise ValueError(
                f"Scoring weights must sum to 1.0 (got {weight_sum:.4f}). "
                "Adjust weight_cmdline, weight_lineage, weight_trie, weight_ppid."
            )


def load_config(path: Path | None = None) -> SentinelConfig:
    """Load a SentinelConfig from a JSON file, or return defaults if path is None.

    Unknown keys in the JSON are ignored (forward-compatible).
    Invalid values raise ValueError after loading.
    """
    if path is None:
        return SentinelConfig()

    try:
        with open(path, encoding="utf-8") as fh:
            data: dict = json.load(fh)
    except FileNotFoundError:
        logger.warning("Config file not found: %s — using defaults", path)
        return SentinelConfig()
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in config file {path}: {exc}") from exc

    cfg = SentinelConfig()
    defaults = asdict(cfg)
    for key, val in data.items():
        if key in defaults:
            try:
                setattr(cfg, key, type(defaults[key])(val))
            except (ValueError, TypeError) as exc:
                logger.warning(
                    "Config key '%s' has invalid value %r (%s); using default %r",
                    key, val, exc, defaults[key],
                )
        else:
            logger.debug("Unknown config key ignored: %s", key)

    cfg.validate()
    logger.info("Loaded Sentinel config from %s", path)
    return cfg


def save_default_config(path: Path) -> None:
    """Write a default config JSON to path for user customization."""
    cfg = SentinelConfig()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(asdict(cfg), fh, indent=2)
    logger.info("Default Sentinel config written to %s", path)
