"""
Score aggregation and tier classification.

Composite score formula:
  s_cmd = min(surprisal_cmdline, MAX_SURPRISAL) / MAX_SURPRISAL
  s_lin = min(surprisal_lineage, MAX_SURPRISAL) / MAX_SURPRISAL

  raw = w_cmd*s_cmd + w_lin*s_lin + w_trie*trie_depth + w_ppid*ppid_flag
  drift_bonus  = raw * host_drift * drift_bonus_weight
  hash_bonus   = hash_mismatch_signal * hash_bonus_weight
  final = min(1.0, raw + drift_bonus + hash_bonus) * 100   → 0–100

All weights and bonus multipliers are read from SentinelConfig so they
can be tuned via a JSON config file without code changes.
"""
from __future__ import annotations

from sentinel.baseline.freq_model import MAX_SURPRISAL
from sentinel.config import SentinelConfig

# Module-level default config (used when no config is passed explicitly)
_DEFAULT_CFG = SentinelConfig()


def composite_score(
    surprisal_cmd: float,
    surprisal_lin: float,
    trie_depth:    float,   # 0.0–1.0 (0=baseline match, 1=unseen)
    ppid_flag:     float,   # 0.0 or 1.0
    host_drift:    float,   # JSD 0.0–1.0
    hash_bonus:    float = 0.0,  # 0.0–1.0 (0=no data or match, 1=mismatch)
    cfg: SentinelConfig | None = None,
) -> float:
    """Return a composite anomaly score in [0.0, 100.0].

    Args:
        surprisal_cmd: Cmdline surprisal in bits.
        surprisal_lin: Parent-lineage surprisal in bits.
        trie_depth:    Ancestry trie depth score (0=match, 1=unseen).
        ppid_flag:     1.0 if PPID spoofing detected, else 0.0.
        host_drift:    Jensen-Shannon divergence (0.0–1.0).
        hash_bonus:    Image hash mismatch signal (0.0 or 1.0).
        cfg:           Optional SentinelConfig; uses module defaults if None.
    """
    c = cfg or _DEFAULT_CFG
    s_cmd = min(surprisal_cmd, MAX_SURPRISAL) / MAX_SURPRISAL
    s_lin = min(surprisal_lin, MAX_SURPRISAL) / MAX_SURPRISAL

    raw = (
        c.weight_cmdline * s_cmd +
        c.weight_lineage * s_lin +
        c.weight_trie    * trie_depth +
        c.weight_ppid    * ppid_flag
    )

    drift_contribution = raw * host_drift * c.drift_bonus_weight
    hash_contribution  = hash_bonus * c.hash_bonus_weight
    final = min(1.0, raw + drift_contribution + hash_contribution)
    return round(final * 100.0, 1)


def trie_depth_score(match_depth: int, chain_len: int) -> float:
    """
    Convert (match_depth, chain_len) → [0.0, 1.0] anomaly score.
    0.0 = full baseline match, 1.0 = process unseen at root.
    """
    max_depth = min(chain_len, 5)
    if max_depth == 0:
        return 1.0
    return 1.0 - (match_depth / max_depth)


def image_hash_bonus(
    proc_norm: str,
    event_hash: str,
    known_hashes: dict[str, set[str]],
) -> float:
    """Return an anomaly bonus when a process is seen with a new/mismatched image hash.

    Uses Sysmon's Hashes field (SHA256/MD5/SHA1 concatenated string).  If the
    process has been seen before with a *different* hash, this likely indicates
    a trojanized or substituted binary — high-value detection signal.

    Returns:
        0.0 — no Sysmon hash available, or first time seeing this process,
              or hash matches a previously seen hash (expected)
        1.0 — process seen before but with a DIFFERENT hash (suspicious)
    """
    if not event_hash or not proc_norm:
        return 0.0
    prev = known_hashes.get(proc_norm)
    if not prev:
        return 0.0   # first occurrence — no baseline to compare against
    if event_hash in prev:
        return 0.0   # hash matches a known-good hash for this process
    return 1.0       # hash mismatch: likely binary substitution
