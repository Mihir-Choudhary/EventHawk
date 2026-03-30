"""
Programmatic justification string builder for Tier 3/4 scored events.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

# Q4: Use HostDriftMonitor constants instead of magic numbers
from sentinel.analysis.drift_monitor import HostDriftMonitor

if TYPE_CHECKING:
    from sentinel.baseline.trie import AncestryTrie
    from sentinel.models import ScoredEvent

_HIGH_SURPRISAL_BITS = 12.0


def build_justification(ev: "ScoredEvent", trie: "AncestryTrie") -> str:
    """
    Produce a human-readable justification string explaining why this event
    was flagged.  Used in the Tier 3 Results table and Tier 4 alert detail.
    """
    parts: list[str] = []
    norm = ev.normalized

    # PPID spoofing (highest priority — explicit attack indicator)
    if 'PPID_MISMATCH' in ev.raw.flags:
        parts.append(
            "PPID spoofing detected: reported parent PID was terminated "
            "before this process started"
        )

    # Anomalous lineage
    if ev.trie_depth_score > 0.5:
        expected_parent = trie.most_common_parent(norm.proc_norm)
        observed = norm.parent_norm or "(unknown)"
        if expected_parent and expected_parent != observed:
            parts.append(
                f"Anomalous lineage: common parent for '{norm.proc_norm}' "
                f"is '{expected_parent}', observed '{observed}'"
            )
        elif not expected_parent:
            parts.append(
                f"Process '{norm.proc_norm}' not seen in baseline "
                f"ancestry trie (depth score={ev.trie_depth_score:.2f})"
            )

    # Rare command line
    if ev.surprisal_cmdline > _HIGH_SURPRISAL_BITS:
        parts.append(
            f"Rare cmdline pattern for '{norm.proc_norm}' "
            f"({ev.surprisal_cmdline:.1f} bits surprisal — "
            f"higher = more anomalous)"
        )

    # Rare lineage pair
    if ev.surprisal_lineage > _HIGH_SURPRISAL_BITS and ev.trie_depth_score <= 0.5:
        parts.append(
            f"Uncommon parent-child pair: '{norm.parent_norm}' → "
            f"'{norm.proc_norm}' ({ev.surprisal_lineage:.1f} bits)"
        )

    # Host drift — use HostDriftMonitor constants (Q4: no magic numbers)
    if ev.host_drift >= HostDriftMonitor.SIGNIFICANT_DRIFT:
        parts.append(
            f"Significant host-level behavioral drift at time of event "
            f"(JSD={ev.host_drift:.3f})"
        )
    elif ev.host_drift >= HostDriftMonitor.MILD_DRIFT:
        parts.append(f"Mild host behavioral drift (JSD={ev.host_drift:.3f})")

    return "; ".join(parts) if parts else "Minor argument drift"
