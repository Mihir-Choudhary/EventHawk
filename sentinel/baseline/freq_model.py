"""
Frequency model for Laplace-smoothed surprisal scoring.

Three independent probability tables:
  - P(cmdline_norm | proc_norm)           → cmdline surprisal
  - P(proc_norm    | parent_norm)         → lineage surprisal
  - triplet counter (proc, parent, cmd)   → high-precision combined lookup

All surprisal values are in bits (-log2 probability).
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models import NormalizedEvent

# Maximum surprisal cap (bits).  Applies when proc/parent is entirely unseen.
MAX_SURPRISAL: float = 20.0


@dataclass
class FrequencyModel:
    # P(cmdline_norm | proc_norm)
    cmdline_given_proc: defaultdict[str, Counter] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    # P(proc_norm | parent_norm)
    proc_given_parent: defaultdict[str, Counter] = field(
        default_factory=lambda: defaultdict(Counter)
    )
    # Combined triplet counter (proc_norm, parent_norm, cmdline_norm)
    triplet: Counter = field(default_factory=Counter)

    # Totals for Laplace denominator
    cmdline_totals: Counter = field(default_factory=Counter)
    proc_totals: Counter = field(default_factory=Counter)


def build_freq_model(events: list["NormalizedEvent"]) -> FrequencyModel:
    """Build frequency tables from a list of NormalizedEvents."""
    m = FrequencyModel()
    for ev in events:
        m.cmdline_given_proc[ev.proc_norm][ev.cmdline_norm] += 1
        m.cmdline_totals[ev.proc_norm] += 1
        m.proc_given_parent[ev.parent_norm][ev.proc_norm] += 1
        m.proc_totals[ev.parent_norm] += 1
        m.triplet[(ev.proc_norm, ev.parent_norm, ev.cmdline_norm)] += 1
    return m


def surprisal_cmdline(model: FrequencyModel, proc: str, cmdline: str) -> float:
    """
    Laplace-smoothed surprisal of (cmdline | proc) in bits.
    Returns MAX_SURPRISAL if proc is entirely unseen in baseline.
    """
    total = model.cmdline_totals[proc]
    if total == 0:
        return MAX_SURPRISAL  # proc unseen; scored by lineage surprisal
    count = model.cmdline_given_proc[proc][cmdline]
    vocab = len(model.cmdline_given_proc[proc]) or 1
    p = (count + 1) / (total + vocab)
    return min(-math.log2(p), MAX_SURPRISAL)


def surprisal_lineage(model: FrequencyModel, proc: str, parent: str) -> float:
    """
    Laplace-smoothed surprisal of (proc | parent) in bits.
    Returns MAX_SURPRISAL if parent is entirely unseen in baseline.
    """
    total = model.proc_totals[parent]
    if total == 0:
        return MAX_SURPRISAL  # parent unseen
    count = model.proc_given_parent[parent][proc]
    vocab = len(model.proc_given_parent[parent]) or 1
    p = (count + 1) / (total + vocab)
    return min(-math.log2(p), MAX_SURPRISAL)


def build_process_distribution(model: FrequencyModel) -> dict[str, float]:
    """
    Return normalized frequency of each process name across ALL parents.
    Used as the baseline distribution for the HostDriftMonitor.
    """
    total_count: Counter = Counter()
    for parent_counts in model.proc_given_parent.values():
        total_count.update(parent_counts)
    grand_total = sum(total_count.values()) or 1
    return {proc: count / grand_total for proc, count in total_count.items()}
