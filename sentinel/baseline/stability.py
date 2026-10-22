"""
Baseline stability validator.

Computes a volatility score (0.0 = chaotic, 1.0 = perfectly stable) over the
set of baseline events before any models are built.  If the baseline itself is
highly volatile the differential analysis becomes unreliable.

Stability metric:
  For each unique process name, count:
    - N_i  = total events for process i
    - U_i  = unique normalized cmdline templates for process i
  volatility_i = U_i / N_i   (0 if only one unique cmdline, 1 if every event is unique)
  overall_volatility = mean(volatility_i weighted by N_i)
  stability = 1.0 - overall_volatility

Thresholds:
  < 0.3  → ABORT (baseline too short or potentially compromised)
  < 0.6  → WARN  (analysis may produce elevated false positives)
  >= 0.6 → OK
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models import RawEvent

logger = logging.getLogger(__name__)

ABORT_THRESHOLD = 0.3
WARN_THRESHOLD = 0.6


def baseline_stability(
    events: list["RawEvent"],
    normalize_fn=None,
) -> float:
    """
    Compute stability score for a list of RawEvents.

    Args:
        events: list of RawEvent (process_name and cmdline required)
        normalize_fn: callable(cmdline: str) -> str.  If None, raw cmdline is used.

    Returns:
        float in [0.0, 1.0]
    """
    if not events:
        return 0.0

    if normalize_fn is None:
        def normalize_fn(c: str) -> str:
            return c

    # Only score create events — termination/access events (4689, 5, 8, 10) have
    # empty command lines which inflate volatility and can cause valid baselines
    # to be incorrectly rejected.
    _CREATE_IDS = {4688, 1}
    create_events = [ev for ev in events if ev.event_id in _CREATE_IDS]
    if not create_events:
        logger.warning(
            "Stability check: no process-creation events (4688/1) found in %d events; "
            "returning stability=0.0",
            len(events),
        )
        return 0.0

    per_process: dict[str, list[str]] = defaultdict(list)
    for ev in create_events:
        per_process[ev.process_name].append(normalize_fn(ev.cmdline))

    total_events = 0
    weighted_volatility = 0.0

    for proc, cmdlines in per_process.items():
        n = len(cmdlines)
        u = len(set(cmdlines))
        volatility = u / n if n > 0 else 0.0
        weighted_volatility += volatility * n
        total_events += n

    overall_volatility = weighted_volatility / total_events if total_events else 0.0
    score = max(0.0, min(1.0, 1.0 - overall_volatility))

    if score < ABORT_THRESHOLD:
        logger.error(
            "Baseline stability %.2f is below abort threshold %.2f. "
            "Baseline may be too short or already compromised. Refusing to build.",
            score, ABORT_THRESHOLD,
        )
    elif score < WARN_THRESHOLD:
        logger.warning(
            "Baseline stability %.2f is below recommended threshold %.2f. "
            "Analysis may produce elevated false positive rates.",
            score, WARN_THRESHOLD,
        )
    else:
        logger.info("Baseline stability score: %.2f (OK)", score)

    return score
