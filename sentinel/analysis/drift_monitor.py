"""
Host-level behavioral drift monitor using Jensen-Shannon divergence.

JSD is computed between a rolling 30-minute process-name frequency distribution
and the baseline process-name distribution.  It is a host-level additive score
modifier, not a per-event score.

JSD range: [0, 1]
  JSD > 0.15 → mild drift
  JSD > 0.35 → significant drift
"""
from __future__ import annotations

import logging
import math
from collections import Counter, deque
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


def js_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """
    Jensen-Shannon divergence between distributions p and q.
    Symmetric, bounded [0, 1].  Returns 0.0 if both distributions are empty.
    """
    all_keys = set(p) | set(q)
    if not all_keys:
        return 0.0
    m = {k: 0.5 * (p.get(k, 0.0) + q.get(k, 0.0)) for k in all_keys}

    def _kl(a: dict, b: dict) -> float:
        return sum(
            a[k] * math.log2(a[k] / b[k])
            for k in a
            if a[k] > 0.0 and b.get(k, 0.0) > 0.0
        )

    return min(1.0, max(0.0, 0.5 * _kl(p, m) + 0.5 * _kl(q, m)))


class HostDriftMonitor:
    """
    Per-host rolling window drift monitor.

    One instance per host per analysis run.  Feed (timestamp, proc_name) tuples
    in chronological order via update().
    """

    MILD_DRIFT = 0.15
    SIGNIFICANT_DRIFT = 0.35

    def __init__(
        self,
        baseline_dist: dict[str, float],
        window_minutes: int = 30,
    ) -> None:
        self.baseline = baseline_dist
        self.window_td = timedelta(minutes=window_minutes)
        self._window: deque[tuple[datetime, str]] = deque()
        self._last_jsd: float = 0.0

    def update(self, ts: datetime, proc_name: str) -> float:
        """
        Add (ts, proc_name) to the rolling window and return current JSD.
        Evicts entries older than window_minutes.
        """
        # Guard against datetime.min fallback (unparseable timestamps) — subtracting
        # a timedelta from datetime.min raises OverflowError: date value out of range.
        if ts == datetime.min:
            logger.warning(
                "Skipping drift update for process %r — event has an unparseable "
                "timestamp (datetime.min). Check EVTX file for corrupt records.",
                proc_name,
            )
            return self._last_jsd
        self._window.append((ts, proc_name))
        try:
            cutoff = ts - self.window_td
        except OverflowError:
            logger.warning(
                "Skipping drift update for process %r — timestamp %s caused "
                "OverflowError when computing rolling window cutoff.",
                proc_name, ts,
            )
            return self._last_jsd
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

        counts = Counter(name for _, name in self._window)
        total = sum(counts.values()) or 1
        current_dist = {k: v / total for k, v in counts.items()}
        self._last_jsd = js_divergence(current_dist, self.baseline)
        return self._last_jsd

    @property
    def last_jsd(self) -> float:
        return self._last_jsd

    @property
    def drift_label(self) -> str:
        if self._last_jsd >= self.SIGNIFICANT_DRIFT:
            return "significant"
        if self._last_jsd >= self.MILD_DRIFT:
            return "mild"
        return "none"
