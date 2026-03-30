"""
Metrics tab.

Displays:
  - Suppression analytics table (events ingested / per tier / suppression %)
  - Baseline stability score (when available)
  - Top-10 suppressed processes
  - Host-level JS divergence summary
"""
from __future__ import annotations

from collections import Counter

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinel.analysis.drift_monitor import HostDriftMonitor
from sentinel.gui.widgets import section_label


class MetricsTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # ── Suppression analytics ──────────────────────────────────────────────
        layout.addWidget(section_label("Suppression Analytics"))
        self._suppression_table = QTableWidget(0, 2)
        self._suppression_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self._suppression_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._suppression_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._suppression_table.setMaximumHeight(200)
        self._suppression_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self._suppression_table)

        # ── Top suppressed processes ───────────────────────────────────────────
        layout.addWidget(section_label("Top-10 Most Suppressed Processes"))
        self._top_procs_table = QTableWidget(0, 2)
        self._top_procs_table.setHorizontalHeaderLabels(["Process", "Suppressed Count"])
        self._top_procs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._top_procs_table.setMaximumHeight(200)
        self._top_procs_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self._top_procs_table)

        # ── Host drift summary ─────────────────────────────────────────────────
        layout.addWidget(section_label("Host Behavioral Drift (JSD)"))
        self._drift_table = QTableWidget(0, 3)
        self._drift_table.setHorizontalHeaderLabels(["Host", "Max JSD", "Drift Level"])
        self._drift_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._drift_table.setMaximumHeight(160)
        self._drift_table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self._drift_table)

        layout.addStretch()

    def populate(self, scored_events: list, metrics: dict, stability_score: float | None = None, cfg=None) -> None:
        """Fill metrics tab from scored events and metrics dict.

        Args:
            scored_events:  List of ScoredEvent objects from the analysis run.
            metrics:        Metrics dict from run_analysis().
            stability_score: Optional baseline stability score (0.0–1.0) to display.
        """
        self._populate_suppression(metrics, stability_score)
        self._populate_top_procs(metrics)
        mild = metrics.get("drift_mild_threshold", HostDriftMonitor.MILD_DRIFT)
        significant = metrics.get("drift_significant_threshold", HostDriftMonitor.SIGNIFICANT_DRIFT)
        self._populate_drift(scored_events, mild, significant)

    def _populate_suppression(self, metrics: dict, stability_score: float | None = None) -> None:
        rows = [
            ("Events parsed (raw)",       metrics.get("events_raw_total", 0)),
            ("Events scored",             metrics.get("events_scored", 0)),
            ("Tier 1 — Suppressed",       metrics.get("tier1_suppressed", 0)),
            ("Tier 2 — Aggregated",       metrics.get("tier2_aggregate", 0)),
            ("Tier 3 — Edge Cases",       metrics.get("tier3_highlight", 0)),
            ("Tier 4 — Critical Alerts",  metrics.get("tier4_critical", 0)),
            ("Suppression Rate",          f"{metrics.get('suppression_rate_pct', 0):.1f}%"),
        ]
        if stability_score is not None:
            if stability_score >= 0.6:
                label = f"{stability_score:.2f}  ✔ OK"
            elif stability_score >= 0.3:
                label = f"{stability_score:.2f}  ⚠ Warning"
            else:
                label = f"{stability_score:.2f}  ✘ Below threshold"
            rows.append(("Baseline Stability", label))

        self._suppression_table.setRowCount(len(rows))
        for r, (label, val) in enumerate(rows):
            self._suppression_table.setItem(r, 0, QTableWidgetItem(label))
            self._suppression_table.setItem(r, 1, QTableWidgetItem(str(val)))

    def _populate_top_procs(self, metrics: dict) -> None:
        top = metrics.get("top10_suppressed_processes", [])
        self._top_procs_table.setRowCount(len(top))
        for r, entry in enumerate(top):
            self._top_procs_table.setItem(r, 0, QTableWidgetItem(entry["process"]))
            self._top_procs_table.setItem(r, 1, QTableWidgetItem(str(entry["count"])))

    def _populate_drift(
        self,
        scored_events: list,
        mild: float = HostDriftMonitor.MILD_DRIFT,
        significant: float = HostDriftMonitor.SIGNIFICANT_DRIFT,
    ) -> None:
        """Summarize max JSD per host from scored events."""
        host_max_jsd: dict[str, float] = {}
        for ev in scored_events:
            host = ev.raw.host
            host_max_jsd[host] = max(host_max_jsd.get(host, 0.0), ev.host_drift)

        rows = sorted(host_max_jsd.items(), key=lambda x: x[1], reverse=True)
        self._drift_table.setRowCount(len(rows))
        for r, (host, jsd) in enumerate(rows):
            if jsd >= significant:
                level = "Significant"
            elif jsd >= mild:
                level = "Mild"
            else:
                level = "None"
            self._drift_table.setItem(r, 0, QTableWidgetItem(host))
            self._drift_table.setItem(r, 1, QTableWidgetItem(f"{jsd:.4f}"))
            self._drift_table.setItem(r, 2, QTableWidgetItem(level))

    def clear(self) -> None:
        self._suppression_table.setRowCount(0)
        self._top_procs_table.setRowCount(0)
        self._drift_table.setRowCount(0)
