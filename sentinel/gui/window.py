"""
SentinelWindow — main QDialog for the Sentinel Baseline Engine.

Launched from evtx_tool's main_window.py as a child QDialog:
    win = SentinelWindow(parent=self)
    win.show()

The dialog owns 4 tabs:
  [0] Baseline Setup  — build or load a baseline
  [1] Analysis        — run analysis against a target
  [2] Results         — tier-classified alerts
  [3] Metrics         — suppression analytics + drift summary
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMenuBar,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from sentinel.gui.analysis_tab import AnalysisTab
from sentinel.gui.baseline_tab import BaselineTab
from sentinel.gui.metrics_tab import MetricsTab
from sentinel.gui.results_tab import ResultsTab

logger = logging.getLogger(__name__)


class SentinelWindow(QDialog):
    """
    Sentinel Baseline Engine standalone window.
    Parented to the main evtx_tool window so it closes automatically when
    the parent closes.  Uses QDialog (not QMainWindow) to avoid a separate
    taskbar entry and to be trivially removable.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Sentinel Baseline Engine")
        self.setMinimumSize(1000, 720)
        self.setWindowFlags(
            Qt.Window |
            Qt.WindowMinimizeButtonHint |
            Qt.WindowMaximizeButtonHint |
            Qt.WindowCloseButtonHint
        )
        self.setSizeGripEnabled(True)

        self._scored_events: list = []
        self._metrics: dict = {}
        self._last_report_path: Path | None = None

        self._setup_ui()
        self._connect_signals()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(2)

        # ── Menu bar ───────────────────────────────────────────────────────────
        menubar = QMenuBar(self)
        file_menu = menubar.addMenu("File")
        file_menu.addAction("Export Report (JSON)...", self._export_report)
        file_menu.addSeparator()
        file_menu.addAction("Close", self.close)

        help_menu = menubar.addMenu("Help")
        help_menu.addAction("About...", self._show_about)

        root.addWidget(menubar)

        # ── Tab widget ─────────────────────────────────────────────────────────
        self._tabs = QTabWidget()
        self._tabs.setTabPosition(QTabWidget.North)

        self._baseline_tab = BaselineTab()
        self._analysis_tab = AnalysisTab()
        self._results_tab = ResultsTab()
        self._metrics_tab = MetricsTab()

        self._tabs.addTab(self._baseline_tab, "Baseline Setup")
        self._tabs.addTab(self._analysis_tab, "Analysis")
        self._tabs.addTab(self._results_tab, "Results")
        self._tabs.addTab(self._metrics_tab, "Metrics")

        # Results and Metrics tabs are empty until analysis completes
        self._tabs.setTabEnabled(2, False)
        self._tabs.setTabEnabled(3, False)

        root.addWidget(self._tabs)

        # ── Status bar ─────────────────────────────────────────────────────────
        status_row = QHBoxLayout()
        self._status_label = QLabel("Ready — Build or load a baseline to begin.")
        status_row.addWidget(self._status_label)
        status_row.addStretch()

        self._jump_results_btn = QPushButton("View Results →")
        self._jump_results_btn.setVisible(False)
        self._jump_results_btn.clicked.connect(
            lambda: self._tabs.setCurrentWidget(self._results_tab)
        )
        status_row.addWidget(self._jump_results_btn)

        root.addLayout(status_row)

    def _connect_signals(self) -> None:
        self._baseline_tab.baseline_ready.connect(self._on_baseline_ready)
        self._analysis_tab.analysis_complete.connect(self._on_analysis_complete)

    # ── Signal handlers ────────────────────────────────────────────────────────

    def _on_baseline_ready(self, artifact_dir: Path) -> None:
        self._analysis_tab.set_baseline_dir(artifact_dir)
        self._status_label.setText(
            f"Baseline ready: {artifact_dir.name} — Switch to Analysis tab to run."
        )
        self._tabs.setTabEnabled(1, True)
        self._tabs.setCurrentIndex(1)

    def _on_analysis_complete(self, scored_events: list, metrics: dict) -> None:
        self._scored_events = scored_events
        self._metrics = metrics

        t4 = metrics.get("tier4_critical", 0)
        t3 = metrics.get("tier3_highlight", 0)
        total = metrics.get("events_scored", 0)
        rate = metrics.get("suppression_rate_pct", 0)

        self._status_label.setText(
            f"Analysis complete — {total} events scored | "
            f"Tier 4: {t4} critical | Tier 3: {t3} edge cases | "
            f"Suppression: {rate:.1f}%"
        )

        self._results_tab.populate(scored_events)
        self._metrics_tab.populate(scored_events, metrics)

        self._jump_results_btn.setVisible(True)
        self._tabs.setTabEnabled(2, True)
        self._tabs.setTabEnabled(3, True)
        self._tabs.setCurrentIndex(2)

        if t4 > 0:
            QMessageBox.warning(
                self,
                "Critical Alerts Detected",
                f"{t4} critical alert(s) detected in Tier 4.\n"
                f"Review the Results tab immediately.",
            )

    # ── Menu actions ───────────────────────────────────────────────────────────

    def _export_report(self) -> None:
        if not self._scored_events:
            QMessageBox.information(self, "No Results", "Run an analysis first.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", "sentinel_report.json",
            "JSON Files (*.json)"
        )
        if not path:
            return

        try:
            from sentinel.baseline.persistence import load_artifacts
            from sentinel.models import BaselineMeta
            baseline_dir = self._analysis_tab._baseline_dir
            if baseline_dir:
                meta, _, _, _ = load_artifacts(baseline_dir)
            else:
                # Fallback stub so generate_report never receives None
                meta = BaselineMeta(
                    host="unknown", start_ts="", end_ts="",
                    stability_score=0.0, event_count=0, build_ts="",
                    tier_boundaries={}, baseline_process_dist={},
                    input_file_hashes={},
                )

            from sentinel.report.generator import generate_report
            generate_report(
                self._scored_events,
                self._metrics,
                meta,
                output_path=Path(path),
            )
            self._last_report_path = Path(path)
            QMessageBox.information(
                self, "Export Complete",
                f"Report saved to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
            logger.exception("Report export failed")

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About Sentinel Baseline Engine",
            "Sentinel Baseline Engine v0.1\n\n"
            "Deterministic, non-ML differential log analysis for Windows EVTX.\n\n"
            "Compares process execution behavior against a known-good baseline\n"
            "using surprisal scoring, ancestry trie, and Jensen-Shannon divergence.\n\n"
            "Fully standalone — no dependencies on evtx_tool internals."
        )
