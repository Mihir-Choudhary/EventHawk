"""
Analysis tab.

Allows the user to:
  - Pick target EVTX files to analyze
  - Select which baseline to use (auto-populated from Baseline Setup tab)
  - Optionally pick a Sigma rules directory
  - Run the analysis pipeline in a background thread
"""
from __future__ import annotations

import logging
from pathlib import Path

from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)


class _AnalysisWorker(QThread):
    progress = Signal(str, float)
    finished = Signal(list, dict)   # scored_events, metrics
    error = Signal(str)

    def __init__(
        self,
        target_source: "Path | list[Path]",   # folder OR explicit file list
        baseline_dir: Path,
        sigma_dir: Path | None,
    ) -> None:
        super().__init__()
        self.target_source = target_source
        self.baseline_dir = baseline_dir
        self.sigma_dir = sigma_dir

    def run(self) -> None:
        try:
            from sentinel.analysis.engine import run_analysis

            # ── Resolve target paths ───────────────────────────────────────────
            if isinstance(self.target_source, list):
                target_paths = self.target_source
            else:
                # Folder given — auto-find relevant files
                from sentinel.analysis.parser import find_relevant_evtx_files

                def _scan_cb(step: str, pct: float) -> None:
                    self.progress.emit(step, pct * 0.10)

                self.progress.emit("Scanning EVTX files for process events...", 0.0)
                target_paths = find_relevant_evtx_files(
                    self.target_source, progress_cb=_scan_cb
                )
                if not target_paths:
                    self.error.emit(
                        "No EVTX files containing process-creation events (EID 4688/1) "
                        f"were found in:\n{self.target_source}\n\n"
                        "Sentinel requires Security.evtx (EID 4688) or Sysmon.evtx (EID 1)."
                    )
                    return
                self.progress.emit(
                    f"Found {len(target_paths)} relevant file(s) — running analysis...", 0.10
                )

            # ── Run analysis ──────────────────────────────────────────────────
            offset = 0.10 if not isinstance(self.target_source, list) else 0.0

            def _cb(step: str, pct: float) -> None:
                self.progress.emit(step, offset + pct * (1.0 - offset))

            scored, metrics = run_analysis(
                target_paths,
                self.baseline_dir,
                self.sigma_dir,
                progress_cb=_cb,
            )
            self.finished.emit(scored, metrics)
        except Exception as exc:
            logger.exception("Analysis failed")
            self.error.emit(str(exc))
            self.finished.emit([], {})  # Q2: always emit finished so UI re-enables button


class AnalysisTab(QWidget):
    # Emitted when analysis completes successfully
    analysis_complete = Signal(list, dict)  # scored_events, metrics

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: _AnalysisWorker | None = None
        self._baseline_dir: Path | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # ── Input group ────────────────────────────────────────────────────────
        input_group = QGroupBox("Analysis Input")
        form = QFormLayout(input_group)

        self._target_edit = QLineEdit()
        self._target_edit.setReadOnly(True)
        self._target_edit.setPlaceholderText(
            "Select a folder (auto-detects relevant files) or pick specific .evtx files..."
        )
        folder_btn = QPushButton("Folder...")
        folder_btn.setFixedWidth(72)
        folder_btn.setToolTip("Pick a folder — Sentinel will automatically find relevant EVTX files")
        folder_btn.clicked.connect(self._pick_target_folder)
        files_btn = QPushButton("Files...")
        files_btn.setFixedWidth(62)
        files_btn.setToolTip("Pick specific .evtx files")
        files_btn.clicked.connect(self._pick_target_files)
        target_row = QHBoxLayout()
        target_row.addWidget(self._target_edit)
        target_row.addWidget(folder_btn)
        target_row.addWidget(files_btn)
        form.addRow("Target EVTX:", target_row)

        self._baseline_edit = QLineEdit()
        self._baseline_edit.setReadOnly(True)
        self._baseline_edit.setPlaceholderText("Baseline artifacts directory (auto-filled from Baseline Setup tab)...")
        baseline_btn = QPushButton("Browse...")
        baseline_btn.setFixedWidth(90)
        baseline_btn.clicked.connect(self._pick_baseline_dir)
        baseline_row = QHBoxLayout()
        baseline_row.addWidget(self._baseline_edit)
        baseline_row.addWidget(baseline_btn)
        form.addRow("Baseline Dir:", baseline_row)

        self._sigma_edit = QLineEdit()
        self._sigma_edit.setReadOnly(True)
        self._sigma_edit.setPlaceholderText("Optional: Sigma rules directory...")
        sigma_btn = QPushButton("Browse...")
        sigma_btn.setFixedWidth(90)
        sigma_btn.clicked.connect(self._pick_sigma_dir)
        sigma_row = QHBoxLayout()
        sigma_row.addWidget(self._sigma_edit)
        sigma_row.addWidget(sigma_btn)
        form.addRow("Sigma Rules:", sigma_row)

        layout.addWidget(input_group)

        # ── Progress ───────────────────────────────────────────────────────────
        run_group = QGroupBox("Analysis Run")
        run_layout = QVBoxLayout(run_group)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        run_layout.addWidget(self._progress_bar)

        self._status_label = QLabel("Ready")
        self._status_label.setAlignment(Qt.AlignCenter)
        run_layout.addWidget(self._status_label)

        self._run_btn = QPushButton("Run Analysis")
        self._run_btn.setFixedHeight(32)
        self._run_btn.clicked.connect(self._start_analysis)
        run_layout.addWidget(self._run_btn)

        layout.addWidget(run_group)

        # ── Log ────────────────────────────────────────────────────────────────
        log_group = QGroupBox("Analysis Log")
        log_layout = QVBoxLayout(log_group)
        self._log_edit = QTextEdit()
        self._log_edit.setReadOnly(True)
        self._log_edit.setMaximumHeight(160)
        self._log_edit.setStyleSheet("font-family: monospace; font-size: 11px;")
        log_layout.addWidget(self._log_edit)
        layout.addWidget(log_group)

        layout.addStretch()

        # Stored target source: either a folder Path or a list[Path] of specific files
        self._target_source: "Path | list[Path] | None" = None

    # ── File/folder picker callbacks ───────────────────────────────────────────

    def _pick_target_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Folder Containing Target EVTX Files")
        if d:
            self._target_source = Path(d)
            self._target_edit.setText(f"Folder: {d}")

    def _pick_target_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(
            self, "Select Target EVTX Files", "", "EVTX Files (*.evtx)"
        )
        if files:
            self._target_source = [Path(f) for f in files]
            self._target_edit.setText(f"{len(files)} file(s) selected")

    def _pick_baseline_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Baseline Artifacts Directory")
        if d:
            self._baseline_dir = Path(d)
            self._baseline_edit.setText(d)

    def _pick_sigma_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Sigma Rules Directory")
        if d:
            self._sigma_edit.setText(d)

    def set_baseline_dir(self, path: Path) -> None:
        """Called by the parent window when baseline is ready."""
        self._baseline_dir = path
        self._baseline_edit.setText(str(path))

    # ── Analysis run ───────────────────────────────────────────────────────────

    def _start_analysis(self) -> None:
        if self._target_source is None:
            QMessageBox.warning(
                self, "No Target",
                "Please select a target EVTX folder or specific files."
            )
            return
        if not self._baseline_dir:
            QMessageBox.warning(self, "No Baseline", "Please select a baseline artifacts directory.")
            return

        from sentinel.baseline.persistence import artifacts_exist
        if not artifacts_exist(self._baseline_dir):
            QMessageBox.warning(
                self, "Invalid Baseline",
                "The selected baseline directory is missing required artifacts.\n"
                "Please build or select a valid baseline first."
            )
            return

        sigma_text = self._sigma_edit.text().strip()
        sigma_dir = Path(sigma_text) if sigma_text else None

        if isinstance(self._target_source, list):
            self._log(f"Starting analysis: {len(self._target_source)} target file(s)")
        else:
            self._log(f"Starting analysis: scanning folder {self._target_source}")
        self._run_btn.setEnabled(False)
        self._progress_bar.setValue(0)

        self._worker = _AnalysisWorker(self._target_source, self._baseline_dir, sigma_dir)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, step: str, pct: float) -> None:
        self._progress_bar.setValue(int(pct * 100))
        self._status_label.setText(step)
        self._log(f"[{int(pct*100):3d}%] {step}")

    def _on_finished(self, scored: list, metrics: dict) -> None:
        self._run_btn.setEnabled(True)
        if not scored and not metrics:
            return  # error case — _on_error already handled UI feedback

        # B25: Legitimate completion with 0 scored events — inform user
        if not scored:
            raw_total = metrics.get("events_raw_total", 0)
            self._progress_bar.setValue(100)
            self._status_label.setText(
                f"Done — {raw_total} events parsed, 0 process-creation events scored. "
                "Ensure target files contain Security EID 4688 or Sysmon EID 1."
            )
            self._log(
                f"Analysis complete: {raw_total} raw events but 0 process-creation events. "
                "No results to display."
            )
            return

        self._progress_bar.setValue(100)
        t4 = metrics.get("tier4_critical", 0)
        t3 = metrics.get("tier3_highlight", 0)
        self._status_label.setText(
            f"Done — {metrics.get('events_scored', 0)} events scored, "
            f"Tier4={t4}, Tier3={t3}"
        )
        self._log(f"Analysis complete. Critical alerts: {t4}, Edge cases: {t3}")
        self.analysis_complete.emit(scored, metrics)

    def _on_error(self, msg: str) -> None:
        self._run_btn.setEnabled(True)
        self._status_label.setText("Error")
        self._log(f"ERROR: {msg}")
        QMessageBox.critical(self, "Analysis Failed", msg)

    def _log(self, msg: str) -> None:
        self._log_edit.append(msg)
