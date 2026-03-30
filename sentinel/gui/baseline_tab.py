"""
Baseline Setup tab.

Allows the user to:
  - Pick a folder of baseline EVTX files
  - Optionally pick a Sigma rules directory
  - Set output directory for artifacts
  - Build the baseline (runs in a background QThread)
  - Load a previously built baseline
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


class _BuildWorker(QThread):
    progress = Signal(str, float)    # step, 0.0-1.0
    finished = Signal(object)        # BaselineMeta or None on error
    error = Signal(str)

    def __init__(
        self,
        evtx_folder: Path,
        output_dir: Path,
        sigma_dir: Path | None,
    ) -> None:
        super().__init__()
        self.evtx_folder = evtx_folder
        self.output_dir = output_dir
        self.sigma_dir = sigma_dir

    def run(self) -> None:
        try:
            from sentinel.analysis.parser import find_relevant_evtx_files
            from sentinel.baseline.builder import build_baseline

            # ── Step 1: auto-find files containing target event IDs ────────────
            def _scan_cb(step: str, pct: float) -> None:
                # Scale scan progress to 0-10% of total
                self.progress.emit(step, pct * 0.10)

            self.progress.emit("Scanning EVTX files for process events...", 0.0)
            evtx_paths = find_relevant_evtx_files(self.evtx_folder, progress_cb=_scan_cb)

            if not evtx_paths:
                self.error.emit(
                    "No EVTX files containing process-creation events (EID 4688/1) "
                    f"were found in:\n{self.evtx_folder}\n\n"
                    "Sentinel requires Security.evtx (Event ID 4688) or "
                    "Sysmon.evtx (Event ID 1).\n"
                    "Application.evtx, System.evtx, and other logs are not supported."
                )
                return

            self.progress.emit(
                f"Found {len(evtx_paths)} relevant file(s) — building baseline...", 0.10
            )

            # ── Step 2: build baseline (progress 10-100%) ────────────────────
            def _cb(step: str, pct: float) -> None:
                # Remap builder progress from 0-1 into 0.10-1.0
                self.progress.emit(step, 0.10 + pct * 0.90)

            meta = build_baseline(
                evtx_paths,
                self.output_dir,
                self.sigma_dir,
                progress_cb=_cb,
            )
            self.finished.emit(meta)
        except Exception as exc:
            logger.exception("Baseline build failed")
            self.error.emit(str(exc))
            self.finished.emit(None)  # Q2: always emit finished so UI re-enables buttons


class BaselineTab(QWidget):
    # Emitted when baseline is successfully built or loaded
    baseline_ready = Signal(Path)   # artifacts directory

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._worker: _BuildWorker | None = None
        self._artifact_dir: Path | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # ── Input group ────────────────────────────────────────────────────────
        input_group = QGroupBox("Baseline Input")
        form = QFormLayout(input_group)

        self._evtx_edit = QLineEdit()
        self._evtx_edit.setReadOnly(True)
        self._evtx_edit.setPlaceholderText("Select folder containing baseline .evtx files...")
        evtx_btn = QPushButton("Browse...")
        evtx_btn.setFixedWidth(90)
        evtx_btn.clicked.connect(self._pick_evtx_folder)
        evtx_row = QHBoxLayout()
        evtx_row.addWidget(self._evtx_edit)
        evtx_row.addWidget(evtx_btn)
        form.addRow("EVTX Folder:", evtx_row)

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

        self._output_edit = QLineEdit()
        self._output_edit.setReadOnly(True)
        self._output_edit.setPlaceholderText("Select output directory for baseline artifacts...")
        output_btn = QPushButton("Browse...")
        output_btn.setFixedWidth(90)
        output_btn.clicked.connect(self._pick_output_dir)
        output_row = QHBoxLayout()
        output_row.addWidget(self._output_edit)
        output_row.addWidget(output_btn)
        form.addRow("Output Dir:", output_row)

        layout.addWidget(input_group)

        # ── Stability progress ─────────────────────────────────────────────────
        stab_group = QGroupBox("Baseline Build")
        stab_layout = QVBoxLayout(stab_group)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        stab_layout.addWidget(self._progress_bar)

        self._status_label = QLabel("Ready")
        self._status_label.setAlignment(Qt.AlignCenter)
        stab_layout.addWidget(self._status_label)

        btn_row = QHBoxLayout()
        self._build_btn = QPushButton("Build Baseline")
        self._build_btn.setFixedHeight(32)
        self._build_btn.clicked.connect(self._start_build)
        btn_row.addWidget(self._build_btn)

        self._load_btn = QPushButton("Load Existing...")
        self._load_btn.setFixedHeight(32)
        self._load_btn.clicked.connect(self._load_existing)
        btn_row.addWidget(self._load_btn)
        stab_layout.addLayout(btn_row)

        layout.addWidget(stab_group)

        # ── Log output ─────────────────────────────────────────────────────────
        log_group = QGroupBox("Build Log")
        log_layout = QVBoxLayout(log_group)
        self._log_edit = QTextEdit()
        self._log_edit.setReadOnly(True)
        self._log_edit.setMaximumHeight(160)
        self._log_edit.setStyleSheet("font-family: monospace; font-size: 11px;")
        log_layout.addWidget(self._log_edit)
        layout.addWidget(log_group)

        layout.addStretch()

    # ── File picker callbacks ──────────────────────────────────────────────────

    def _pick_evtx_folder(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Baseline EVTX Folder")
        if d:
            self._evtx_edit.setText(d)

    def _pick_sigma_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Sigma Rules Directory")
        if d:
            self._sigma_edit.setText(d)

    def _pick_output_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if d:
            self._output_edit.setText(d)

    # ── Build ──────────────────────────────────────────────────────────────────

    def _start_build(self) -> None:
        evtx_folder = self._evtx_edit.text().strip()
        output_folder = self._output_edit.text().strip()
        if not evtx_folder or not output_folder:
            QMessageBox.warning(
                self, "Missing Input",
                "Please select both an EVTX folder and an output directory."
            )
            return

        evtx_dir = Path(evtx_folder)
        output_dir = Path(output_folder)
        if not any(evtx_dir.rglob("*.evtx")):
            QMessageBox.warning(self, "No Files", "No .evtx files found in the selected folder.")
            return

        sigma_text = self._sigma_edit.text().strip()
        sigma_dir = Path(sigma_text) if sigma_text else None

        self._log(f"Scanning {evtx_folder} for relevant EVTX files...")
        self._build_btn.setEnabled(False)
        self._load_btn.setEnabled(False)
        self._progress_bar.setValue(0)

        self._worker = _BuildWorker(evtx_dir, output_dir, sigma_dir)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, step: str, pct: float) -> None:
        self._progress_bar.setValue(int(pct * 100))
        self._status_label.setText(step)
        self._log(f"[{int(pct*100):3d}%] {step}")

    def _on_finished(self, meta) -> None:
        self._build_btn.setEnabled(True)
        self._load_btn.setEnabled(True)
        if meta is None:
            return  # error already handled by _on_error
        self._progress_bar.setValue(100)
        self._status_label.setText(
            f"Done — {meta.event_count} events, stability={meta.stability_score:.2f}"
        )
        self._log(f"Baseline built successfully. Stability={meta.stability_score:.2f}")
        output_dir = Path(self._output_edit.text())
        self._artifact_dir = output_dir
        self.baseline_ready.emit(output_dir)

    def _on_error(self, msg: str) -> None:
        self._build_btn.setEnabled(True)
        self._load_btn.setEnabled(True)
        self._status_label.setText("Error")
        self._log(f"ERROR: {msg}")
        QMessageBox.critical(self, "Build Failed", msg)

    # ── Load existing ──────────────────────────────────────────────────────────

    def _load_existing(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Baseline Artifacts Directory")
        if not d:
            return
        from sentinel.baseline.persistence import artifacts_exist
        artifact_dir = Path(d)
        if not artifacts_exist(artifact_dir):
            QMessageBox.warning(
                self, "Invalid Directory",
                "Selected directory does not contain valid baseline artifacts.\n"
                "Please select a directory produced by 'Build Baseline'."
            )
            return
        self._artifact_dir = artifact_dir
        self._output_edit.setText(d)
        self._log(f"Loaded existing baseline from: {d}")
        self._status_label.setText("Baseline loaded")
        self.baseline_ready.emit(artifact_dir)

    def get_artifact_dir(self) -> Path | None:
        return self._artifact_dir

    def _log(self, msg: str) -> None:
        self._log_edit.append(msg)
