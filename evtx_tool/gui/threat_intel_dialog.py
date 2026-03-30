"""
Threat Intelligence Enrichment Dialog.

Provides two modes:
  1. Offline  — import a local file (CSV / TXT / STIX 2.1 JSON) of known-bad IOCs
  2. VirusTotal API — check hashes, IPs, domains with free-tier rate limiting

The dialog is launched from the IOC panel header via the "🔍 Threat Intel" button.
On completion, it mutates the parent window's self._iocs entries in-place and
calls self._refresh_iocs_tab() to update the display.
"""

from __future__ import annotations

import threading

from PySide6.QtCore    import Qt, QTimer, Signal, QObject
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog,
    QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QProgressBar, QPushButton, QTabWidget, QVBoxLayout, QWidget,
)


# ── Worker signals (Qt requires a QObject for signals) ────────────────────────

class _WorkerSignals(QObject):
    progress  = Signal(int, int, str)    # (checked, total, current_value)
    finished  = Signal(int, int)         # (total_checked, malicious_found)
    error     = Signal(str)


# ── Background worker thread ──────────────────────────────────────────────────

class _EnrichWorker(threading.Thread):
    """
    Runs ThreatIntelChecker.enrich_iocs() in a background thread so the
    GUI remains responsive.  Progress is reported via Qt signals.
    """

    def __init__(
        self,
        checker,
        iocs: dict,
        mode: str,
        ioc_types: list[str],
        signals: _WorkerSignals,
        cancel_flag: list[bool],
    ) -> None:
        super().__init__(daemon=True, name="ThreatIntelWorker")
        self._checker     = checker
        self._iocs        = iocs
        self._mode        = mode
        self._ioc_types   = ioc_types
        self._signals     = signals
        self._cancel_flag = cancel_flag
        self._malicious   = 0

    def run(self) -> None:
        def _progress(checked: int, total: int, value: str) -> None:
            self._signals.progress.emit(checked, total, value)

        def _cancel() -> bool:
            return self._cancel_flag[0]

        try:
            self._checker.enrich_iocs(
                self._iocs,
                mode=self._mode,
                ioc_types=self._ioc_types,
                progress_fn=_progress,
                cancel_fn=_cancel,
            )
            # Count malicious results
            for ioc_type in self._ioc_types:
                for entry in (self._iocs.get(ioc_type) or []):
                    ti = entry.get("threat_intel") if isinstance(entry, dict) else None
                    if ti and ti.get("verdict") in ("malicious", "suspicious"):
                        self._malicious += 1

            total = sum(
                len(self._iocs.get(t) or []) for t in self._ioc_types
            )
            self._signals.finished.emit(total, self._malicious)
        except Exception as exc:
            self._signals.error.emit(str(exc))


# ── Main dialog ───────────────────────────────────────────────────────────────

class ThreatIntelDialog(QDialog):
    """
    Threat Intelligence Enrichment popup.

    Parent must be the MainWindow (or any object with .self._iocs and
    ._refresh_iocs_tab() attributes).
    """

    def __init__(self, parent: object = None) -> None:
        super().__init__(parent)
        self._parent_win      = parent
        self._offline_checker = None   # set by _on_browse; persists across VT runs
        self._checker         = None   # active checker (may be offline or VT instance)
        self._worker          = None
        self._cancel_flag: list[bool] = [False]
        self._signals    = _WorkerSignals()

        self.setWindowTitle("🔍 Threat Intelligence Enrichment")
        self.setMinimumWidth(480)
        self.setModal(True)

        self._build_ui()
        self._connect_signals()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(8)

        # ── Tab widget: Offline | VirusTotal ──────────────────────────────
        self._tab_widget = QTabWidget()

        # Offline tab
        offline_w = QWidget()
        offline_l = QVBoxLayout(offline_w)
        offline_l.setSpacing(6)

        file_row = QHBoxLayout()
        self._lbl_file = QLabel("No file loaded")
        self._lbl_file.setWordWrap(True)
        file_row.addWidget(self._lbl_file, 1)
        self._btn_browse = QPushButton("Browse…")
        self._btn_browse.setFixedWidth(80)
        file_row.addWidget(self._btn_browse)
        offline_l.addLayout(file_row)

        offline_l.addWidget(QLabel(
            "<small>Supported formats: CSV (type,value,verdict), "
            "TXT (one hash per line), STIX 2.1 JSON bundle</small>"
        ))

        self._lbl_offline_count = QLabel("Loaded: 0 indicators")
        offline_l.addWidget(self._lbl_offline_count)
        offline_l.addStretch()

        self._btn_apply_offline = QPushButton("Apply Offline Check")
        self._btn_apply_offline.setEnabled(False)
        offline_l.addWidget(self._btn_apply_offline, 0, Qt.AlignmentFlag.AlignRight)

        self._tab_widget.addTab(offline_w, "Offline")

        # VirusTotal tab
        vt_w = QWidget()
        vt_l = QVBoxLayout(vt_w)
        vt_l.setSpacing(6)

        vt_l.addWidget(QLabel("VirusTotal API Key:"))
        self._edit_apikey = QLineEdit()
        self._edit_apikey.setEchoMode(QLineEdit.EchoMode.Password)
        self._edit_apikey.setPlaceholderText("Enter your VT API key…")
        vt_l.addWidget(self._edit_apikey)

        vt_l.addWidget(QLabel("Check IOC types:"))
        self._chk_hashes  = QCheckBox("Hashes (MD5, SHA1, SHA256)")
        self._chk_ips     = QCheckBox("IP Addresses (IPv4, IPv6)")
        self._chk_domains = QCheckBox("Domains")
        self._chk_urls    = QCheckBox("URLs  ⚠ slow — each URL = 1 request")
        for chk in (self._chk_hashes, self._chk_ips, self._chk_domains):
            chk.setChecked(True)
            vt_l.addWidget(chk)
        self._chk_urls.setChecked(False)
        vt_l.addWidget(self._chk_urls)

        self._lbl_vt_limit = QLabel(
            "<small>Free tier: <b>4 req/min</b> · <b>500 req/day</b> · "
            "rate limiting is automatic</small>"
        )
        self._lbl_vt_limit.setTextFormat(Qt.TextFormat.RichText)
        vt_l.addWidget(self._lbl_vt_limit)

        self._lbl_estimate = QLabel("Estimated requests: 0")
        vt_l.addWidget(self._lbl_estimate)
        vt_l.addStretch()

        self._btn_start_vt = QPushButton("Start VT Check")
        vt_l.addWidget(self._btn_start_vt, 0, Qt.AlignmentFlag.AlignRight)

        self._tab_widget.addTab(vt_w, "VirusTotal API")
        root.addWidget(self._tab_widget)

        # ── Progress section (shared) ──────────────────────────────────────
        self._lbl_status = QLabel("Ready.")
        self._lbl_status.setWordWrap(True)
        root.addWidget(self._lbl_status)

        self._progress = QProgressBar()
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        self._progress.setVisible(False)
        root.addWidget(self._progress)

        self._lbl_stats = QLabel("")
        root.addWidget(self._lbl_stats)

        # ── Bottom buttons ────────────────────────────────────────────────
        self._btn_cancel_check = QPushButton("Cancel Check")
        self._btn_cancel_check.setVisible(False)
        root.addWidget(self._btn_cancel_check, 0, Qt.AlignmentFlag.AlignRight)

        self._btn_close = QPushButton("Close")
        root.addWidget(self._btn_close, 0, Qt.AlignmentFlag.AlignRight)

    # ── Signal wiring ─────────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self._btn_browse.clicked.connect(self._on_browse)
        self._btn_apply_offline.clicked.connect(self._on_apply_offline)
        self._btn_start_vt.clicked.connect(self._on_start_vt)
        self._btn_cancel_check.clicked.connect(self._on_cancel_check)
        self._btn_close.clicked.connect(self.accept)

        self._signals.progress.connect(self._on_progress)
        self._signals.finished.connect(self._on_finished)
        self._signals.error.connect(self._on_error)

        # Update VT estimate when checkboxes change
        for chk in (self._chk_hashes, self._chk_ips,
                     self._chk_domains, self._chk_urls):
            chk.stateChanged.connect(self._update_vt_estimate)

        # Update estimate when dialog opens (after iocs are available)
        QTimer.singleShot(0, self._update_vt_estimate)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _iocs(self) -> dict | None:
        pw = self._parent_win
        return getattr(pw, "_iocs", None) if pw else None

    def _ioc_count(self, ioc_types: list[str]) -> int:
        iocs = self._iocs()
        if not iocs:
            return 0
        return sum(len(iocs.get(t) or []) for t in ioc_types)

    def _selected_vt_types(self) -> list[str]:
        types: list[str] = []
        if self._chk_hashes.isChecked():
            types.extend(["md5", "sha1", "sha256"])
        if self._chk_ips.isChecked():
            types.extend(["ipv4", "ipv6"])
        if self._chk_domains.isChecked():
            types.append("domains")
        if self._chk_urls.isChecked():
            types.append("urls")
        return types

    def _update_vt_estimate(self) -> None:
        n = self._ioc_count(self._selected_vt_types())
        self._lbl_estimate.setText(
            f"Estimated requests: {n:,}  "
            f"({'≈ {:.0f} min at free tier'.format(n / 4) if n else 'none'})"
        )

    def _set_running(self, running: bool) -> None:
        """Toggle UI between idle and running state."""
        self._tab_widget.setEnabled(not running)
        self._btn_close.setEnabled(not running)
        self._btn_cancel_check.setVisible(running)
        self._progress.setVisible(running)
        if not running:
            self._progress.setValue(0)

    # ── Slot handlers ─────────────────────────────────────────────────────────

    def _on_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select IOC file",
            "",
            "IOC files (*.csv *.txt *.json);;CSV (*.csv);;TXT (*.txt);;STIX JSON (*.json)",
        )
        if not path:
            return
        try:
            from evtx_tool.analysis.threat_intel import ThreatIntelChecker
            self._offline_checker = ThreatIntelChecker()
            count = self._offline_checker.load_offline(path)
            import os
            self._lbl_file.setText(os.path.basename(path))
            self._lbl_offline_count.setText(f"Loaded: {count:,} indicators")
            self._btn_apply_offline.setEnabled(count > 0)
            self._lbl_status.setText(f"Loaded {count:,} indicators from file.")
        except Exception as exc:
            QMessageBox.critical(self, "Load Failed", str(exc))

    def _on_apply_offline(self) -> None:
        iocs = self._iocs()
        if not iocs or not self._offline_checker:
            return
        self._cancel_flag[0] = False
        self._set_running(True)
        self._lbl_status.setText("Applying offline check…")
        self._lbl_stats.setText("")

        all_types = [k for k in iocs if k not in ("summary", "correlation")]
        self._checker = self._offline_checker
        self._worker = _EnrichWorker(
            self._checker, iocs, "offline", all_types,
            self._signals, self._cancel_flag,
        )
        self._worker.start()

    def _on_start_vt(self) -> None:
        api_key = self._edit_apikey.text().strip()
        if not api_key:
            QMessageBox.warning(self, "No API Key", "Please enter a VirusTotal API key.")
            return
        iocs = self._iocs()
        if not iocs:
            QMessageBox.information(self, "No IOCs", "No IOC data available to check.")
            return

        ioc_types = self._selected_vt_types()
        if not ioc_types:
            QMessageBox.warning(self, "No Types Selected", "Select at least one IOC type to check.")
            return

        n = self._ioc_count(ioc_types)
        if n > 500:
            reply = QMessageBox.question(
                self, "Many Requests",
                f"This will send {n:,} requests to VirusTotal.\n"
                f"Free tier allows 500/day. Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self._cancel_flag[0] = False
        self._set_running(True)
        self._lbl_status.setText("Starting VirusTotal check…")
        self._lbl_stats.setText("")

        from evtx_tool.analysis.threat_intel import ThreatIntelChecker
        checker = ThreatIntelChecker(api_key=api_key)
        self._checker = checker

        self._worker = _EnrichWorker(
            checker, iocs, "virustotal", ioc_types,
            self._signals, self._cancel_flag,
        )
        self._worker.start()

    def _on_cancel_check(self) -> None:
        self._cancel_flag[0] = True
        self._lbl_status.setText("Cancelling…")

    def _on_progress(self, checked: int, total: int, value: str) -> None:
        if total > 0:
            pct = int(checked / total * 100)
            self._progress.setValue(pct)
        short_val = value[:60] + "…" if len(value) > 60 else value
        self._lbl_status.setText(f"Checking: {short_val}")
        self._lbl_stats.setText(f"Checked: {checked:,} / {total:,}")

    def _on_finished(self, total: int, malicious: int) -> None:
        self._set_running(False)
        self._lbl_status.setText(
            f"Done — {total:,} IOCs checked, {malicious:,} malicious/suspicious found."
        )
        self._lbl_stats.setText(
            f"Checked: {total:,}   Malicious/Suspicious: {malicious:,}"
        )
        # Refresh IOC panel in parent window
        pw = self._parent_win
        if pw and hasattr(pw, "_refresh_iocs_tab"):
            pw._refresh_iocs_tab()

    def _on_error(self, message: str) -> None:
        self._set_running(False)
        self._lbl_status.setText(f"Error: {message}")
        QMessageBox.critical(self, "Threat Intel Error", message)

    def closeEvent(self, event) -> None:
        # Cancel any running worker on close
        self._cancel_flag[0] = True
        super().closeEvent(event)
