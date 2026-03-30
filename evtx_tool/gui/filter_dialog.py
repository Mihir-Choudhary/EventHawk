"""
Advanced Filter Dialog — Event Log Explorer style.

Full-featured filter dialog with:
  - Event type checkboxes (Verbose, Information, Warning, Error, Critical, etc.)
  - Source / Category / User / Computer fields with browse pickers & exclude toggles
  - Event ID range expressions (1-19,100,250-450!10,255)
  - Text-in-description with RegExp and Exclude toggles
  - Date/time from/to + relative time ("last N days M hours")
  - Custom field conditions (name / operator / value)
  - Save / Load filter presets + Case sensitive toggle
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta
from typing import Any

from PySide6.QtCore import Qt, QDateTime, QDate, QTime
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QGroupBox,
    QCheckBox, QLabel, QLineEdit, QPushButton, QComboBox,
    QDateTimeEdit, QDateEdit, QTimeEdit, QSpinBox,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QWidget, QFrame, QFileDialog, QMessageBox, QAbstractItemView,
    QSizePolicy, QScrollArea, QCalendarWidget,
)

from .picker_dialog import PickerDialog
from .theme import COLORS


# ── Date+time popup widgets ───────────────────────────────────────────────────

class _TimeAwareCalendar(QCalendarWidget):
    """
    QCalendarWidget that appends a QTimeEdit row at the bottom of the popup.

    Used by _DateTimePickerEdit so the user can set both date AND time from
    a single popup instead of having to click inside the text field segments.
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        # Build the time row
        time_container = QWidget()
        row = QHBoxLayout(time_container)
        row.setContentsMargins(8, 4, 8, 7)
        row.setSpacing(8)

        lbl = QLabel("Time:")
        lbl.setStyleSheet(f"color:{COLORS['text']}; font-size:9pt;")
        row.addWidget(lbl)

        self._time_edit = QTimeEdit()
        self._time_edit.setDisplayFormat("HH:mm:ss")
        self._time_edit.setFixedHeight(23)
        self._time_edit.setStyleSheet(f"""
            QTimeEdit {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 2px 4px;
                font-size: 9pt;
            }}
            QTimeEdit::up-button, QTimeEdit::down-button {{
                width: 14px;
            }}
        """)
        row.addWidget(self._time_edit, stretch=1)

        # Inject the time row into the bottom of the calendar's main VBoxLayout
        main_layout = self.layout()
        if main_layout is not None:
            main_layout.addWidget(time_container)

    # ── Public helpers ────────────────────────────────────────────────────

    def get_time(self) -> QTime:
        return self._time_edit.time()

    def set_time(self, t: QTime) -> None:
        """Set the time widget without emitting signals (used for sync)."""
        self._time_edit.blockSignals(True)
        self._time_edit.setTime(t)
        self._time_edit.blockSignals(False)

    def time_edit(self) -> QTimeEdit:
        return self._time_edit


class _DateTimePickerEdit(QDateTimeEdit):
    """
    QDateTimeEdit whose calendar popup includes an embedded time editor.

    Behaviour:
    - Opening the popup syncs the embedded time widget to the current value.
    - Changing the time widget immediately updates the QDateTimeEdit (date kept).
    - Clicking a date in the calendar updates only the date (time preserved).
    - Double-clicking a date (or pressing Enter) confirms and closes the popup.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        # Enable popup FIRST so the internal container exists
        self.setCalendarPopup(True)
        # Create calendar with no parent — setCalendarWidget takes ownership
        # and reparents it to the popup container.  Passing parent=self would
        # make the full calendar grid render inside the QDateTimeEdit widget.
        self._cal = _TimeAwareCalendar()
        self.setCalendarWidget(self._cal)
        # Live-update the datetime when the embedded time widget changes
        self._cal.time_edit().timeChanged.connect(self._on_cal_time_changed)

    def showPopup(self) -> None:
        # Sync embedded time widget to the current datetime before the popup appears
        self._cal.set_time(self.time())
        super().showPopup()

    def _on_cal_time_changed(self, t: QTime) -> None:
        """Update time portion only, keeping the current date."""
        self.blockSignals(True)
        self.setDateTime(QDateTime(self.date(), t))
        self.blockSignals(False)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _styled_line(parent=None) -> QFrame:
    """Thin horizontal separator."""
    line = QFrame(parent)
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color:{COLORS['border']};")
    line.setFixedHeight(1)
    return line


def _lbl(text: str, bold: bool = False) -> QLabel:
    lbl = QLabel(text)
    if bold:
        f = lbl.font()
        f.setBold(True)
        lbl.setFont(f)
    return lbl


class FilterDialog(QDialog):
    """
    Advanced filter dialog.

    Parameters
    ----------
    metadata : dict
        Output of ``build_metadata(events)`` — field → {value → count}.
    current_filter : dict | None
        Previously applied filter config to restore state.
    parent : QWidget | None
    """

    def __init__(
        self,
        metadata: dict,
        current_filter: dict | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Filter")
        self.resize(680, 720)
        self.setMinimumSize(580, 550)
        self._metadata = metadata
        self._current = current_filter or {}
        self._build_ui()
        self._restore_state(self._current)
        self._apply_styles()

    # =====================================================================
    # UI CONSTRUCTION
    # =====================================================================

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(6)

        # Scrollable body
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body_widget = QWidget()
        body = QVBoxLayout(body_widget)
        body.setContentsMargins(0, 0, 4, 0)
        body.setSpacing(6)

        # ── Row 1: Event types + Source/Category/User/Computer ────────────
        top_row = QHBoxLayout()
        top_row.setSpacing(12)

        # Event types group
        types_grp = QGroupBox("Event types")
        types_layout = QVBoxLayout(types_grp)
        types_layout.setSpacing(2)
        types_layout.setContentsMargins(8, 12, 8, 8)

        self._chk_verbose     = QCheckBox("Verbose")
        self._chk_information = QCheckBox("Information")
        self._chk_warning     = QCheckBox("Warning")
        self._chk_error       = QCheckBox("Error")
        self._chk_critical    = QCheckBox("Critical")
        self._chk_audit_success = QCheckBox("Audit Success")
        self._chk_audit_failure = QCheckBox("Audit Failure")

        self._level_checks = {
            "Verbose":       self._chk_verbose,
            "Information":   self._chk_information,
            "Warning":       self._chk_warning,
            "Error":         self._chk_error,
            "Critical":      self._chk_critical,
            "Audit Success": self._chk_audit_success,
            "Audit Failure": self._chk_audit_failure,
        }
        for chk in self._level_checks.values():
            chk.setChecked(True)
            types_layout.addWidget(chk)

        top_row.addWidget(types_grp)

        # Source / Category / User / Computer grid
        fields_widget = QWidget()
        fields_grid = QGridLayout(fields_widget)
        fields_grid.setContentsMargins(0, 0, 0, 0)
        fields_grid.setSpacing(4)

        # Source
        fields_grid.addWidget(_lbl("Source:"), 0, 0)
        self._inp_source = QLineEdit()
        self._inp_source.setPlaceholderText("Provider name")
        fields_grid.addWidget(self._inp_source, 0, 1)
        self._btn_source = QPushButton("...")
        self._btn_source.setFixedWidth(28)
        self._btn_source.setToolTip("Browse available sources")
        self._btn_source.clicked.connect(lambda: self._open_picker("source", "Select sources", self._inp_source))
        fields_grid.addWidget(self._btn_source, 0, 2)
        self._chk_source_exclude = QCheckBox("Exclude")
        fields_grid.addWidget(self._chk_source_exclude, 0, 3)

        # Category
        fields_grid.addWidget(_lbl("Category:"), 1, 0)
        self._inp_category = QLineEdit()
        self._inp_category.setPlaceholderText("Channel name")
        fields_grid.addWidget(self._inp_category, 1, 1)
        self._btn_category = QPushButton("...")
        self._btn_category.setFixedWidth(28)
        self._btn_category.setToolTip("Browse available categories")
        self._btn_category.clicked.connect(lambda: self._open_picker("category", "Select categories", self._inp_category))
        fields_grid.addWidget(self._btn_category, 1, 2)
        self._chk_category_exclude = QCheckBox("Exclude")
        fields_grid.addWidget(self._chk_category_exclude, 1, 3)

        # User
        fields_grid.addWidget(_lbl("User:"), 2, 0)
        self._inp_user = QLineEdit()
        self._inp_user.setPlaceholderText("User / SID")
        fields_grid.addWidget(self._inp_user, 2, 1)
        self._btn_user = QPushButton("...")
        self._btn_user.setFixedWidth(28)
        self._btn_user.setToolTip("Browse available users")
        self._btn_user.clicked.connect(lambda: self._open_picker("user", "Select users", self._inp_user))
        fields_grid.addWidget(self._btn_user, 2, 2)
        self._chk_user_exclude = QCheckBox("Exclude")
        fields_grid.addWidget(self._chk_user_exclude, 2, 3)

        # Computer
        fields_grid.addWidget(_lbl("Computer:"), 3, 0)
        self._inp_computer = QLineEdit()
        self._inp_computer.setPlaceholderText("Hostname")
        fields_grid.addWidget(self._inp_computer, 3, 1)
        self._btn_computer = QPushButton("...")
        self._btn_computer.setFixedWidth(28)
        self._btn_computer.setToolTip("Browse available computers")
        self._btn_computer.clicked.connect(lambda: self._open_picker("computer", "Select computers", self._inp_computer))
        fields_grid.addWidget(self._btn_computer, 3, 2)
        self._chk_computer_exclude = QCheckBox("Exclude")
        fields_grid.addWidget(self._chk_computer_exclude, 3, 3)

        top_row.addWidget(fields_widget, stretch=1)
        body.addLayout(top_row)

        body.addWidget(_styled_line())

        # ── Event IDs ─────────────────────────────────────────────────────
        eid_row = QHBoxLayout()
        eid_row.addWidget(_lbl("Event ID(s):"))
        self._inp_event_ids = QLineEdit()
        self._inp_event_ids.setPlaceholderText("1-19,100,250-450!10,255")
        eid_row.addWidget(self._inp_event_ids, stretch=1)
        self._chk_eid_exclude = QCheckBox("Exclude")
        eid_row.addWidget(self._chk_eid_exclude)
        body.addLayout(eid_row)

        hint = QLabel("Enter ID numbers and/or ID ranges, separated by commas, "
                       "use exclamation mark to exclude criteria (e.g. 1-19,100,250-450!10,255)")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{COLORS['text_dim']}; font-size:7pt;")
        body.addWidget(hint)

        body.addWidget(_styled_line())

        # ── Text in description ───────────────────────────────────────────
        text_row = QHBoxLayout()
        text_row.addWidget(_lbl("Text in description:"))
        self._inp_text = QLineEdit()
        self._inp_text.setPlaceholderText("Search in event data values")
        text_row.addWidget(self._inp_text, stretch=1)
        self._chk_regex = QCheckBox("RegExp")
        self._chk_regex.setToolTip("Treat search text as a regular expression")
        text_row.addWidget(self._chk_regex)
        self._chk_text_exclude = QCheckBox("Exclude")
        text_row.addWidget(self._chk_text_exclude)
        body.addLayout(text_row)

        body.addWidget(_styled_line())

        # ── Date / Time ───────────────────────────────────────────────────
        dt_header = QHBoxLayout()
        self._chk_date_enable = QCheckBox("Date")
        self._chk_time_enable = QCheckBox("Time")
        self._chk_separately  = QCheckBox("Separately")
        dt_header.addWidget(self._chk_date_enable)
        dt_header.addWidget(self._chk_time_enable)
        dt_header.addWidget(self._chk_separately)
        dt_header.addStretch()
        body.addLayout(dt_header)

        dt_row = QHBoxLayout()
        dt_row.addWidget(_lbl("From:"))
        self._dt_from = _DateTimePickerEdit()
        self._dt_from.setDisplayFormat("dd-MM-yyyy HH:mm:ss")
        self._dt_from.setDateTime(QDateTime.currentDateTime().addYears(-1))
        self._dt_from.setEnabled(False)
        dt_row.addWidget(self._dt_from)
        dt_row.addWidget(_lbl("To:"))
        self._dt_to = _DateTimePickerEdit()
        self._dt_to.setDisplayFormat("dd-MM-yyyy HH:mm:ss")
        self._dt_to.setDateTime(QDateTime.currentDateTime())
        self._dt_to.setEnabled(False)
        dt_row.addWidget(self._dt_to)
        self._chk_date_exclude = QCheckBox("Exclude")
        dt_row.addWidget(self._chk_date_exclude)
        body.addLayout(dt_row)

        # Enable/disable date pickers
        self._chk_date_enable.toggled.connect(self._toggle_date)
        self._chk_time_enable.toggled.connect(self._toggle_date)

        # Relative time
        rel_row = QHBoxLayout()
        rel_row.addWidget(_lbl("Display events for the last"))
        self._spn_days = QSpinBox()
        self._spn_days.setRange(0, 9999)
        self._spn_days.setValue(0)
        rel_row.addWidget(self._spn_days)
        rel_row.addWidget(_lbl("days"))
        self._spn_hours = QSpinBox()
        self._spn_hours.setRange(0, 23)
        self._spn_hours.setValue(0)
        rel_row.addWidget(self._spn_hours)
        rel_row.addWidget(_lbl("hours"))
        self._chk_rel_exclude = QCheckBox("Exclude")
        rel_row.addWidget(self._chk_rel_exclude)
        rel_row.addStretch()
        body.addLayout(rel_row)

        body.addWidget(_styled_line())

        # ── Custom conditions ──────────────────────────────────────────────
        cond_widget = QWidget()
        cond_widget.setMaximumHeight(180)
        cond_layout = QVBoxLayout(cond_widget)
        cond_layout.setContentsMargins(4, 4, 4, 4)
        cond_layout.setSpacing(4)

        cond_btn_row = QHBoxLayout()
        btn_new_cond = QPushButton("New condition")
        btn_new_cond.clicked.connect(self._add_condition)
        btn_del_cond = QPushButton("Delete condition")
        btn_del_cond.clicked.connect(self._del_condition)
        btn_clear_cond = QPushButton("Clear list")
        btn_clear_cond.clicked.connect(self._clear_conditions)
        cond_btn_row.addWidget(btn_new_cond)
        cond_btn_row.addWidget(btn_del_cond)
        cond_btn_row.addWidget(btn_clear_cond)
        cond_btn_row.addStretch()
        cond_layout.addLayout(cond_btn_row)

        self._tbl_conditions = QTableWidget(0, 3)
        self._tbl_conditions.setHorizontalHeaderLabels(["Name", "Operator", "Value"])
        hdr = self._tbl_conditions.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(False)
        hdr.resizeSection(0, 180)   # Name
        hdr.resizeSection(1, 130)   # Operator — wide enough for "not contains"
        hdr.resizeSection(2, 240)   # Value
        self._tbl_conditions.verticalHeader().setVisible(False)
        cond_layout.addWidget(self._tbl_conditions)

        body.addWidget(cond_widget)

        scroll.setWidget(body_widget)
        root.addWidget(scroll)

        # ── Bottom buttons ────────────────────────────────────────────────
        bottom = QHBoxLayout()
        btn_clear = QPushButton("Clear")
        btn_clear.setToolTip("Reset all filter fields")
        btn_clear.clicked.connect(self._clear_all)
        bottom.addWidget(btn_clear)

        btn_load = QPushButton("Load...")
        btn_load.setToolTip("Load filter preset from file")
        btn_load.clicked.connect(self._load_preset)
        bottom.addWidget(btn_load)

        btn_save = QPushButton("Save...")
        btn_save.setToolTip("Save current filter as preset")
        btn_save.clicked.connect(self._save_preset)
        bottom.addWidget(btn_save)

        bottom.addStretch()

        self._chk_case_sensitive = QCheckBox("Case sensitive")
        bottom.addWidget(self._chk_case_sensitive)

        btn_ok = QPushButton("OK")
        btn_ok.setDefault(True)
        btn_ok.setMinimumWidth(70)
        btn_ok.clicked.connect(self.accept)
        bottom.addWidget(btn_ok)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.setMinimumWidth(70)
        btn_cancel.clicked.connect(self.reject)
        bottom.addWidget(btn_cancel)

        root.addLayout(bottom)

    # =====================================================================
    # STYLES
    # =====================================================================

    def _apply_styles(self) -> None:
        self.setStyleSheet(f"""
            QDialog {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text']};
            }}
            QGroupBox {{
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 12px;
                font-size: 9pt;
                font-weight: bold;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 4px;
            }}
            QCheckBox {{
                color: {COLORS['text']};
                spacing: 4px;
                font-size: 9pt;
            }}
            QCheckBox::indicator {{
                width: 14px;
                height: 14px;
            }}
            QLabel {{
                color: {COLORS['text']};
                font-size: 9pt;
            }}
            QLineEdit {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 3px 6px;
                font-size: 9pt;
            }}
            QLineEdit:focus {{
                border-color: {COLORS.get('accent', '#7a5c1e')};
            }}
            QPushButton {{
                background: {COLORS['bg_header']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 4px 10px;
                font-size: 9pt;
            }}
            QPushButton:hover {{
                background: {COLORS.get('accent', '#7a5c1e')};
                color: white;
            }}
            QPushButton:pressed {{
                background: {COLORS.get('accent_hover', '#9b7a2e')};
            }}
            QDateTimeEdit, QSpinBox {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 2px 4px;
                font-size: 9pt;
            }}
            QTabWidget::pane {{
                border: 1px solid {COLORS['border']};
                background: {COLORS['bg_panel']};
            }}
            QTabBar::tab {{
                background: {COLORS['bg_header']};
                color: {COLORS['text_dim']};
                border: 1px solid {COLORS['border']};
                border-bottom: none;
                padding: 4px 10px;
                font-size: 8pt;
            }}
            QTabBar::tab:selected {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text']};
            }}
            QTableWidget {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                gridline-color: {COLORS['border']};
                font-size: 9pt;
            }}
            QHeaderView::section {{
                background: {COLORS['bg_header']};
                color: {COLORS['text_dim']};
                border: 1px solid {COLORS['border']};
                padding: 3px 6px;
                font-size: 8pt;
                font-weight: bold;
            }}
            QScrollArea {{
                border: none;
            }}
            QComboBox {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 3px 6px;
                font-size: 9pt;
            }}
        """)

    # =====================================================================
    # ACTIONS
    # =====================================================================

    def _toggle_date(self) -> None:
        enabled = self._chk_date_enable.isChecked() or self._chk_time_enable.isChecked()
        self._dt_from.setEnabled(enabled)
        self._dt_to.setEnabled(enabled)

    def _open_picker(self, field: str, title: str, line_edit: QLineEdit) -> None:
        items = self._metadata.get(field, {})
        if not items:
            QMessageBox.information(self, title, "No data available for this field.\nParse events first.")
            return

        # Pre-select values currently in the line edit
        current_text = line_edit.text().strip()
        pre_selected = set()
        if current_text:
            pre_selected = {v.strip() for v in current_text.split(",")}

        dlg = PickerDialog(title, items, pre_selected, parent=self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            selected = dlg.selected_values()
            line_edit.setText(", ".join(sorted(selected)) if selected else "")

    def _add_condition(self) -> None:
        row = self._tbl_conditions.rowCount()
        self._tbl_conditions.insertRow(row)

        # Name column — plain text
        self._tbl_conditions.setItem(row, 0, QTableWidgetItem(""))

        # Operator column — combo box
        cmb = QComboBox()
        cmb.addItems(["contains", "equals", "starts with", "ends with",
                       "not contains", "not equals", "regex", "greater than",
                       "less than"])
        self._tbl_conditions.setCellWidget(row, 1, cmb)

        # Value column — plain text
        self._tbl_conditions.setItem(row, 2, QTableWidgetItem(""))

    def _del_condition(self) -> None:
        row = self._tbl_conditions.currentRow()
        if row >= 0:
            self._tbl_conditions.removeRow(row)

    def _clear_conditions(self) -> None:
        self._tbl_conditions.setRowCount(0)

    def _clear_all(self) -> None:
        """Reset every filter field to default."""
        for chk in self._level_checks.values():
            chk.setChecked(True)

        self._inp_source.clear()
        self._inp_category.clear()
        self._inp_user.clear()
        self._inp_computer.clear()
        self._chk_source_exclude.setChecked(False)
        self._chk_category_exclude.setChecked(False)
        self._chk_user_exclude.setChecked(False)
        self._chk_computer_exclude.setChecked(False)

        self._inp_event_ids.clear()
        self._chk_eid_exclude.setChecked(False)

        self._inp_text.clear()
        self._chk_regex.setChecked(False)
        self._chk_text_exclude.setChecked(False)

        self._chk_date_enable.setChecked(False)
        self._chk_time_enable.setChecked(False)
        self._chk_separately.setChecked(False)
        self._chk_date_exclude.setChecked(False)
        self._spn_days.setValue(0)
        self._spn_hours.setValue(0)
        self._chk_rel_exclude.setChecked(False)

        self._clear_conditions()
        self._chk_case_sensitive.setChecked(False)

    # ── Save / Load presets ───────────────────────────────────────────────

    def _save_preset(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Filter Preset", "", "JSON files (*.json)"
        )
        if not path:
            return
        cfg = self.get_filter_config()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2, ensure_ascii=False)
            QMessageBox.information(self, "Saved", f"Filter saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save filter:\n{e}")

    def _load_preset(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Filter Preset", "", "JSON files (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            # FINDING-21: validate schema before restoring state.
            # Without this, malformed values (e.g. "conditions": 42) raise a
            # cryptic TypeError inside _restore_state() instead of a clear message.
            if not isinstance(cfg, dict):
                raise ValueError("Preset file must be a JSON object at the top level")
            for _list_key in ("conditions", "levels", "event_ids", "sources",
                              "categories", "users", "computers"):
                if _list_key in cfg and not isinstance(cfg[_list_key], (list, type(None))):
                    raise ValueError(
                        f"Preset key '{_list_key}' must be a list, "
                        f"got {type(cfg[_list_key]).__name__}"
                    )
            self._restore_state(cfg)
            QMessageBox.information(self, "Loaded", f"Filter loaded from:\n{path}")
        except (json.JSONDecodeError, ValueError) as e:
            QMessageBox.warning(self, "Invalid Preset", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load filter:\n{e}")

    # =====================================================================
    # STATE MANAGEMENT
    # =====================================================================

    def _restore_state(self, cfg: dict) -> None:
        """Populate dialog widgets from a filter config dict."""
        if not cfg:
            return

        # Levels
        levels = cfg.get("levels")
        if levels is not None:
            level_set = set(levels)
            for name, chk in self._level_checks.items():
                chk.setChecked(name in level_set)

        # Source / Category / User / Computer
        self._inp_source.setText(", ".join(cfg.get("sources", [])))
        self._chk_source_exclude.setChecked(cfg.get("source_exclude", False))
        self._inp_category.setText(", ".join(cfg.get("categories", [])))
        self._chk_category_exclude.setChecked(cfg.get("category_exclude", False))
        self._inp_user.setText(", ".join(cfg.get("users", [])))
        self._chk_user_exclude.setChecked(cfg.get("user_exclude", False))
        self._inp_computer.setText(", ".join(cfg.get("computers", [])))
        self._chk_computer_exclude.setChecked(cfg.get("computer_exclude", False))

        # Event IDs
        self._inp_event_ids.setText(cfg.get("event_id_expr", ""))
        self._chk_eid_exclude.setChecked(cfg.get("event_id_exclude", False))

        # Text
        self._inp_text.setText(cfg.get("text_search", ""))
        self._chk_regex.setChecked(cfg.get("text_regex", False))
        self._chk_text_exclude.setChecked(cfg.get("text_exclude", False))

        # Date/time
        self._chk_date_enable.setChecked(cfg.get("date_enabled", False))
        self._chk_time_enable.setChecked(cfg.get("time_enabled", False))
        if cfg.get("date_from"):
            self._dt_from.setDateTime(QDateTime.fromString(cfg["date_from"], "yyyy-MM-dd HH:mm:ss"))
        if cfg.get("date_to"):
            self._dt_to.setDateTime(QDateTime.fromString(cfg["date_to"], "yyyy-MM-dd HH:mm:ss"))
        self._chk_date_exclude.setChecked(cfg.get("date_exclude", False))

        self._spn_days.setValue(cfg.get("relative_days", 0))
        self._spn_hours.setValue(cfg.get("relative_hours", 0))
        self._chk_rel_exclude.setChecked(cfg.get("relative_exclude", False))

        # Custom conditions — FINDING-8: disable updates while populating to
        # avoid visible flicker when restoring presets with many conditions.
        self._clear_conditions()
        self._tbl_conditions.setUpdatesEnabled(False)
        try:
            for cond in cfg.get("conditions", []):
                self._add_condition()
                row = self._tbl_conditions.rowCount() - 1
                self._tbl_conditions.item(row, 0).setText(cond.get("name", ""))
                cmb = self._tbl_conditions.cellWidget(row, 1)
                if cmb:
                    idx = cmb.findText(cond.get("operator", "contains"))
                    if idx >= 0:
                        cmb.setCurrentIndex(idx)
                self._tbl_conditions.item(row, 2).setText(cond.get("value", ""))
        finally:
            self._tbl_conditions.setUpdatesEnabled(True)

        self._chk_case_sensitive.setChecked(cfg.get("case_sensitive", False))

    def get_filter_config(self) -> dict:
        """
        Read dialog state into a filter config dict.

        The returned dict is used by ``EventFilterProxyModel.set_advanced_filter()``
        and can be serialized to JSON for save/load.
        """
        # Levels — return empty list when ALL checkboxes are checked.
        # All-checked means "no level filter" (show everything).  Returning the
        # full list would generate "level IN (1,2,3,4,5)" which excludes
        # level=0 (LogAlways) events — e.g. all Security audit events.
        levels = [name for name, chk in self._level_checks.items() if chk.isChecked()]
        if len(levels) == len(self._level_checks):
            levels = []

        # Helper to split comma-separated field into a list
        def _split(text: str) -> list[str]:
            return [v.strip() for v in text.split(",") if v.strip()] if text.strip() else []

        # Date/time
        date_from = None
        date_to = None
        if self._chk_date_enable.isChecked() or self._chk_time_enable.isChecked():
            date_from = self._dt_from.dateTime().toString("yyyy-MM-dd HH:mm:ss")
            date_to = self._dt_to.dateTime().toString("yyyy-MM-dd HH:mm:ss")

        # Custom conditions
        conditions = []
        for row in range(self._tbl_conditions.rowCount()):
            name_item = self._tbl_conditions.item(row, 0)
            value_item = self._tbl_conditions.item(row, 2)
            cmb = self._tbl_conditions.cellWidget(row, 1)
            if name_item and value_item:
                name_text = name_item.text().strip()
                value_text = value_item.text().strip()
                if name_text:
                    conditions.append({
                        "name": name_text,
                        "operator": cmb.currentText() if cmb else "contains",
                        "value": value_text,
                    })

        return {
            # Levels
            "levels": levels,
            # Source / Category / User / Computer
            "sources": _split(self._inp_source.text()),
            "source_exclude": self._chk_source_exclude.isChecked(),
            "categories": _split(self._inp_category.text()),
            "category_exclude": self._chk_category_exclude.isChecked(),
            "users": _split(self._inp_user.text()),
            "user_exclude": self._chk_user_exclude.isChecked(),
            "computers": _split(self._inp_computer.text()),
            "computer_exclude": self._chk_computer_exclude.isChecked(),
            # Event IDs
            "event_id_expr": self._inp_event_ids.text().strip(),
            "event_id_exclude": self._chk_eid_exclude.isChecked(),
            # Text
            "text_search": self._inp_text.text().strip(),
            "text_regex": self._chk_regex.isChecked(),
            "text_exclude": self._chk_text_exclude.isChecked(),
            # Date/time
            "date_enabled": self._chk_date_enable.isChecked(),
            "time_enabled": self._chk_time_enable.isChecked(),
            "date_from": date_from,
            "date_to": date_to,
            "date_exclude": self._chk_date_exclude.isChecked(),
            # Relative time
            "relative_days": self._spn_days.value(),
            "relative_hours": self._spn_hours.value(),
            "relative_exclude": self._chk_rel_exclude.isChecked(),
            # Custom conditions
            "conditions": conditions,
            # Options
            "case_sensitive": self._chk_case_sensitive.isChecked(),
        }
