"""
Profile Editor Dialog — create or edit a custom DFIR profile.

Supports all standard profile fields plus extended filter fields:
  - Event IDs, Sources, Channels, Computers, Users, Levels, Keywords
  - Custom conditions (Name / Operator / Value) for event_data field matching
    e.g.  LogonType  equals  3
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QScrollArea, QWidget, QMessageBox, QFrame,
)

from .theme import COLORS

_OPERATORS = [
    "contains", "equals", "starts with", "ends with",
    "not contains", "not equals", "regex", "greater than", "less than",
]

_LEVEL_NAMES = [
    "Verbose", "Information", "Warning", "Error", "Critical",
    "Audit Success", "Audit Failure",
]


def _sep() -> QFrame:
    line = QFrame()
    line.setFrameShape(QFrame.Shape.HLine)
    line.setStyleSheet(f"color: {COLORS['border']};")
    return line


class ProfileEditorDialog(QDialog):
    """
    Dialog for creating or editing a user-defined profile.

    Pass ``profile=None`` to create a new profile.
    Pass an existing profile dict to edit it (read-only if it's a default profile).
    """

    def __init__(self, profile: dict | None = None, parent=None):
        super().__init__(parent)
        self._original = profile or {}
        self._is_new = profile is None
        self._is_default = not self._original.get("_user_defined", False) and not self._is_new

        title = "New Profile" if self._is_new else f"Edit Profile — {self._original.get('name', '')}"
        self.setWindowTitle(title)
        self.setMinimumSize(580, 680)
        self.resize(640, 740)

        self._build_ui()
        self._apply_styles()
        if not self._is_new:
            self._populate(self._original)

        if self._is_default:
            self._set_readonly(True)

    # =========================================================================
    # UI BUILD
    # =========================================================================

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 12)

        if self._is_default:
            info = QLabel(
                "This is a built-in profile and cannot be edited directly.\n"
                "Click 'Copy to New Profile' to create an editable copy."
            )
            info.setWordWrap(True)
            info.setStyleSheet(
                f"background:{COLORS['bg_header']}; color:{COLORS['text_dim']};"
                " padding:6px; border-radius:4px;"
            )
            root.addWidget(info)

        # ── Scroll area ───────────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        body_widget = QWidget()
        body = QVBoxLayout(body_widget)
        body.setSpacing(10)
        body.setContentsMargins(4, 4, 4, 4)

        # ── Basic info ────────────────────────────────────────────────────────
        grp_info = QGroupBox("Profile Info")
        form_info = QFormLayout(grp_info)
        form_info.setSpacing(6)

        self._inp_name = QLineEdit()
        self._inp_name.setPlaceholderText("e.g. Network Logon Monitoring")
        form_info.addRow("Name *", self._inp_name)

        self._inp_desc = QTextEdit()
        self._inp_desc.setPlaceholderText("Brief description of what this profile detects")
        self._inp_desc.setFixedHeight(56)
        form_info.addRow("Description", self._inp_desc)

        self._inp_author = QLineEdit()
        self._inp_author.setPlaceholderText("Your name / team")
        form_info.addRow("Author", self._inp_author)

        self._inp_tags = QLineEdit()
        self._inp_tags.setPlaceholderText("authentication, lateral-movement, ...")
        form_info.addRow("Tags", self._inp_tags)

        body.addWidget(grp_info)

        # ── Event filter fields ───────────────────────────────────────────────
        grp_filter = QGroupBox("Event Filters")
        form_filter = QFormLayout(grp_filter)
        form_filter.setSpacing(6)

        self._inp_event_ids = QLineEdit()
        self._inp_event_ids.setPlaceholderText("e.g. 4624,4625  or  4624-4630!4627")
        form_filter.addRow("Event IDs", self._inp_event_ids)

        self._inp_sources = QLineEdit()
        self._inp_sources.setPlaceholderText("Microsoft-Windows-Security-Auditing, ...")
        form_filter.addRow("Sources / Providers", self._inp_sources)

        self._inp_channels = QLineEdit()
        self._inp_channels.setPlaceholderText("Security, System, ...")
        form_filter.addRow("Channels", self._inp_channels)

        self._inp_computers = QLineEdit()
        self._inp_computers.setPlaceholderText("DC01, WS-ADMIN, ...")
        form_filter.addRow("Computers", self._inp_computers)

        self._inp_users = QLineEdit()
        self._inp_users.setPlaceholderText("DOMAIN\\user, S-1-5-..., ...")
        form_filter.addRow("Users", self._inp_users)

        self._inp_keywords = QLineEdit()
        self._inp_keywords.setPlaceholderText("mimikatz, pass-the-hash, ...")
        form_filter.addRow("Keywords", self._inp_keywords)

        # Levels row
        lvl_widget = QWidget()
        lvl_layout = QHBoxLayout(lvl_widget)
        lvl_layout.setContentsMargins(0, 0, 0, 0)
        lvl_layout.setSpacing(8)
        self._level_checks: dict[str, QCheckBox] = {}
        for name in _LEVEL_NAMES:
            chk = QCheckBox(name)
            chk.setChecked(False)
            self._level_checks[name] = chk
            lvl_layout.addWidget(chk)
        lvl_layout.addStretch()
        form_filter.addRow("Levels", lvl_widget)

        body.addWidget(grp_filter)

        # ── Custom conditions ─────────────────────────────────────────────────
        grp_cond = QGroupBox("Custom Conditions  (event data field matching)")
        cond_layout = QVBoxLayout(grp_cond)
        cond_layout.setSpacing(6)

        hint = QLabel(
            "Match specific parsed event data fields.  "
            "Example:  <b>LogonType</b>  equals  <b>3</b>"
        )
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLORS['text_dim']}; font-size: 11px;")
        cond_layout.addWidget(hint)

        btn_row = QHBoxLayout()
        btn_new_cond = QPushButton("Add Condition")
        btn_new_cond.clicked.connect(self._add_condition)
        btn_del_cond = QPushButton("Remove")
        btn_del_cond.clicked.connect(self._del_condition)
        btn_clear_cond = QPushButton("Clear All")
        btn_clear_cond.clicked.connect(self._clear_conditions)
        btn_row.addWidget(btn_new_cond)
        btn_row.addWidget(btn_del_cond)
        btn_row.addWidget(btn_clear_cond)
        btn_row.addStretch()
        cond_layout.addLayout(btn_row)

        self._tbl_conditions = QTableWidget(0, 3)
        self._tbl_conditions.setHorizontalHeaderLabels(["Field Name", "Operator", "Value"])
        hdr = self._tbl_conditions.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(False)
        hdr.resizeSection(0, 160)
        hdr.resizeSection(1, 130)
        hdr.resizeSection(2, 220)
        self._tbl_conditions.verticalHeader().setVisible(False)
        self._tbl_conditions.setMinimumHeight(100)
        self._tbl_conditions.setMaximumHeight(200)
        cond_layout.addWidget(self._tbl_conditions)

        self._chk_case_sensitive = QCheckBox("Case sensitive matching")
        cond_layout.addWidget(self._chk_case_sensitive)

        body.addWidget(grp_cond)
        body.addStretch()
        scroll.setWidget(body_widget)
        root.addWidget(scroll)

        # ── Buttons ───────────────────────────────────────────────────────────
        root.addWidget(_sep())
        btn_bar = QHBoxLayout()

        if self._is_default:
            btn_copy = QPushButton("Copy to New Profile")
            btn_copy.clicked.connect(self._copy_as_new)
            btn_bar.addWidget(btn_copy)
        else:
            btn_save = QPushButton("Save Profile")
            btn_save.setDefault(True)
            btn_save.setMinimumWidth(110)
            btn_save.clicked.connect(self._on_save)
            btn_bar.addWidget(btn_save)

        btn_bar.addStretch()
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setMinimumWidth(80)
        btn_cancel.clicked.connect(self.reject)
        btn_bar.addWidget(btn_cancel)
        root.addLayout(btn_bar)

    # =========================================================================
    # POPULATE / READ
    # =========================================================================

    def _populate(self, p: dict) -> None:
        """Fill UI fields from a profile dict."""
        self._inp_name.setText(p.get("name", ""))
        self._inp_desc.setPlainText(p.get("description", ""))
        self._inp_author.setText(p.get("author", ""))
        self._inp_tags.setText(", ".join(p.get("tags", [])))

        # Event IDs: prefer expression string, fall back to list
        eids = p.get("event_ids", [])
        self._inp_event_ids.setText(", ".join(str(e) for e in eids) if eids else "")

        self._inp_sources.setText(", ".join(p.get("sources", [])))
        self._inp_channels.setText(", ".join(p.get("channels", [])))
        self._inp_computers.setText(", ".join(p.get("computers", [])))
        self._inp_users.setText(", ".join(p.get("users", [])))
        self._inp_keywords.setText(", ".join(p.get("keywords", [])))

        profile_levels = set(p.get("levels", []))
        for name, chk in self._level_checks.items():
            chk.setChecked(name in profile_levels)

        self._chk_case_sensitive.setChecked(bool(p.get("case_sensitive", False)))

        for cond in p.get("conditions", []):
            self._add_condition(cond)

    def _get_profile_dict(self) -> dict:
        """Read UI fields into a profile dict."""
        def _split(text: str) -> list[str]:
            return [v.strip() for v in text.split(",") if v.strip()] if text.strip() else []

        def _split_int(text: str) -> list[int]:
            result = []
            for token in _split(text):
                try:
                    result.append(int(float(token)))
                except ValueError:
                    pass
            return result

        conditions = []
        for row in range(self._tbl_conditions.rowCount()):
            name_item = self._tbl_conditions.item(row, 0)
            value_item = self._tbl_conditions.item(row, 2)
            cmb = self._tbl_conditions.cellWidget(row, 1)
            if name_item:
                fname = name_item.text().strip()
                if fname:
                    conditions.append({
                        "name": fname,
                        "operator": cmb.currentText() if cmb else "contains",
                        "value": value_item.text().strip() if value_item else "",
                    })

        levels = [n for n, chk in self._level_checks.items() if chk.isChecked()]

        return {
            "name": self._inp_name.text().strip(),
            "description": self._inp_desc.toPlainText().strip(),
            "author": self._inp_author.text().strip(),
            "tags": _split(self._inp_tags.text()),
            "event_ids": _split_int(self._inp_event_ids.text()),
            "sources": _split(self._inp_sources.text()),
            "channels": _split(self._inp_channels.text()),
            "computers": _split(self._inp_computers.text()),
            "users": _split(self._inp_users.text()),
            "keywords": _split(self._inp_keywords.text()),
            "levels": levels,
            "conditions": conditions,
            "case_sensitive": self._chk_case_sensitive.isChecked(),
        }

    def get_profile(self) -> dict:
        """Return the profile dict built from the dialog's current state."""
        return self._result

    # =========================================================================
    # CONDITIONS TABLE HELPERS
    # =========================================================================

    def _add_condition(self, cond: dict | None = None) -> None:
        row = self._tbl_conditions.rowCount()
        self._tbl_conditions.insertRow(row)

        name_val = cond.get("name", "") if cond else ""
        op_val   = cond.get("operator", "contains") if cond else "contains"
        val_val  = cond.get("value", "") if cond else ""

        self._tbl_conditions.setItem(row, 0, QTableWidgetItem(name_val))

        cmb = QComboBox()
        cmb.addItems(_OPERATORS)
        if op_val in _OPERATORS:
            cmb.setCurrentText(op_val)
        self._tbl_conditions.setCellWidget(row, 1, cmb)

        self._tbl_conditions.setItem(row, 2, QTableWidgetItem(val_val))

    def _del_condition(self) -> None:
        row = self._tbl_conditions.currentRow()
        if row >= 0:
            self._tbl_conditions.removeRow(row)

    def _clear_conditions(self) -> None:
        self._tbl_conditions.setRowCount(0)

    # =========================================================================
    # SAVE / COPY
    # =========================================================================

    def _on_save(self) -> None:
        p = self._get_profile_dict()
        if not p["name"]:
            QMessageBox.warning(self, "Validation Error", "Profile name is required.")
            return

        try:
            from evtx_tool.profiles.manager import ProfileManager
            pm = ProfileManager()

            if self._is_new:
                pm.create(p)
            else:
                pm.update(self._original["name"], p)

            self._result = p
            self.accept()
        except Exception as exc:
            QMessageBox.critical(self, "Save Failed", str(exc))

    def _copy_as_new(self) -> None:
        """Open a fresh editor pre-filled with this default profile's data."""
        copy = dict(self._original)
        copy.pop("_source_path", None)
        copy.pop("_user_defined", None)
        copy["name"] = copy.get("name", "") + " (Custom)"
        dlg = ProfileEditorDialog(profile=None, parent=self.parent())
        dlg._populate(copy)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self._result = dlg.get_profile()
            self.accept()

    def _set_readonly(self, readonly: bool) -> None:
        self._inp_name.setReadOnly(readonly)
        self._inp_desc.setReadOnly(readonly)
        self._inp_author.setReadOnly(readonly)
        self._inp_tags.setReadOnly(readonly)
        self._inp_event_ids.setReadOnly(readonly)
        self._inp_sources.setReadOnly(readonly)
        self._inp_channels.setReadOnly(readonly)
        self._inp_computers.setReadOnly(readonly)
        self._inp_users.setReadOnly(readonly)
        self._inp_keywords.setReadOnly(readonly)
        for chk in self._level_checks.values():
            chk.setEnabled(not readonly)
        self._chk_case_sensitive.setEnabled(not readonly)
        self._tbl_conditions.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers if readonly
            else QTableWidget.EditTrigger.DoubleClicked | QTableWidget.EditTrigger.SelectedClicked
        )

    # =========================================================================
    # STYLES
    # =========================================================================

    def _apply_styles(self) -> None:
        self.setStyleSheet(f"""
            QDialog {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text']};
            }}
            QGroupBox {{
                font-weight: bold;
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 4px;
                margin-top: 8px;
                padding-top: 6px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 4px;
                color: {COLORS['accent']};
            }}
            QLabel {{ color: {COLORS['text']}; }}
            QLineEdit, QTextEdit {{
                background: {COLORS['bg_input']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 3px 5px;
            }}
            QLineEdit:read-only, QTextEdit:read-only {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text_dim']};
            }}
            QCheckBox {{ color: {COLORS['text']}; spacing: 5px; }}
            QTableWidget {{
                background: {COLORS['bg_input']};
                color: {COLORS['text']};
                gridline-color: {COLORS['border']};
                border: 1px solid {COLORS['border']};
            }}
            QHeaderView::section {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                padding: 3px;
            }}
            QPushButton {{
                background: {COLORS['btn_bg']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 4px 12px;
            }}
            QPushButton:hover {{ background: {COLORS['btn_hover']}; }}
            QPushButton:default {{
                background: {COLORS['accent']};
                color: #fff;
                border-color: {COLORS['accent']};
            }}
            QPushButton:default:hover {{ background: {COLORS['accent_hover']}; }}
            QScrollArea {{ border: none; background: transparent; }}
            QScrollBar:vertical {{
                background: {COLORS['bg_panel']};
                width: 10px;
            }}
            QScrollBar::handle:vertical {{
                background: {COLORS['border']};
                border-radius: 4px;
                min-height: 20px;
            }}
        """)
