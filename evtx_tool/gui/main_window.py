"""
EventHawk — Main Window (PySide6)

Layout (3-panel + status bar):
  Left  : Input panel  — files, profiles, filters, analysis toggles, parse/stop
  Center: Events table (top splitter) + event detail (bottom splitter)
  Bottom: Analysis tabs — ATT&CK | IOCs | Chains | Case
  Status: Stats bar
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from PySide6.QtCore import (
    QModelIndex, QPoint, QSortFilterProxyModel, Qt, QThread, QTimer, Signal, Slot,
    QPropertyAnimation, QEasingCurve, QSettings, QFileSystemWatcher,
)
from PySide6.QtGui import (
    QAction, QColor, QFont, QKeySequence, QIcon, QPixmap,
    QStandardItem, QStandardItemModel,
)
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QDateTimeEdit,
    QDialog, QDialogButtonBox, QFileDialog, QFrame, QGroupBox, QHBoxLayout,
    QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QMainWindow, QMessageBox, QProgressBar, QPushButton, QRadioButton,
    QScrollArea,
    QSizePolicy, QSplitter, QStatusBar, QStyle, QStyleOptionComboBox,
    QStylePainter, QTabWidget, QTableView, QTableWidget,
    QTableWidgetItem, QTextBrowser, QToolBar, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget, QSpinBox,
)
from PySide6.QtCore import QDateTime

from .models import (
    EventTableModel, EventFilterProxyModel, COLUMNS, COL_DEFAULT_COUNT,
    COL_RECORD_ID, set_tz_config, apply_tz,
)
from .worker import ParseWorker, AnalysisWorker
from evtx_tool.analysis.analysis_runner import AnalysisRunner
from .theme import COLORS
from .filter_dialog import FilterDialog


# ── helpers ───────────────────────────────────────────────────────────────────

def _sep(parent=None) -> QFrame:
    """Thin horizontal line separator."""
    f = QFrame(parent)
    f.setFrameShape(QFrame.Shape.HLine)
    f.setFrameShadow(QFrame.Shadow.Plain)
    return f


def _section_label(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setObjectName("sectionHeader")
    return lbl


def _escape_html(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# ── CheckableComboBox ─────────────────────────────────────────────────────────

class CheckableComboBox(QComboBox):
    """
    A QComboBox that shows checkable items in its popup.

    - Display text summarises selection: "All profiles", "3 of 7 selected", etc.
    - Popup stays open while the user checks / unchecks items (click-to-toggle).
    - All/None buttons in the parent layout call checkAll() / uncheckAll().
    """

    def __init__(self, placeholder: str = "— none —", parent=None):
        super().__init__(parent)
        self._placeholder = placeholder
        self._skip_hide   = False

        # Replace the default string model with a checkable item model
        self._chk_model = QStandardItemModel(self)
        self._proxy_model = QSortFilterProxyModel(self)
        self._proxy_model.setSourceModel(self._chk_model)
        self._proxy_model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setModel(self._proxy_model)

        # Inject search bar into the popup container
        self._search_bar = QLineEdit()
        self._search_bar.setPlaceholderText("Search profiles...")
        self._search_bar.setClearButtonEnabled(True)
        self._search_bar.textChanged.connect(self.setFilterText)
        
        container = self.view().parentWidget()
        if container and container.layout():
            container.layout().insertWidget(0, self._search_bar)

        # Toggle check-state when the user clicks inside the dropdown
        self.view().pressed.connect(self._on_item_pressed)

    def setFilterText(self, text: str) -> None:
        """Filter the displayed items based on search text."""
        self._proxy_model.setFilterWildcard(f"*{text}*")

    # ── population ────────────────────────────────────────────────────────────

    def addCheckItem(self, text: str, checked: bool = False,
                     tooltip: str = "") -> None:
        """Append one checkable row."""
        item = QStandardItem(text)
        item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
        item.setCheckState(
            Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        )
        if tooltip:
            item.setToolTip(tooltip)
        self._chk_model.appendRow(item)
        self.update()

    def clearItems(self) -> None:
        """Remove all rows."""
        self._chk_model.clear()
        self.update()

    # ── read checked state ────────────────────────────────────────────────────

    def checkedItems(self) -> list[str]:
        return [
            self._chk_model.item(i).text()
            for i in range(self._chk_model.rowCount())
            if self._chk_model.item(i).checkState() == Qt.CheckState.Checked
        ]

    def checkAll(self) -> None:
        """Check all currently visible (filtered) items."""
        for i in range(self._proxy_model.rowCount()):
            idx = self._proxy_model.index(i, 0)
            src_idx = self._proxy_model.mapToSource(idx)
            self._chk_model.itemFromIndex(src_idx).setCheckState(Qt.CheckState.Checked)
        self.update()

    def uncheckAll(self) -> None:
        """Uncheck all currently visible (filtered) items."""
        for i in range(self._proxy_model.rowCount()):
            idx = self._proxy_model.index(i, 0)
            src_idx = self._proxy_model.mapToSource(idx)
            self._chk_model.itemFromIndex(src_idx).setCheckState(Qt.CheckState.Unchecked)
        self.update()

    # ── popup stays open while clicking items ─────────────────────────────────

    def _on_item_pressed(self, index) -> None:
        src_index = self._proxy_model.mapToSource(index)
        item = self._chk_model.itemFromIndex(src_index)
        if item:
            new_state = (
                Qt.CheckState.Unchecked
                if item.checkState() == Qt.CheckState.Checked
                else Qt.CheckState.Checked
            )
            item.setCheckState(new_state)
        self._skip_hide = True

    def hidePopup(self) -> None:
        if self._skip_hide:
            self._skip_hide = False
            return
        if hasattr(self, '_search_bar'):
            self._search_bar.clear()
        super().hidePopup()

    # ── custom paint: show summary text in the closed combo ───────────────────

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QStylePainter(self)
        opt = QStyleOptionComboBox()
        self.initStyleOption(opt)

        checked = self.checkedItems()
        total   = self._chk_model.rowCount()
        if total == 0:
            opt.currentText = self._placeholder
        elif len(checked) == total:
            opt.currentText = f"All  ({total})"
        elif len(checked) == 0:
            opt.currentText = self._placeholder
        else:
            opt.currentText = f"{len(checked)} / {total}  selected"

        painter.drawComplexControl(QStyle.ComplexControl.CC_ComboBox, opt)
        painter.drawControl(QStyle.ControlElement.CE_ComboBoxLabel, opt)


# ── Column Filter Popup (Excel-style header dropdown) ─────────────────────────

class ColumnFilterPopup(QDialog):
    """
    Excel-style dropdown that appears when clicking a filterable column header.

    Shows checkboxes for every unique value in that column.
    Unchecked values are excluded via Quick Filter.
    """

    filterApplied = Signal(int, list)      # (column_index, list_of_excluded_values)
    sortRequested = Signal(int, Qt.SortOrder)  # (column_index, order)

    # Columns that support dropdown filtering  →  event-dict key
    FILTERABLE = {
        1: "event_id",       # Event ID
        2: "level_name",     # Level
        4: "computer",       # Computer
        5: "channel",        # Channel
        6: "user_id",        # User
        8: "source_file",    # Source File
    }

    def __init__(self, col_index: int, values: dict, parent=None):
        """
        Parameters
        ----------
        col_index : int
            Column index (matches COLUMNS list).
        values : dict
            ``{display_value: count}`` — from metadata or live data.
        """
        super().__init__(parent, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self._col = col_index
        self._all_values = values
        self.setMinimumWidth(220)
        self.setMaximumHeight(400)
        self._build_ui()
        self._apply_popup_style()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        # Search / filter input
        self._inp_search = QLineEdit()
        self._inp_search.setPlaceholderText("Search…")
        self._inp_search.textChanged.connect(self._filter_list)
        root.addWidget(self._inp_search)

        # Sort buttons
        sort_row = QHBoxLayout()
        btn_sort_asc = QPushButton("▲ Sort A→Z")
        btn_sort_asc.setFixedHeight(22)
        btn_sort_asc.clicked.connect(lambda: self._emit_sort(Qt.SortOrder.AscendingOrder))
        btn_sort_desc = QPushButton("▼ Sort Z→A")
        btn_sort_desc.setFixedHeight(22)
        btn_sort_desc.clicked.connect(lambda: self._emit_sort(Qt.SortOrder.DescendingOrder))
        sort_row.addWidget(btn_sort_asc)
        sort_row.addWidget(btn_sort_desc)
        root.addLayout(sort_row)

        # Select All / None
        btn_row = QHBoxLayout()
        btn_all = QPushButton("All")
        btn_all.setFixedHeight(22)
        btn_all.clicked.connect(self._check_all)
        btn_none = QPushButton("None")
        btn_none.setFixedHeight(22)
        btn_none.clicked.connect(self._check_none)
        btn_row.addWidget(btn_all)
        btn_row.addWidget(btn_none)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # Checkbox list (scrollable)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._list_widget = QWidget()
        self._list_layout = QVBoxLayout(self._list_widget)
        self._list_layout.setContentsMargins(0, 0, 0, 0)
        self._list_layout.setSpacing(1)

        self._checkboxes: list[QCheckBox] = []
        sorted_values = sorted(self._all_values.items(), key=lambda kv: (-kv[1], str(kv[0])))
        for val, count in sorted_values:
            display = str(val) if val else "(empty)"
            chk = QCheckBox(f"{display}  ({count})")
            chk.setChecked(True)
            chk.setProperty("filter_value", str(val))
            self._checkboxes.append(chk)
            self._list_layout.addWidget(chk)

        self._list_layout.addStretch()
        scroll.setWidget(self._list_widget)
        root.addWidget(scroll)

        # OK / Cancel
        btn_row2 = QHBoxLayout()
        btn_row2.addStretch()
        btn_ok = QPushButton("OK")
        btn_ok.setFixedWidth(60)
        btn_ok.setFixedHeight(24)
        btn_ok.clicked.connect(self._apply)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setFixedWidth(60)
        btn_cancel.setFixedHeight(24)
        btn_cancel.clicked.connect(self.reject)
        btn_row2.addWidget(btn_ok)
        btn_row2.addWidget(btn_cancel)
        root.addLayout(btn_row2)

    def _apply_popup_style(self) -> None:
        self.setStyleSheet("""
            QDialog {
                background: #ede8df;
                border: 1px solid #c4bba8;
                border-radius: 4px;
            }
            QCheckBox { color: #1e1a14; font-size: 9pt; spacing: 4px; background: transparent; }
            QCheckBox::indicator { width: 13px; height: 13px; border: 1px solid #c4bba8;
                border-radius: 2px; background: #faf7f2; }
            QCheckBox::indicator:checked { background: #7a5c1e; border-color: #9b7a2e; }
            QCheckBox::indicator:hover { border-color: #9a8878; }
            QLineEdit { background: #faf7f2; color: #1e1a14; border: 1px solid #c4bba8;
                border-radius: 2px; padding: 3px 6px; font-size: 9pt; }
            QLineEdit:focus { border-color: #b8924a; }
            QPushButton { background: #e4ddd3; color: #1e1a14; border: 1px solid #c4bba8;
                border-radius: 2px; padding: 2px 8px; font-size: 8pt; }
            QPushButton:hover { background: #d8d1c5; }
            QScrollArea { border: none; background: transparent; }
        """)

    def _filter_list(self, text: str) -> None:
        text_lower = text.lower()
        for chk in self._checkboxes:
            visible = not text_lower or text_lower in chk.text().lower()
            chk.setVisible(visible)
        if text_lower:
            # Auto-check matching items, uncheck hidden items
            for chk in self._checkboxes:
                chk.setChecked(chk.isVisible())
        else:
            # Search cleared — restore all to checked
            for chk in self._checkboxes:
                chk.setChecked(True)

    def _check_all(self) -> None:
        for chk in self._checkboxes:
            if chk.isVisible():
                chk.setChecked(True)

    def _check_none(self) -> None:
        for chk in self._checkboxes:
            if chk.isVisible():
                chk.setChecked(False)

    def _apply(self) -> None:
        excluded = []
        for chk in self._checkboxes:
            if not chk.isChecked():
                excluded.append(chk.property("filter_value"))
        self.filterApplied.emit(self._col, excluded)
        self.accept()

    def _emit_sort(self, order: Qt.SortOrder) -> None:
        """Emit sortRequested and close the popup without changing filter state."""
        self.sortRequested.emit(self._col, order)
        self.accept()


# ── Per-file tab state ────────────────────────────────────────────────────────

@dataclass
class FileTabState:
    """Holds model/proxy/table and cached data for one file's tab."""
    filepath: str
    display_name: str
    events: list
    search_cache: list
    model: object          # EventTableModel
    proxy: object          # EventFilterProxyModel
    table: object          # QTableView
    attack_summary: dict | None = None
    iocs: dict | None = None


# ── Lightweight proxy shim for Juggernaut Mode per-file tabs ─────────────────
# In JM separate mode each file tab gets its own ArrowTableModel but the
# FileTabState.proxy slot expects an EventFilterProxyModel interface.
# This shim satisfies all the proxy calls made by main_window.py.

class _JMProxyShim:
    """Duck-type shim so JM per-file tabs satisfy the proxy interface."""

    def __init__(self, model) -> None:
        self._model = model

    # Called by _close_file_tab / _clear_results
    def setSourceModel(self, _) -> None:
        self._model.close()

    # Called by _set_session_filter / _clear_session_filter
    # Session filter for JM is handled at the top-level _hw_model; per-file
    # tabs don't need it separately.
    def set_session_filter(self, _logon_id) -> None:
        pass

    # Called by bookmark / IOC pivot
    def set_record_id_filter(self, ids) -> None:
        self._model.apply_record_id_filter(frozenset(ids) if ids else frozenset())

    def clear_record_id_filter(self) -> None:
        self._model.clear_record_id_filter()

    def has_quick_filters(self) -> bool:
        return self._model.has_quick_filters()

    def get_quick_filters(self) -> list:
        return self._model.get_quick_filters()


# ── QTabWidget that can truly collapse its tab-bar gap ────────────────────────

class _EventsTabWidget(QTabWidget):
    """
    QTabWidget subclass used for the events panel.

    ``QTabWidget`` internally reads ``tabBar().sizeHint().height()`` inside
    ``initStyleOption()`` and offsets the pane by that amount — even when the
    tab bar is hidden.  Neither ``setVisible(False)`` nor a CSS
    ``max-height: 0`` on the tab bar changes ``sizeHint()``, so a ~30 px
    gap always remains above the pane content.

    This subclass overrides ``initStyleOption`` to report a zero-height
    tab bar when collapsed, eliminating the gap entirely.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._bar_collapsed: bool = False

    # ── public API ────────────────────────────────────────────────────
    def setBarCollapsed(self, collapsed: bool) -> None:
        """Hide/show the tab bar *and* eliminate the reserved gap."""
        self._bar_collapsed = collapsed
        self.tabBar().setVisible(not collapsed)
        self.updateGeometry()
        self.update()

    def isBarCollapsed(self) -> bool:
        return self._bar_collapsed

    # ── override ──────────────────────────────────────────────────────
    def initStyleOption(self, option) -> None:  # noqa: N802
        super().initStyleOption(option)
        if self._bar_collapsed:
            from PySide6.QtCore import QSize as _QSize
            option.tabBarSize = _QSize(0, 0)


# ── Time-zone dialog helpers ──────────────────────────────────────────────────

# (display_label, IANA_name) pairs — sorted West → East, used by the dialog combo.
_COMMON_TIMEZONES: list[tuple[str, str]] = [
    ("(UTC-12:00) International Date Line West",       "Etc/GMT+12"),
    ("(UTC-11:00) Coordinated Universal Time-11",      "Pacific/Midway"),
    ("(UTC-10:00) Hawaii",                             "Pacific/Honolulu"),
    ("(UTC-09:30) Marquesas Islands",                  "Pacific/Marquesas"),
    ("(UTC-09:00) Alaska",                             "America/Anchorage"),
    ("(UTC-08:00) Pacific Time (US & Canada)",         "America/Los_Angeles"),
    ("(UTC-07:00) Mountain Time (US & Canada)",        "America/Denver"),
    ("(UTC-06:00) Central Time (US & Canada)",         "America/Chicago"),
    ("(UTC-05:00) Eastern Time (US & Canada)",         "America/New_York"),
    ("(UTC-04:00) Atlantic Time (Canada)",             "America/Halifax"),
    ("(UTC-03:30) Newfoundland",                       "America/St_Johns"),
    ("(UTC-03:00) Buenos Aires",                       "America/Argentina/Buenos_Aires"),
    ("(UTC-02:00) Coordinated Universal Time-02",      "Etc/GMT+2"),
    ("(UTC-01:00) Azores",                             "Atlantic/Azores"),
    ("(UTC+00:00) London, Dublin, Lisbon",             "Europe/London"),
    ("(UTC+01:00) Amsterdam, Berlin, Paris, Rome",     "Europe/Paris"),
    ("(UTC+02:00) Cairo, Helsinki, Athens",            "Europe/Athens"),
    ("(UTC+03:00) Moscow, Kuwait, Riyadh",             "Europe/Moscow"),
    ("(UTC+03:30) Tehran",                             "Asia/Tehran"),
    ("(UTC+04:00) Abu Dhabi, Muscat, Dubai",           "Asia/Dubai"),
    ("(UTC+04:30) Kabul",                              "Asia/Kabul"),
    ("(UTC+05:00) Islamabad, Karachi, Tashkent",       "Asia/Karachi"),
    ("(UTC+05:30) Chennai, Kolkata, Mumbai, New Delhi","Asia/Kolkata"),
    ("(UTC+05:45) Kathmandu",                          "Asia/Kathmandu"),
    ("(UTC+06:00) Dhaka, Almaty",                      "Asia/Dhaka"),
    ("(UTC+06:30) Yangon (Rangoon)",                   "Asia/Rangoon"),
    ("(UTC+07:00) Bangkok, Hanoi, Jakarta",            "Asia/Bangkok"),
    ("(UTC+08:00) Beijing, Singapore, Hong Kong",      "Asia/Singapore"),
    ("(UTC+08:45) Eucla",                              "Australia/Eucla"),
    ("(UTC+09:00) Tokyo, Seoul, Osaka",                "Asia/Tokyo"),
    ("(UTC+09:30) Adelaide, Darwin",                   "Australia/Darwin"),
    ("(UTC+10:00) Sydney, Melbourne, Brisbane",        "Australia/Sydney"),
    ("(UTC+10:30) Lord Howe Island",                   "Australia/Lord_Howe"),
    ("(UTC+11:00) Solomon Islands, New Caledonia",     "Pacific/Guadalcanal"),
    ("(UTC+12:00) Auckland, Fiji",                     "Pacific/Auckland"),
    ("(UTC+12:45) Chatham Islands",                    "Pacific/Chatham"),
    ("(UTC+13:00) Samoa",                              "Pacific/Apia"),
    ("(UTC+14:00) Kiribati",                           "Pacific/Kiritimati"),
]


class EventTimeZoneDialog(QDialog):
    """
    Modal dialog for selecting how event timestamps are displayed.

    Appears with a light-grey background regardless of the application theme.
    Supports four modes: Local, UTC, Specific (IANA zone with DST), Custom offset.
    The custom offset sign is toggled via a clickable +/- button as per the UI spec.

    Cascade-isolation strategy
    --------------------------
    The dark app theme sets (a) a QApplication-level DARK_QSS stylesheet and
    (b) a dark QPalette via app.setPalette().  Both bleed into child dialogs.

    We counter this with three layers:
      1. setPalette() – resets native rendering (radio indicator, spinbox chrome)
         to light colours so Qt's style engine draws them correctly.
      2. setStyleSheet() with a comprehensive QWidget root rule – overrides the
         dark `QWidget { background:#0d1117 }` for every descendant in one shot.
      3. Explicit sub-control rules for QRadioButton::indicator, QSpinBox arrows,
         and QComboBox drop-down so the drawn chrome is visible on the light bg.
      4. combo.view().setStyleSheet() – the popup is a floating top-level window
         that inherits directly from the APPLICATION stylesheet, not the dialog's,
         so we must style its view widget independently.
    """

    # ── Light palette (class-level helper) ────────────────────────────────────
    @staticmethod
    def _make_light_palette():
        from PySide6.QtGui import QPalette, QColor
        p = QPalette()
        p.setColor(QPalette.ColorRole.Window,          QColor("#f5f0e8"))
        p.setColor(QPalette.ColorRole.WindowText,      QColor("#1e1a14"))
        p.setColor(QPalette.ColorRole.Base,            QColor("#faf7f2"))
        p.setColor(QPalette.ColorRole.AlternateBase,   QColor("#ede8df"))
        p.setColor(QPalette.ColorRole.Text,            QColor("#1e1a14"))
        p.setColor(QPalette.ColorRole.Button,          QColor("#e4ddd3"))
        p.setColor(QPalette.ColorRole.ButtonText,      QColor("#1e1a14"))
        p.setColor(QPalette.ColorRole.Highlight,       QColor("#7a5c1e"))
        p.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        p.setColor(QPalette.ColorRole.ToolTipBase,     QColor("#e4ddd3"))
        p.setColor(QPalette.ColorRole.ToolTipText,     QColor("#1e1a14"))
        p.setColor(QPalette.ColorRole.PlaceholderText, QColor("#9a8878"))
        # Disabled group – warm-muted on cream background
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor("#9a8878"))
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text,       QColor("#9a8878"))
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor("#9a8878"))
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Base,       QColor("#ede8df"))
        p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Button,     QColor("#ede8df"))
        return p

    # ── Comprehensive cream stylesheet ─────────────────────────────────────────
    _LIGHT_QSS = """
        /* -- Base: every descendant starts from cream -- */
        QWidget {
            background: #f5f0e8;
            color: #1e1a14;
            font-family: "Segoe UI", Arial, sans-serif;
            font-size: 9pt;
        }

        /* -- Dialog frame -- */
        QDialog { background: #f5f0e8; }

        /* -- Labels -- */
        QLabel {
            background: transparent;
            color: #1e1a14;
        }

        /* -- Radio buttons + their indicator in all states -- */
        QRadioButton {
            background: transparent;
            color: #1e1a14;
            spacing: 8px;
        }
        QRadioButton:checked {
            color: #9b7a2e;
            font-weight: bold;
        }
        QRadioButton:disabled { color: #9a8878; }

        QRadioButton::indicator {
            width: 14px;
            height: 14px;
            border-radius: 7px;
            border: 2px solid #9a8878;
            background: #faf7f2;
        }
        QRadioButton::indicator:hover {
            border-color: #7a5c1e;
            background: #e8e0d0;
        }
        QRadioButton::indicator:checked {
            border: 1px solid #9b7a2e;
            background: #9b7a2e;
        }
        QRadioButton::indicator:checked:hover {
            border-color: #7a5c1e;
            background: #7a5c1e;
        }
        QRadioButton::indicator:disabled {
            border-color: #c4bba8;
            background: #ede8df;
        }

        /* -- ComboBox body -- */
        QComboBox {
            background: #faf7f2;
            color: #1e1a14;
            border: 1px solid #c4bba8;
            border-radius: 3px;
            padding: 3px 6px;
            min-height: 24px;
        }
        QComboBox:hover  { border-color: #7a5c1e; }
        QComboBox:focus  { border-color: #7a5c1e; }
        QComboBox:on     { border-color: #7a5c1e; }
        QComboBox:disabled {
            background: #ede8df;
            color: #9a8878;
            border-color: #c4bba8;
        }
        QComboBox::drop-down {
            subcontrol-origin: padding;
            subcontrol-position: top right;
            width: 22px;
            border-left: 1px solid #c4bba8;
            background: #ede8df;
            border-radius: 0 3px 3px 0;
        }
        QComboBox::drop-down:hover { background: #ccc5b5; }
        QComboBox::down-arrow {
            image: none;
            width: 0; height: 0;
            border-left:  5px solid transparent;
            border-right: 5px solid transparent;
            border-top:   6px solid #5a4e42;
        }

        /* -- SpinBox body + chrome -- */
        QSpinBox {
            background: #faf7f2;
            color: #1e1a14;
            border: 1px solid #c4bba8;
            border-radius: 3px;
            padding: 2px 4px;
            min-height: 24px;
        }
        QSpinBox:hover { border-color: #7a5c1e; }
        QSpinBox:focus { border-color: #7a5c1e; }
        QSpinBox:disabled {
            background: #ede8df;
            color: #9a8878;
            border-color: #c4bba8;
        }
        QSpinBox::up-button, QSpinBox::down-button {
            background: #e4ddd3;
            border: none;
            width: 16px;
        }
        QSpinBox::up-button:hover, QSpinBox::down-button:hover {
            background: #ccc5b5;
        }
        QSpinBox::up-button:disabled, QSpinBox::down-button:disabled {
            background: #ede8df;
        }
        QSpinBox::up-arrow {
            image: none;
            width: 0; height: 0;
            border-left:  4px solid transparent;
            border-right: 4px solid transparent;
            border-bottom: 5px solid #5a4e42;
        }
        QSpinBox::down-arrow {
            image: none;
            width: 0; height: 0;
            border-left:  4px solid transparent;
            border-right: 4px solid transparent;
            border-top:   5px solid #5a4e42;
        }
        QSpinBox::up-arrow:disabled, QSpinBox::down-arrow:disabled {
            border-top-color:    #9a8878;
            border-bottom-color: #9a8878;
        }

        /* -- Sign toggle button -- */
        QPushButton#signToggle {
            font-weight: bold;
            font-size: 14pt;
            color: #7a5c1e;
            background: #e8e0cc;
            border: 1px solid #7a5c1e;
            border-radius: 4px;
            min-width: 32px;
            max-width: 32px;
            min-height: 28px;
            max-height: 28px;
            padding: 0px;
        }
        QPushButton#signToggle:hover   { background: #d4c8a8; }
        QPushButton#signToggle:pressed { background: #c4b898; }
        QPushButton#signToggle:disabled {
            color: #9a8878;
            border-color: #c4bba8;
            background: #ede8df;
        }

        /* -- OK button -- */
        QPushButton#okBtn {
            background: #7a5c1e;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            padding: 5px 20px;
            font-weight: bold;
            font-size: 9pt;
            min-height: 0;
        }
        QPushButton#okBtn:hover   { background: #6b4e18; }
        QPushButton#okBtn:pressed { background: #5a3e10; }

        /* -- Cancel button -- */
        QPushButton#cancelBtn {
            background: #e4ddd3;
            color: #1e1a14;
            border: 1px solid #c4bba8;
            border-radius: 4px;
            padding: 5px 20px;
            font-size: 9pt;
            min-height: 0;
        }
        QPushButton#cancelBtn:hover   { background: #ccc5b5; }
        QPushButton#cancelBtn:pressed { background: #b8b0a0; }

        /* -- Scrollbar inside combo popup -- */
        QScrollBar:vertical {
            background: #f5f0e8;
            width: 10px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background: #b8b0a0;
            border-radius: 5px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover { background: #9a8878; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    """

    # ── Popup view stylesheet (applied directly to QComboBox.view()) ──────────
    # The dropdown popup is a top-level window → inherits from the APPLICATION
    # stylesheet, not from the dialog's.  We must style it independently.
    _POPUP_QSS = """
        QAbstractItemView {
            background: #faf7f2;
            color: #1e1a14;
            selection-background-color: #7a5c1e;
            selection-color: #ffffff;
            border: 1px solid #c4bba8;
            outline: none;
            font-size: 9pt;
        }
        QAbstractItemView::item {
            padding: 4px 8px;
            min-height: 22px;
        }
        QAbstractItemView::item:hover {
            background: #e8e0d0;
            color: #1e1a14;
        }
        QAbstractItemView::item:selected {
            background: #7a5c1e;
            color: #ffffff;
        }
        QScrollBar:vertical {
            background: #f5f0e8;
            width: 10px;
            margin: 0;
        }
        QScrollBar::handle:vertical {
            background: #b8b0a0;
            border-radius: 5px;
            min-height: 20px;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    """

    def __init__(
        self,
        current_mode: str = "local",
        current_specific: str = "Asia/Kolkata",
        current_custom_offset_min: int = 330,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Event time zone")
        self.setModal(True)
        self.setFixedWidth(500)

        # ── Reset palette so Qt's native rendering uses light colours ─────────
        self.setPalette(self._make_light_palette())
        # Propagate light palette to all child widgets (Qt default is True,
        # but being explicit avoids surprises on some platforms).

        # ── Apply comprehensive light stylesheet ──────────────────────────────
        self.setStyleSheet(self._LIGHT_QSS)

        # ── Custom-offset internal state ──────────────────────────────────────
        self._custom_sign: int = 1 if current_custom_offset_min >= 0 else -1
        _abs = abs(current_custom_offset_min)
        self._custom_hours:   int = _abs // 60
        self._custom_minutes: int = _abs % 60

        # ── Layout ────────────────────────────────────────────────────────────
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(22, 18, 22, 16)
        main_layout.setSpacing(10)

        # Title label
        lbl_title = QLabel("Display event time in")
        _f = lbl_title.font()
        _f.setPointSize(10)
        _f.setBold(True)
        lbl_title.setFont(_f)
        main_layout.addWidget(lbl_title)

        # ── Radio: Local ──────────────────────────────────────────────────────
        self._radio_local = QRadioButton("Local time zone")
        main_layout.addWidget(self._radio_local)

        # ── Radio: UTC ────────────────────────────────────────────────────────
        self._radio_utc = QRadioButton("UTC time zone")
        main_layout.addWidget(self._radio_utc)

        # ── Radio: Specific ───────────────────────────────────────────────────
        self._radio_specific = QRadioButton(
            "Specific time zone (respects daylight saving time)"
        )
        main_layout.addWidget(self._radio_specific)

        # Timezone combo (indented, below specific radio)
        _combo_wrap = QWidget()
        _combo_layout = QHBoxLayout(_combo_wrap)
        _combo_layout.setContentsMargins(28, 0, 0, 4)
        _combo_layout.setSpacing(0)

        self._combo_specific = QComboBox()
        self._combo_specific.setMinimumWidth(400)
        for _disp, _ in _COMMON_TIMEZONES:
            self._combo_specific.addItem(_disp)

        # Pre-select the saved IANA zone (fallback → India +05:30, index 23)
        _sel_idx = 23
        for _i, (_, _iana) in enumerate(_COMMON_TIMEZONES):
            if _iana == current_specific:
                _sel_idx = _i
                break
        self._combo_specific.setCurrentIndex(_sel_idx)

        # Style the floating popup view independently (app stylesheet would
        # otherwise override it with dark colours)
        self._combo_specific.view().setStyleSheet(self._POPUP_QSS)

        _combo_layout.addWidget(self._combo_specific)
        _combo_layout.addStretch()
        main_layout.addWidget(_combo_wrap)

        # ── Radio: Custom ─────────────────────────────────────────────────────
        self._radio_custom = QRadioButton("Custom time zone")
        main_layout.addWidget(self._radio_custom)

        # Custom offset row (indented): UTC [+/-] [HH] : [MM]
        _cust_wrap = QWidget()
        _cust_layout = QHBoxLayout(_cust_wrap)
        _cust_layout.setContentsMargins(28, 0, 0, 2)
        _cust_layout.setSpacing(6)

        _lbl_utc = QLabel("UTC")
        _lbl_utc.setStyleSheet(
            "font-weight: bold; background: transparent; color: #1e1a14;"
        )
        _cust_layout.addWidget(_lbl_utc)

        self._btn_sign = QPushButton("+" if self._custom_sign >= 0 else "-")
        self._btn_sign.setObjectName("signToggle")
        self._btn_sign.setToolTip("Click to flip the offset sign (+ / −)")
        self._btn_sign.clicked.connect(self._toggle_sign)
        _cust_layout.addWidget(self._btn_sign)

        self._spin_h = QSpinBox()
        self._spin_h.setRange(0, 14)
        self._spin_h.setValue(self._custom_hours)
        self._spin_h.setFixedWidth(54)
        _cust_layout.addWidget(self._spin_h)

        _lbl_colon = QLabel(":")
        _lbl_colon.setStyleSheet("background: transparent; color: #1e1a14;")
        _cust_layout.addWidget(_lbl_colon)

        self._spin_m = QSpinBox()
        self._spin_m.setRange(0, 59)
        self._spin_m.setSingleStep(15)
        self._spin_m.setValue(self._custom_minutes)
        self._spin_m.setFixedWidth(54)
        _cust_layout.addWidget(self._spin_m)

        _cust_layout.addStretch()
        main_layout.addWidget(_cust_wrap)

        # Instruction text (verbatim from spec)
        _lbl_hint = QLabel("Click on + / - to reverse.")
        _lbl_hint.setStyleSheet(
            "color: #666666; font-size: 8pt; background: transparent; padding-left: 28px;"
        )
        main_layout.addWidget(_lbl_hint)

        main_layout.addSpacing(8)

        # ── OK / Cancel ───────────────────────────────────────────────────────
        _btn_row = QHBoxLayout()
        _btn_row.setSpacing(8)
        _btn_row.addStretch()

        _btn_ok = QPushButton("OK")
        _btn_ok.setObjectName("okBtn")
        _btn_ok.setDefault(True)
        _btn_ok.clicked.connect(self.accept)

        _btn_cancel = QPushButton("Cancel")
        _btn_cancel.setObjectName("cancelBtn")
        _btn_cancel.clicked.connect(self.reject)

        _btn_row.addWidget(_btn_ok)
        _btn_row.addWidget(_btn_cancel)
        main_layout.addLayout(_btn_row)

        # ── Wire radio state → enable/disable sub-controls ────────────────────
        for _rb in (
            self._radio_local, self._radio_utc,
            self._radio_specific, self._radio_custom,
        ):
            _rb.toggled.connect(self._update_controls)

        # Set initial selection
        _mode_map = {
            "local":    self._radio_local,
            "utc":      self._radio_utc,
            "specific": self._radio_specific,
            "custom":   self._radio_custom,
        }
        _mode_map.get(current_mode, self._radio_local).setChecked(True)
        self._update_controls()

    # ── Internal slots ────────────────────────────────────────────────────────

    def _toggle_sign(self) -> None:
        """Flip the custom offset sign between + and − and update button label."""
        self._custom_sign = -self._custom_sign
        self._btn_sign.setText("+" if self._custom_sign >= 0 else "-")

    def _update_controls(self) -> None:
        """Enable/disable sub-controls based on active radio button."""
        is_specific = self._radio_specific.isChecked()
        is_custom   = self._radio_custom.isChecked()
        self._combo_specific.setEnabled(is_specific)
        self._btn_sign.setEnabled(is_custom)
        self._spin_h.setEnabled(is_custom)
        self._spin_m.setEnabled(is_custom)

    # ── Result accessors ──────────────────────────────────────────────────────

    def selected_mode(self) -> str:
        if self._radio_utc.isChecked():      return "utc"
        if self._radio_specific.isChecked(): return "specific"
        if self._radio_custom.isChecked():   return "custom"
        return "local"

    def selected_specific_iana(self) -> str:
        idx = self._combo_specific.currentIndex()
        if 0 <= idx < len(_COMMON_TIMEZONES):
            return _COMMON_TIMEZONES[idx][1]
        return "Asia/Kolkata"

    def selected_custom_offset_min(self) -> int:
        """Signed total minutes — e.g. +330 for +05:30, -300 for -05:00."""
        total = self._spin_h.value() * 60 + self._spin_m.value()
        return total * self._custom_sign


# ── Logon Session Browser dialog ──────────────────────────────────────────────

class _LogonSessionDialog(QDialog):
    """
    Non-modal dialog that lists every logon session found in the loaded events.

    Columns: User | Computer | Logon Type | Session ID | Start | End | Duration
             | Processes | Priv Events | ⚠ Dangerous Privs

    Double-clicking a row (or pressing "Filter to Selected Session") applies a
    Layer-5 session filter to the main event table so only events belonging to
    that LogonId are visible.  The filter survives dialog closure and is
    indicated by the orange badge below the event table.
    """

    _SKIP_IDS = frozenset({"0x0", "0", "", "0x00000000"})

    _TYPE_NAMES: dict[str, str] = {
        "2":  "Interactive (2)",
        "3":  "Network (3)",
        "4":  "Batch (4)",
        "5":  "Service (5)",
        "7":  "Unlock (7)",
        "8":  "NetworkCleartext (8)",
        "9":  "NewCredentials (9)",
        "10": "RemoteInteractive / RDP (10)",
        "11": "CachedInteractive (11)",
    }

    # Human-readable explanation of how the session was initiated
    _TYPE_INITIATION: dict[str, str] = {
        "2":  "Local console logon (physical/VM keyboard)",
        "3":  "Network authentication (SMB, named pipe, etc.)",
        "4":  "Scheduled task / batch job",
        "5":  "Windows service started under this account",
        "7":  "Workstation unlock (screen saver dismissed)",
        "8":  "Network logon with plaintext credentials (IIS Basic Auth, etc.)",
        "9":  "RunAs /netonly — local identity kept, network uses new creds",
        "10": "Remote Desktop (RDP) / Remote Assistance session",
        "11": "Cached domain credentials used (DC unreachable)",
    }

    _DANGEROUS_PRIVS = frozenset({
        "SeTcbPrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege",
        "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
    })

    _HEADERS = [
        "User", "Computer", "Logon Type", "Initiation", "Session ID",
        "Start", "End", "Duration", "Procs", "Priv Events", "⚠ Dangerous",
    ]

    def __init__(self, events: list[dict], on_filter_fn, parent=None):
        super().__init__(parent)
        self._on_filter_fn   = on_filter_fn
        self._all_sessions   = self._build_sessions(events)
        self._shown_sessions = list(self._all_sessions)
        self._build_ui()
        self._populate_table(self._all_sessions)

    # ── Session building ───────────────────────────────────────────────────

    def _build_sessions(self, events: list[dict]) -> list[dict]:
        """Scan events and build one session record per unique LogonId."""
        raw: dict[str, dict] = {}
        for ev in events:
            eid = ev.get("event_id", 0)
            ed  = ev.get("event_data", {}) or {}
            if eid == 4624:
                lid = str(ed.get("TargetLogonId",  "")).strip()
                if lid not in self._SKIP_IDS:
                    raw.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )["logon"] = ev
            elif eid == 4672:
                lid = str(ed.get("SubjectLogonId", "")).strip()
                if lid not in self._SKIP_IDS:
                    raw.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )["privs"].append(ev)
            elif eid == 4688:
                lid = str(ed.get("SubjectLogonId", "")).strip()
                if lid not in self._SKIP_IDS:
                    raw.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )["procs"].append(ev)
            elif eid == 4634:
                lid = str(ed.get("TargetLogonId",  "")).strip()
                if lid not in self._SKIP_IDS:
                    raw.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )["logoff"] = ev

        result: list[dict] = []
        for lid, sess in raw.items():
            logon_ev  = sess.get("logon")
            logoff_ev = sess.get("logoff")

            if logon_ev:
                ed         = logon_ev.get("event_data", {}) or {}
                user       = ed.get("TargetUserName") or ed.get("SubjectUserName") or ""
                computer   = logon_ev.get("computer", "")
                logon_type = str(ed.get("LogonType", "")).strip()
                start_ts   = logon_ev.get("timestamp", "")
            else:
                user = computer = logon_type = start_ts = ""

            end_ts   = logoff_ev.get("timestamp", "") if logoff_ev else ""
            duration = (
                self._calc_duration(start_ts, end_ts) if (start_ts and end_ts)
                else ("Active" if start_ts else "")
            )

            has_dangerous = any(
                any(dp in str((p.get("event_data") or {}).get("PrivilegeList", ""))
                    for dp in self._DANGEROUS_PRIVS)
                for p in sess.get("privs", [])
            )

            result.append({
                "lid":              lid,
                "user":             user,
                "computer":         computer,
                "logon_type":       logon_type,
                "logon_type_label": self._TYPE_NAMES.get(logon_type, f"Type {logon_type}") if logon_type else "",
                "initiation":       self._TYPE_INITIATION.get(logon_type, "") if logon_type else "",
                "start_ts":         start_ts,
                "end_ts":           end_ts,
                "duration":         duration,
                "proc_count":       len(sess.get("procs", [])),
                "priv_count":       len(sess.get("privs", [])),
                "has_dangerous":    has_dangerous,
                "logon_ev":         logon_ev,
            })

        result.sort(key=lambda s: s["start_ts"])
        return result

    @staticmethod
    def _calc_duration(start: str, end: str) -> str:
        try:
            fmt     = "%Y-%m-%dT%H:%M:%S"
            s_clean = start.rstrip("Z").split(".")[0][:19]
            e_clean = end.rstrip("Z").split(".")[0][:19]
            td      = datetime.strptime(e_clean, fmt) - datetime.strptime(s_clean, fmt)
            total   = int(abs(td.total_seconds()))
            h, rem  = divmod(total, 3600)
            m, sec  = divmod(rem, 60)
            if h > 0:
                return f"{h}h {m:02d}m {sec:02d}s"
            elif m > 0:
                return f"{m}m {sec:02d}s"
            else:
                return f"{sec}s"
        except Exception:
            return "?"

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("Logon Session Browser")
        self.setMinimumSize(1100, 520)
        self.resize(1340, 620)
        # Allow minimize / maximize so it can stay open alongside the main window
        self.setWindowFlags(
            Qt.WindowType.Window |
            Qt.WindowType.WindowMinMaxButtonsHint |
            Qt.WindowType.WindowCloseButtonHint
        )

        self.setPalette(EventTimeZoneDialog._make_light_palette())
        self.setStyleSheet(
            EventTimeZoneDialog._LIGHT_QSS + """
            QTableWidget {
                background: #faf7f2;
                color: #1e1a14;
                border: 1px solid #c4bba8;
                gridline-color: #e0d8cc;
                font-size: 8.5pt;
                alternate-background-color: #f3ede3;
            }
            QTableWidget::item:selected {
                background: #7a5c1e;
                color: white;
            }
            QHeaderView::section {
                background: #ede8df;
                color: #3a2a10;
                border: 1px solid #c4bba8;
                padding: 3px 6px;
                font-size: 8pt;
                font-weight: bold;
            }
            QLineEdit {
                background: #faf7f2;
                border: 1px solid #c4bba8;
                border-radius: 3px;
                padding: 3px 6px;
                font-size: 9pt;
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 10)
        root.setSpacing(8)

        # ── Summary ───────────────────────────────────────────────────────
        total     = len(self._all_sessions)
        with_4624 = sum(1 for s in self._all_sessions if s["logon_ev"])
        active    = sum(1 for s in self._all_sessions if s["start_ts"] and not s["end_ts"])
        dangerous = sum(1 for s in self._all_sessions if s["has_dangerous"])

        danger_txt = (
            f"<span style='color:#a01800;font-weight:bold;'>⚠ {dangerous} with dangerous privileges</span>"
            if dangerous else
            "<span style='color:#2e6820;'>✓ No dangerous privileges detected</span>"
        )
        summary_html = (
            f"<b>{total}</b> session(s) &nbsp;│&nbsp; "
            f"<b>{with_4624}</b> with logon event &nbsp;│&nbsp; "
            f"<b>{active}</b> active (no logoff recorded) &nbsp;│&nbsp; "
            f"{danger_txt}"
        )
        lbl_summary = QLabel(summary_html)
        lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        lbl_summary.setStyleSheet("padding: 4px 0; font-size: 9pt; background:transparent;")
        root.addWidget(lbl_summary)

        # ── Search bar ────────────────────────────────────────────────────
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText(
            "Filter by user, computer, session ID, or logon type…"
        )
        self._search_edit.textChanged.connect(self._on_search)
        search_row.addWidget(self._search_edit, stretch=1)
        root.addLayout(search_row)

        # ── Table ─────────────────────────────────────────────────────────
        self._tbl = QTableWidget(0, len(self._HEADERS))
        self._tbl.setHorizontalHeaderLabels(self._HEADERS)
        self._tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._tbl.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl.setSortingEnabled(True)
        self._tbl.setAlternatingRowColors(True)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.verticalHeader().setDefaultSectionSize(22)

        hdr = self._tbl.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(False)
        # Col order: User, Computer, Logon Type, Initiation, Session ID, Start, End, Duration, Procs, Priv Events, ⚠ Dangerous
        for i, w in enumerate([120, 120, 155, 280, 90, 140, 140, 80, 50, 70, 80]):
            self._tbl.setColumnWidth(i, w)

        self._tbl.doubleClicked.connect(self._on_filter_clicked)
        self._tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tbl.customContextMenuRequested.connect(self._on_context_menu)
        root.addWidget(self._tbl)

        # ── Active filter badge ───────────────────────────────────────────
        self._filter_badge = QLabel()
        self._filter_badge.setStyleSheet(
            "background:#7a5c1e; color:white; border-radius:3px;"
            " padding:3px 8px; font-size:8.5pt; font-weight:bold;"
        )
        self._filter_badge.setVisible(False)
        root.addWidget(self._filter_badge)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()

        self._btn_filter = QPushButton("Filter to Selected Session")
        self._btn_filter.setToolTip(
            "Show only events belonging to this logon session in the main table"
        )
        self._btn_filter.clicked.connect(self._on_filter_clicked)
        btn_row.addWidget(self._btn_filter)

        self._btn_clear = QPushButton("Clear Session Filter")
        self._btn_clear.setToolTip("Remove the session filter and show all events")
        self._btn_clear.clicked.connect(self._on_clear_filter)
        btn_row.addWidget(self._btn_clear)

        btn_row.addStretch()

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        btn_row.addWidget(btn_close)

        root.addLayout(btn_row)

    # ── Table population ──────────────────────────────────────────────────

    def _populate_table(self, sessions: list[dict]) -> None:
        from PySide6.QtGui import QColor
        self._tbl.setSortingEnabled(False)
        self._tbl.setRowCount(len(sessions))

        active_color  = QColor("#fdf5dc")   # warm yellow for active (no logoff)
        danger_color  = QColor("#fde8e0")   # pale red for dangerous privs
        danger_fg     = QColor("#a01800")

        for row, s in enumerate(sessions):
            row_bg = None
            if s["has_dangerous"]:
                row_bg = danger_color
            elif not s["end_ts"]:
                row_bg = active_color

            start_disp = s["start_ts"].replace("T", " ").rstrip("Z")[:19] if s["start_ts"] else ""
            end_disp   = s["end_ts"].replace("T", " ").rstrip("Z")[:19] if s["end_ts"] else "Active"

            cells = [
                s["user"],
                s["computer"],
                s["logon_type_label"],
                s["initiation"],
                s["lid"],
                start_disp,
                end_disp,
                s["duration"],
                str(s["proc_count"]),
                str(s["priv_count"]),
                "⚠ Yes" if s["has_dangerous"] else "No",
            ]
            right_align_cols = {8, 9}   # Procs, Priv Events (shifted +1 by new column)

            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                align = (
                    Qt.AlignmentFlag.AlignRight if col in right_align_cols
                    else Qt.AlignmentFlag.AlignLeft
                )
                item.setTextAlignment(align | Qt.AlignmentFlag.AlignVCenter)
                # Store LogonId in UserRole for retrieval on click
                item.setData(Qt.ItemDataRole.UserRole, s["lid"])
                if row_bg:
                    item.setBackground(row_bg)
                if col == 10 and s["has_dangerous"]:   # ⚠ Dangerous column (shifted +1)
                    item.setForeground(danger_fg)
                self._tbl.setItem(row, col, item)

        self._tbl.setSortingEnabled(True)
        self._shown_sessions = sessions

    # ── Interaction ───────────────────────────────────────────────────────

    def _on_search(self, text: str) -> None:
        t = text.strip().lower()
        if not t:
            self._populate_table(self._all_sessions)
            return
        filtered = [
            s for s in self._all_sessions
            if t in s["user"].lower()
            or t in s["computer"].lower()
            or t in s["lid"].lower()
            or t in s["logon_type_label"].lower()
        ]
        self._populate_table(filtered)

    def _selected_session(self) -> dict | None:
        row = self._tbl.currentRow()
        if row < 0:
            return None
        item = self._tbl.item(row, 4)   # Session ID column (index 4 after Initiation added)
        if not item:
            return None
        lid = item.data(Qt.ItemDataRole.UserRole) or item.text()
        for s in self._all_sessions:
            if s["lid"] == lid:
                return s
        return None

    def _on_filter_clicked(self) -> None:
        sess = self._selected_session()
        if not sess:
            QMessageBox.information(self, "No Selection", "Select a session row first.")
            return
        self._on_filter_fn(sess["lid"], sess)
        self._filter_badge.setText(
            f"\U0001f510  Filtering:  {sess['user'] or '?'}  \u2022  "
            f"{sess['logon_type_label'] or '?'}  \u2022  "
            f"LogonId {sess['lid']}  \u2022  "
            f"started {sess['start_ts'].replace('T',' ')[:19] if sess['start_ts'] else '?'}"
            + (f"  \u2022  duration {sess['duration']}" if sess["duration"] else "")
        )
        self._filter_badge.setVisible(True)

    def _on_clear_filter(self) -> None:
        self._on_filter_fn(None, None)
        self._filter_badge.setVisible(False)

    def _on_context_menu(self, pos) -> None:
        """Right-click context menu on a session row."""
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui import QGuiApplication

        # Select the row under the cursor so _selected_session() picks it up
        index = self._tbl.indexAt(pos)
        if index.isValid():
            self._tbl.selectRow(index.row())

        sess = self._selected_session()

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#2b2b2b; color:#e8e8e8; border:1px solid #555; }"
            "QMenu::item:selected { background:#4a6fa5; color:white; }"
            "QMenu::separator { height:1px; background:#555; margin:4px 8px; }"
        )

        if sess:
            # Primary action
            act_filter = menu.addAction(
                f"\U0001f50d  Filter events for this session  "
                f"({sess['user'] or '?'} \u2022 LogonId {sess['lid']})"
            )
            act_filter.triggered.connect(self._on_filter_clicked)

            menu.addSeparator()

            # Copy helpers
            act_copy_lid = menu.addAction(f"\U0001f4cb  Copy Session ID  ({sess['lid']})")
            act_copy_lid.triggered.connect(
                lambda: QGuiApplication.clipboard().setText(sess["lid"])
            )

            act_copy_user = menu.addAction(f"\U0001f4cb  Copy Username  ({sess['user'] or '?'})")
            act_copy_user.triggered.connect(
                lambda: QGuiApplication.clipboard().setText(sess["user"] or "")
            )

            if sess["computer"]:
                act_copy_host = menu.addAction(f"\U0001f4cb  Copy Computer  ({sess['computer']})")
                act_copy_host.triggered.connect(
                    lambda: QGuiApplication.clipboard().setText(sess["computer"])
                )

            menu.addSeparator()

        # Clear filter — always available
        act_clear = menu.addAction("\u274c  Clear session filter")
        act_clear.setEnabled(self._filter_badge.isVisible())
        act_clear.triggered.connect(self._on_clear_filter)

        menu.exec(self._tbl.viewport().mapToGlobal(pos))


# ── Missing Record ID results dialog ──────────────────────────────────────────

class _MissingRecordIdDialog(QDialog):
    """Results dialog for the 'Identify Missing Record IDs' analysis."""

    def __init__(self, total_missing: int, file_count: int,
                 sections: list[str], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Missing Record ID Analysis")
        self.setModal(True)
        self.setMinimumSize(620, 440)
        self.resize(720, 520)

        self.setPalette(EventTimeZoneDialog._make_light_palette())
        self.setStyleSheet(EventTimeZoneDialog._LIGHT_QSS)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 12)
        root.setSpacing(10)

        # Summary header
        if total_missing == 0:
            summary_text = (
                f"<span style='color:#2e6820;font-size:10pt;font-weight:bold;'>"
                f"No gaps found</span> &mdash; all Record ID sequences are complete "
                f"across {file_count} file(s)."
            )
        else:
            summary_text = (
                f"<span style='color:#a01800;font-size:10pt;font-weight:bold;'>"
                f"{total_missing:,} missing Record ID(s)</span> detected across "
                f"{file_count} file(s). Gaps may indicate log tampering or clearing."
            )

        lbl_summary = QLabel(summary_text)
        lbl_summary.setWordWrap(True)
        lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        lbl_summary.setStyleSheet("background:transparent; padding:6px 0;")
        root.addWidget(lbl_summary)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color:#c4bba8;")
        root.addWidget(sep)

        # Per-file results in a scrollable text browser
        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)
        browser.setStyleSheet(
            "QTextBrowser { background:#faf7f2; border:1px solid #c4bba8;"
            " border-radius:3px; padding:4px; font-size:9pt; color:#1e1a14; }"
            "QScrollBar:vertical { background:#f5f0e8; width:8px; margin:0; }"
            "QScrollBar::handle:vertical { background:#5a3e1e; border-radius:4px; min-height:20px; }"
            "QScrollBar::handle:vertical:hover { background:#7a5c1e; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }"
        )
        browser.setHtml("<br>".join(sections))
        root.addWidget(browser)

        # Close button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_close = QPushButton("Close")
        btn_close.setObjectName("okBtn")
        btn_close.setFixedWidth(90)
        btn_close.clicked.connect(self.accept)
        btn_row.addWidget(btn_close)
        root.addLayout(btn_row)


# ── Add / Remove Columns dialog ───────────────────────────────────────────────

class AddRemoveColumnsDialog(QDialog):
    """
    Light-themed modal for managing which columns are shown and their order.

    Layout mirrors Windows Event Viewer:
      [Available cols]  [Add->/<-Remove]  [Displayed cols]  [Up/Down]
                                     [Restore Defaults]  [OK]  [Cancel]

    Uses the same palette/QSS isolation as EventTimeZoneDialog so the dark
    application theme does not bleed into the controls.
    """

    _DEFAULT_VISIBLE: list[int] = list(range(COL_DEFAULT_COUNT))  # 0-8

    # Extra QSS on top of the base cream QSS — styles the list widgets
    _EXTRA_QSS = """
        QListWidget {
            background: #faf7f2;
            color: #1e1a14;
            border: 1px solid #c4bba8;
            border-radius: 0px;
            outline: none;
            font-size: 9pt;
        }
        QListWidget::item {
            /* Zero vertical padding + minimal horizontal so text
               sits flush — no gap between rows or beside the border. */
            padding: 0px 2px;
            color: #1e1a14;
            background: transparent;
            border: none;
        }
        QListWidget::item:selected {
            background: #7a5c1e;
            color: #ffffff;
        }
        QListWidget::item:hover:!selected {
            background: #e0d8c4;
            color: #1e1a14;
        }
        QPushButton {
            background: #e4ddd3;
            color: #1e1a14;
            border: 1px solid #c4bba8;
            border-radius: 3px;
            padding: 4px 14px;
            min-height: 0;
            font-size: 9pt;
        }
        QPushButton:hover   { background: #ccc5b5; }
        QPushButton:pressed { background: #b8b0a0; }
        QPushButton:disabled { color: #9a8878; background: #ede8df; border-color: #c4bba8; }
        QPushButton#okBtn {
            background: #7a5c1e;
            color: #ffffff;
            border: none;
            border-radius: 3px;
            padding: 4px 18px;
            font-weight: bold;
        }
        QPushButton#okBtn:hover   { background: #6b4e18; }
        QPushButton#okBtn:pressed { background: #5a3e10; }
        QPushButton#cancelBtn {
            background: #e4ddd3;
            color: #1e1a14;
            border: 1px solid #c4bba8;
            border-radius: 3px;
            padding: 4px 14px;
        }
        QPushButton#cancelBtn:hover { background: #ccc5b5; }
    """

    def __init__(self, visible_cols: list[int], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add/Remove Columns")
        self.setModal(True)
        self.setMinimumSize(660, 400)

        # Light theme (same isolation strategy as EventTimeZoneDialog)
        self.setPalette(EventTimeZoneDialog._make_light_palette())
        self.setStyleSheet(EventTimeZoneDialog._LIGHT_QSS + self._EXTRA_QSS)

        # ── Root layout ───────────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 12)
        root.setSpacing(10)

        # ── Middle row ────────────────────────────────────────────────────────
        mid = QHBoxLayout()
        mid.setSpacing(8)

        # Available columns (left)
        _avail_vbox = QVBoxLayout()
        _avail_vbox.setSpacing(4)
        _avail_lbl = QLabel("Available columns:")
        _avail_lbl.setStyleSheet("font-size:9pt; color:#1e1a14; background:transparent;")
        _avail_vbox.addWidget(_avail_lbl)
        self._list_avail = QListWidget()
        self._list_avail.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._list_avail.setUniformItemSizes(True)   # uniform row height = compact look
        self._list_avail.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list_avail.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._list_avail.itemDoubleClicked.connect(self._do_add)
        _avail_vbox.addWidget(self._list_avail)
        mid.addLayout(_avail_vbox, 2)

        # Add / Remove buttons (centre column)
        _btn_col = QVBoxLayout()
        _btn_col.setSpacing(6)
        _btn_col.addStretch()
        self._btn_add = QPushButton("Add  →")
        self._btn_add.clicked.connect(self._do_add)
        _btn_col.addWidget(self._btn_add)
        self._btn_remove = QPushButton("←  Remove")
        self._btn_remove.clicked.connect(self._do_remove)
        _btn_col.addWidget(self._btn_remove)
        _btn_col.addStretch()
        mid.addLayout(_btn_col)

        # Displayed columns (right)
        _disp_vbox = QVBoxLayout()
        _disp_vbox.setSpacing(4)
        _disp_lbl = QLabel("Displayed columns:")
        _disp_lbl.setStyleSheet("font-size:9pt; color:#1e1a14; background:transparent;")
        _disp_vbox.addWidget(_disp_lbl)
        self._list_disp = QListWidget()
        self._list_disp.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._list_disp.setUniformItemSizes(True)   # matches Available list row height
        self._list_disp.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list_disp.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._list_disp.itemDoubleClicked.connect(self._do_remove)
        _disp_vbox.addWidget(self._list_disp)
        mid.addLayout(_disp_vbox, 2)

        # Move Up / Move Down (far right)
        _move_col = QVBoxLayout()
        _move_col.setSpacing(6)
        _move_col.addSpacing(22)   # align with list (label height)
        self._btn_up = QPushButton("Move Up")
        self._btn_up.clicked.connect(self._do_move_up)
        _move_col.addWidget(self._btn_up)
        self._btn_dn = QPushButton("Move Down")
        self._btn_dn.clicked.connect(self._do_move_down)
        _move_col.addWidget(self._btn_dn)
        _move_col.addStretch()
        mid.addLayout(_move_col)

        root.addLayout(mid, 1)

        # ── Bottom row ────────────────────────────────────────────────────────
        _bot = QHBoxLayout()
        _bot.setSpacing(8)
        _btn_restore = QPushButton("Restore Defaults")
        _btn_restore.clicked.connect(self._do_restore)
        _bot.addWidget(_btn_restore)
        _bot.addStretch()
        _btn_ok = QPushButton("OK")
        _btn_ok.setObjectName("okBtn")
        _btn_ok.setDefault(True)
        _btn_ok.clicked.connect(self.accept)
        _btn_cancel = QPushButton("Cancel")
        _btn_cancel.setObjectName("cancelBtn")
        _btn_cancel.clicked.connect(self.reject)
        _bot.addWidget(_btn_ok)
        _bot.addWidget(_btn_cancel)
        root.addLayout(_bot)

        # Populate from current state
        self._populate(visible_cols)

    # ── List population ───────────────────────────────────────────────────────

    def _populate(self, visible_cols: list[int]) -> None:
        """Rebuild both list widgets from a visible_cols order list."""
        visible_set = set(visible_cols)

        self._list_disp.clear()
        for col_idx in visible_cols:
            item = QListWidgetItem(COLUMNS[col_idx])
            item.setData(Qt.ItemDataRole.UserRole, col_idx)
            self._list_disp.addItem(item)

        self._list_avail.clear()
        for col_idx in range(len(COLUMNS)):
            if col_idx not in visible_set:
                item = QListWidgetItem(COLUMNS[col_idx])
                item.setData(Qt.ItemDataRole.UserRole, col_idx)
                self._list_avail.addItem(item)

    # ── Slot: Add ─────────────────────────────────────────────────────────────

    def _do_add(self) -> None:
        """Move selected item from Available → Displayed."""
        sel = self._list_avail.selectedItems()
        if not sel:
            return
        item = sel[0]
        col_idx = item.data(Qt.ItemDataRole.UserRole)
        self._list_avail.takeItem(self._list_avail.row(item))
        new_item = QListWidgetItem(COLUMNS[col_idx])
        new_item.setData(Qt.ItemDataRole.UserRole, col_idx)
        self._list_disp.addItem(new_item)
        self._list_disp.setCurrentItem(new_item)

    # ── Slot: Remove ──────────────────────────────────────────────────────────

    def _do_remove(self) -> None:
        """Move selected item from Displayed → Available (sorted by col index)."""
        sel = self._list_disp.selectedItems()
        if not sel:
            return
        item = sel[0]
        col_idx = item.data(Qt.ItemDataRole.UserRole)
        self._list_disp.takeItem(self._list_disp.row(item))
        # Re-insert into Available in ascending column-index order
        new_item = QListWidgetItem(COLUMNS[col_idx])
        new_item.setData(Qt.ItemDataRole.UserRole, col_idx)
        insert_at = self._list_avail.count()
        for i in range(self._list_avail.count()):
            if self._list_avail.item(i).data(Qt.ItemDataRole.UserRole) > col_idx:
                insert_at = i
                break
        self._list_avail.insertItem(insert_at, new_item)
        self._list_avail.setCurrentItem(new_item)

    # ── Slot: Move Up / Down ──────────────────────────────────────────────────

    def _do_move_up(self) -> None:
        sel = self._list_disp.selectedItems()
        if not sel:
            return
        row = self._list_disp.row(sel[0])
        if row <= 0:
            return
        item = self._list_disp.takeItem(row)
        self._list_disp.insertItem(row - 1, item)
        self._list_disp.setCurrentRow(row - 1)

    def _do_move_down(self) -> None:
        sel = self._list_disp.selectedItems()
        if not sel:
            return
        row = self._list_disp.row(sel[0])
        if row >= self._list_disp.count() - 1:
            return
        item = self._list_disp.takeItem(row)
        self._list_disp.insertItem(row + 1, item)
        self._list_disp.setCurrentRow(row + 1)

    # ── Slot: Restore Defaults ────────────────────────────────────────────────

    def _do_restore(self) -> None:
        self._populate(self._DEFAULT_VISIBLE)

    # ── Result ────────────────────────────────────────────────────────────────

    def get_visible_cols(self) -> list[int]:
        """Return ordered list of logical column indices to display."""
        return [
            self._list_disp.item(i).data(Qt.ItemDataRole.UserRole)
            for i in range(self._list_disp.count())
        ]


# ── Export scope chooser ──────────────────────────────────────────────────────

class _FilterTargetDialog(QDialog):
    """
    Shown in separate-tabs mode when the user applies any filter.
    Lets them pick which open file tabs the filter should be applied to.
    """

    def __init__(self, file_tabs: dict, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Apply Filter To…")
        self.setWindowFlags(
            self.windowFlags() & ~Qt.WindowType.WindowContextHelpButtonHint
        )
        self.setMinimumWidth(340)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Apply filter to:"))

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(4)

        self._checkboxes: list[tuple[str, QCheckBox]] = []
        for fp, state in file_tabs.items():
            if fp.startswith("__chain__"):
                continue
            cb = QCheckBox(state.display_name)
            cb.setToolTip(fp)
            cb.setChecked(True)
            inner_layout.addWidget(cb)
            self._checkboxes.append((fp, cb))
        inner_layout.addStretch()
        scroll.setWidget(inner)
        layout.addWidget(scroll)

        btn_row = QHBoxLayout()
        btn_all  = QPushButton("Select All")
        btn_none = QPushButton("Select None")
        btn_all.setFixedHeight(22)
        btn_none.setFixedHeight(22)
        btn_all.clicked.connect(lambda: [cb.setChecked(True)  for _, cb in self._checkboxes])
        btn_none.clicked.connect(lambda: [cb.setChecked(False) for _, cb in self._checkboxes])
        btn_row.addWidget(btn_all)
        btn_row.addWidget(btn_none)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def selected(self) -> list[str]:
        return [fp for fp, cb in self._checkboxes if cb.isChecked()]


class _ExportScopeDialog(QDialog):
    """
    Clean export-scope chooser with four radio-button options:

      • Export Current View   — whatever is visible/filtered in the active tab
      • Export All Combined   — all events merged into one output file
      • Export All Separate   — one output file per source EVTX file
      • Export Specific Files — user picks which source files to include

    When "Specific Files" is chosen the dialog reveals a scrollable checklist
    of all loaded source files.
    """

    def __init__(
        self,
        all_file_paths: list[str],
        active_file: str | None,
        view_mode: str,
        total_events: int,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Export")
        self.setMinimumWidth(440)
        self._all_file_paths = all_file_paths
        self._scope = "combined"       # default
        self._file_checks: list[tuple[QCheckBox, str]] = []

        from .theme import COLORS

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 14, 16, 14)
        root.setSpacing(10)

        # ── Title ─────────────────────────────────────────────────────────
        title = QLabel("Choose what to export:")
        font = title.font()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 1)
        title.setFont(font)
        root.addWidget(title)

        # ── Radio buttons ─────────────────────────────────────────────────
        from PySide6.QtWidgets import QRadioButton, QButtonGroup, QScrollArea, QGroupBox

        self._btn_grp = QButtonGroup(self)

        active_name = os.path.basename(active_file) if active_file else "current view"
        n_files = len(all_file_paths)

        self._rb_view = QRadioButton(
            f"Current view  —  {active_name} (with active filters)"
        )
        self._rb_combined = QRadioButton(
            f"All files combined  —  {total_events:,} events, {n_files} file(s)"
        )
        self._rb_separate = QRadioButton(
            f"All files separate  —  one output file per source ({n_files} file(s))"
        )
        self._rb_specific = QRadioButton("Specific files  —  choose below")

        for i, rb in enumerate([self._rb_view, self._rb_combined,
                                  self._rb_separate, self._rb_specific]):
            self._btn_grp.addButton(rb, i)
            root.addWidget(rb)

        self._rb_combined.setChecked(True)

        # ── File checklist (revealed when "Specific" is chosen) ────────────
        self._files_box = QGroupBox("Select files to export:")
        files_layout = QVBoxLayout(self._files_box)
        files_layout.setSpacing(3)
        files_layout.setContentsMargins(8, 8, 8, 8)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFixedHeight(min(180, 32 * max(1, len(all_file_paths))))
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setSpacing(2)
        inner_layout.setContentsMargins(0, 0, 0, 0)

        for fp in all_file_paths:
            chk = QCheckBox(os.path.basename(fp))
            chk.setChecked(True)
            chk.setToolTip(fp)
            inner_layout.addWidget(chk)
            self._file_checks.append((chk, fp))

        scroll.setWidget(inner)
        files_layout.addWidget(scroll)

        # Select All / None mini-buttons inside the box
        mini_row = QHBoxLayout()
        btn_all_files = QPushButton("All")
        btn_all_files.setMaximumWidth(50)
        btn_all_files.clicked.connect(lambda: [c.setChecked(True) for c, _ in self._file_checks])
        btn_none_files = QPushButton("None")
        btn_none_files.setMaximumWidth(55)
        btn_none_files.clicked.connect(lambda: [c.setChecked(False) for c, _ in self._file_checks])
        mini_row.addWidget(btn_all_files)
        mini_row.addWidget(btn_none_files)
        mini_row.addStretch()
        files_layout.addLayout(mini_row)

        self._files_box.setVisible(False)
        root.addWidget(self._files_box)

        # ── OK / Cancel ───────────────────────────────────────────────────
        root.addSpacing(4)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_ok = QPushButton("Export")
        btn_ok.setDefault(True)
        btn_ok.setMinimumWidth(80)
        btn_ok.clicked.connect(self._on_ok)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.setMinimumWidth(70)
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_ok)
        btn_row.addWidget(btn_cancel)
        root.addLayout(btn_row)

        # Wire visibility of file list
        self._rb_specific.toggled.connect(self._files_box.setVisible)
        self._rb_specific.toggled.connect(lambda _: self.adjustSize())

        # Apply theme styles
        self.setStyleSheet(f"""
            QDialog {{ background: {COLORS['bg_panel']}; color: {COLORS['text']}; }}
            QLabel  {{ color: {COLORS['text']}; font-size: 9pt; }}
            QRadioButton {{ color: {COLORS['text']}; font-size: 9pt; spacing: 6px; }}
            QRadioButton::indicator {{ width: 14px; height: 14px; }}
            QCheckBox {{ color: {COLORS['text']}; font-size: 9pt; spacing: 4px; }}
            QCheckBox::indicator {{ width: 13px; height: 13px; }}
            QGroupBox {{
                color: {COLORS['text']}; border: 1px solid {COLORS['border']};
                border-radius: 4px; margin-top: 8px; padding-top: 10px;
                font-size: 9pt; font-weight: bold;
            }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; }}
            QPushButton {{
                background: {COLORS['bg_header']}; color: {COLORS['text']};
                border: 1px solid {COLORS['border']}; border-radius: 3px;
                padding: 4px 12px; font-size: 9pt;
            }}
            QPushButton:hover {{ background: {COLORS.get('accent', '#7a5c1e')}; color: white; }}
            QScrollArea {{ border: none; background: transparent; }}
        """)

    def _on_ok(self) -> None:
        bid = self._btn_grp.checkedId()
        self._scope = ["view", "combined", "separate", "specific"][bid]
        if self._scope == "specific" and not self.selected_files():
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.warning(self, "No Files Selected",
                                "Please check at least one file to export.")
            return
        self.accept()

    def selected_scope(self) -> str:
        """Returns 'view' | 'combined' | 'separate' | 'specific'."""
        return self._scope

    def selected_files(self) -> set:
        """Returns set of full file paths selected (only meaningful for 'specific')."""
        return {fp for chk, fp in self._file_checks if chk.isChecked()}


# ── Main Window ───────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """
    Main application window.
    All parsing runs in ParseWorker(QThread) — GUI never freezes.
    """

    def __init__(self, initial_paths: list[str] | None = None):
        super().__init__()
        self.setWindowTitle("EventHawk  v1.2")
        self.resize(1420, 860)
        self.setMinimumSize(900, 600)


        # ── Live state (set after parse finishes) ──────────────────────────
        self._events:         list[dict]  = []
        self._attack_summary: dict | None = None
        self._iocs:           dict | None = None
        self._chains:         list        = []
        self._worker:         ParseWorker | None = None
        self._analysis_runner: AnalysisRunner | None = None
        # IOC pivot map: (category_key, value) → frozenset[record_id].
        # Built in _on_analysis_finished; cleared when analysis restarts.
        # category_key matches the keys in the ioc_types list in _refresh_iocs_tab.
        self._ioc_pivot_map: dict[tuple[str, str], frozenset] = {}
        # Bookmark storage — session-scoped.
        # _bookmarked_keys uses (source_file, record_id) composite key so that events
        # with the same record_id from different files are distinguished in merge mode.
        self._bookmarks: list[dict] = []
        self._bookmarked_keys: set[tuple[str, int]] = set()
        # Detail-pane render cache: skip re-building HTML when the same event
        # and display mode are re-selected.  Key: (record_id, source_file, full_mode).
        self._last_detail_key: tuple | None = None
        self._parse_start_ts: float = 0.0
        self._metadata:       dict        = {}   # field → {value → count}


        # ── ATT&CK tactic filter state ──────────────────────────────────────
        self._active_tactic_filter:    str | None = None   # lowercase tactic name
        self._active_technique_filter: str | None = None   # lowercase TID or None

        # ── Advanced filter state ────────────────────────────────────────────
        self._adv_filter_cfg:  dict | None = None   # last-used FilterDialog config

        # ── Column header dropdown filter state ─────────────────────────────
        self._col_filters: dict[int, list[str]] = {}  # col_idx → list of excluded values

        # ── Per-file tab/tree state ───────────────────────────────────────────
        self._view_mode: str = "merged"                   # "merged" or "separate"
        self._per_file_data: dict[str, dict] = {}         # filepath → {events, search_cache}
        self._file_tabs: dict[str, FileTabState] = {}     # filepath → tab state
        self._active_file_tab: str | None = None          # filepath of current tab
        self._analysis_scope: str = "file"                # "file" or "all"

        # ── Timezone display state ───────────────────────────────────────────
        self._tz_mode:              str = "local"        # "local"|"utc"|"specific"|"custom"
        self._tz_specific:          str = "Asia/Kolkata" # IANA name for "specific" mode
        self._tz_custom_offset_min: int = 330            # signed minutes (+330 = +05:30)

        # ── Column visibility state ──────────────────────────────────────────
        # Ordered list of column indices currently shown (default = first 9)
        self._visible_cols: list[int] = list(range(COL_DEFAULT_COUNT))

        # ── Event detail pane mode ────────────────────────────────────────────
        # True = Full (all fields shown);  False = Brief (header block only)
        self._detail_full_mode: bool = True

        # ── Left panel collapse state ────────────────────────────────────────
        self._panel_open:         bool   = True
        self._panel_stored_width: int    = 270
        self._panel_anim:         object = None   # keep QPropertyAnimation alive

        # ── Build UI ───────────────────────────────────────────────────────
        self._build_menu()
        self._build_central()
        self._build_status_bar()
        self._connect_signals()

        # Pre-populate profiles list
        self._refresh_profiles()

        # Watch profiles directories for auto-refresh
        self._profile_watcher = QFileSystemWatcher(self)
        self._profile_watcher_timer = QTimer(self)
        self._profile_watcher_timer.setSingleShot(True)
        self._profile_watcher_timer.setInterval(500)  # 500ms debounce
        self._profile_watcher_timer.timeout.connect(self._refresh_profiles)
        self._profile_watcher.directoryChanged.connect(
            lambda _: self._profile_watcher_timer.start()
        )
        self._setup_profile_watcher()

        # Pre-load any paths passed on launch
        if initial_paths:
            for p in initial_paths:
                self._add_path(p)

        self._set_status("Ready")

    # =========================================================================
    # MENU BAR
    # =========================================================================

    def _build_menu(self) -> None:
        mb = self.menuBar()

        # ── File ──────────────────────────────────────────────────────────
        fm = mb.addMenu("File")
        a = fm.addAction("Add File(s)...")
        a.setShortcut(QKeySequence("Ctrl+O"))
        a.triggered.connect(self._on_add_files)

        a = fm.addAction("Add Directory...")
        a.setShortcut(QKeySequence("Ctrl+Shift+O"))
        a.triggered.connect(self._on_add_dir)

        fm.addSeparator()
        self._act_export = fm.addAction("Export Events...")
        self._act_export.setShortcut(QKeySequence("Ctrl+S"))
        self._act_export.setEnabled(False)
        self._act_export.triggered.connect(self._on_export_clicked)

        fm.addSeparator()
        a = fm.addAction("Exit")
        a.setShortcut(QKeySequence("Ctrl+Q"))
        a.triggered.connect(self.close)

        # ── Tools ─────────────────────────────────────────────────────────
        tm = mb.addMenu("Tools")
        a = tm.addAction("View Logon Sessions\u2026")
        a.setToolTip("Browse all logon sessions, view durations and types, filter events to a session")
        a.triggered.connect(self._on_show_logon_sessions)

        tm.addSeparator()
        a = tm.addAction("Clear Results")
        a.triggered.connect(self._clear_results)

        tm.addSeparator()
        a = tm.addAction("Baseline Analysis (Sentinel)...")
        a.setToolTip("Differential EVTX log analysis — compare target against a known-good baseline")
        a.triggered.connect(self._launch_sentinel)

        # ── Time zone ─────────────────────────────────────────────────────
        tz_act = mb.addAction("Time zone")
        tz_act.setToolTip("Configure how event timestamps are displayed")
        tz_act.triggered.connect(self._on_timezone_action)

        # ── PowerShell History ─────────────────────────────────────────────
        self._act_ps_extract = mb.addAction("PowerShell History")
        self._act_ps_extract.setToolTip(
            "Export PowerShell artifacts — commands and scripts executed"
        )
        self._act_ps_extract.setEnabled(False)
        self._act_ps_extract.triggered.connect(self._on_ps_extract)


    # =========================================================================
    # CENTRAL WIDGET (3-panel splitter)
    # =========================================================================

    def _build_central(self) -> None:
        root_splitter = QSplitter(Qt.Orientation.Horizontal)
        root_splitter.setChildrenCollapsible(False)

        # Left: filter panel wrapped with a collapse-toggle button on its right edge
        left_wrapper = self._build_left_wrapper()

        # Right side: vertical splitter (events table | detail + analysis)
        right_splitter = QSplitter(Qt.Orientation.Vertical)
        right_splitter.setChildrenCollapsible(False)

        top_panel = self._build_events_panel()
        bottom_panel = self._build_bottom_panel()

        right_splitter.addWidget(top_panel)
        right_splitter.addWidget(bottom_panel)
        right_splitter.setSizes([480, 340])

        root_splitter.addWidget(left_wrapper)
        root_splitter.addWidget(right_splitter)
        # 270 panel + 16 toggle button = 286 for the left wrapper
        root_splitter.setSizes([286, 1134])

        self.setCentralWidget(root_splitter)

        # Restore saved open/collapsed state after the window geometry is settled
        QTimer.singleShot(50, self._restore_panel_state)

    # =========================================================================
    # LEFT PANEL WRAPPER  (filter panel + collapse toggle)
    # =========================================================================

    def _build_left_wrapper(self) -> QWidget:
        """
        Thin QWidget that holds the filter panel and a 16-px collapse/expand
        toggle button at its right edge.  The toggle button is always visible;
        only the scroll area animates in/out.

        The WRAPPER's maximumWidth is animated (not the inner scroll area's),
        so the QSplitter sees the size change and expands the right panel.
        """
        wrapper = QWidget()
        wrapper.setMinimumWidth(16)   # always at least as wide as the toggle button
        self._left_panel_wrapper = wrapper   # stored for animation

        hbox = QHBoxLayout(wrapper)
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.setSpacing(0)

        # ── Filter panel ──────────────────────────────────────────────────
        self._left_panel_scroll = self._build_left_panel()
        self._left_panel_scroll.setMinimumWidth(0)  # let the layout shrink it when wrapper collapses
        # No explicit maximumWidth on the scroll area — the wrapper's maxWidth drives sizing
        hbox.addWidget(self._left_panel_scroll)

        # ── Collapse / expand toggle button (right edge of left panel) ────
        self._btn_panel_toggle = QPushButton("◀")
        self._btn_panel_toggle.setFixedWidth(16)
        self._btn_panel_toggle.setSizePolicy(
            QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding
        )
        self._btn_panel_toggle.setToolTip("Collapse / expand filter panel")
        self._btn_panel_toggle.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text_dim']};
                border: none;
                border-left: 1px solid {COLORS['border']};
                border-radius: 0;
                font-size: 7pt;
                padding: 0;
                min-height: 0;
            }}
            QPushButton:hover {{
                background: {COLORS['bg_header']};
                color: {COLORS['text']};
            }}
            QPushButton:pressed {{
                background: {COLORS['bg_main']};
                color: {COLORS['accent_hover']};
            }}
        """)
        self._btn_panel_toggle.clicked.connect(self._toggle_left_panel)
        hbox.addWidget(self._btn_panel_toggle)

        return wrapper

    # =========================================================================
    # LEFT PANEL
    # =========================================================================

    def _build_left_panel(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        # ── FILES ─────────────────────────────────────────────────────────
        layout.addWidget(_section_label("Files"))

        self._file_list = QListWidget()
        self._file_list.setMaximumHeight(110)
        self._file_list.setSpacing(0)
        self._file_list.setToolTip("Files/directories to parse")
        layout.addWidget(self._file_list)

        btn_row = QHBoxLayout()
        btn_add_files = QPushButton("+ Files")
        btn_add_files.setToolTip("Add EVTX files (Ctrl+O)")
        btn_add_files.clicked.connect(self._on_add_files)
        btn_add_dir = QPushButton("+ Dir")
        btn_add_dir.setToolTip("Add directory (Ctrl+Shift+O)")
        btn_add_dir.clicked.connect(self._on_add_dir)
        btn_clear_files = QPushButton("✕")
        btn_clear_files.setToolTip("Clear file list and parsed results")
        btn_clear_files.setMaximumWidth(28)
        btn_clear_files.clicked.connect(self._on_clear_files)
        btn_row.addWidget(btn_add_files)
        btn_row.addWidget(btn_add_dir)
        btn_row.addWidget(btn_clear_files)
        layout.addLayout(btn_row)

        layout.addWidget(_sep())

        # ── PROFILES ──────────────────────────────────────────────────────
        layout.addWidget(_section_label("Profiles"))

        self._profile_combo = CheckableComboBox(placeholder="— no profile —")
        self._profile_combo.setToolTip(
            "Click to open list — tick the profiles you want to activate.\n"
            "The dropdown stays open while you select."
        )
        layout.addWidget(self._profile_combo)

        prof_btn_row = QHBoxLayout()
        btn_all = QPushButton("All")
        btn_all.setToolTip("Select all profiles")
        btn_all.clicked.connect(self._select_all_profiles)
        btn_none = QPushButton("None")
        btn_none.setToolTip("Deselect all profiles")
        btn_none.clicked.connect(self._select_no_profiles)
        btn_refresh = QPushButton('↻')
        btn_refresh.setToolTip('Refresh profiles from disk')
        btn_refresh.setMaximumWidth(28)
        btn_refresh.clicked.connect(self._refresh_profiles)
        prof_btn_row.addWidget(btn_all)
        prof_btn_row.addWidget(btn_none)
        prof_btn_row.addWidget(btn_refresh)
        layout.addLayout(prof_btn_row)

        prof_edit_row = QHBoxLayout()
        btn_new_profile = QPushButton("＋ New Profile")
        btn_new_profile.setToolTip("Create a new custom profile")
        btn_new_profile.clicked.connect(self._on_new_profile)
        self._btn_edit_profile = QPushButton("✎ Edit Profile")
        self._btn_edit_profile.setToolTip(
            "Edit or view the selected profile\n"
            "(built-in profiles can be copied to a new custom profile)"
        )
        self._btn_edit_profile.clicked.connect(self._on_edit_profile)
        prof_edit_row.addWidget(btn_new_profile)
        prof_edit_row.addWidget(self._btn_edit_profile)
        layout.addLayout(prof_edit_row)

        layout.addWidget(_sep())


        # ── ANALYSIS ──────────────────────────────────────────────────────
        layout.addWidget(_section_label("Analysis"))
        self._chk_attack   = QCheckBox("ATT&CK Mapping")
        self._chk_attack.setChecked(True)
        self._chk_ioc      = QCheckBox("IOC Extraction")
        self._chk_correlate = QCheckBox("Correlation Engine")
        self._chk_hayabusa  = QCheckBox("Hayabusa Rules")
        self._chk_hayabusa.setToolTip(
            "Run Hayabusa sigma-based threat detection rules against the loaded EVTX files.\n"
            "Hayabusa is a free, open-source Windows event log fast-forensics tool.\n"
            "Requires the Hayabusa executable — use the Browse button below to set its path.\n"
            "Download: https://github.com/Yamato-Security/hayabusa/releases"
        )
        layout.addWidget(self._chk_attack)
        layout.addWidget(self._chk_ioc)
        layout.addWidget(self._chk_correlate)
        layout.addWidget(self._chk_hayabusa)

        # Hayabusa binary path picker
        lbl_hayabusa_hint = QLabel("Hayabusa path  (hayabusa.exe)")
        lbl_hayabusa_hint.setStyleSheet("font-size: 11px; color: #9a8878; margin-bottom: 0px;")
        lbl_hayabusa_hint.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(lbl_hayabusa_hint)
        layout.addSpacing(-4)

        hayabusa_row = QHBoxLayout()
        self._lbl_hayabusa_path = QLabel("Not configured")
        self._lbl_hayabusa_path.setStyleSheet("font-size: 11px; color: #aaa;")
        self._btn_hayabusa_path = QPushButton("Browse…")
        self._btn_hayabusa_path.setFixedHeight(24)
        self._btn_hayabusa_path.setToolTip(
            "Select the Hayabusa executable (hayabusa.exe or hayabusa on Linux/macOS).\n\n"
            "Hayabusa is a standalone .exe — download the latest release from:\n"
            "  github.com/Yamato-Security/hayabusa/releases\n\n"
            "After selecting, the path is saved automatically for future sessions."
        )
        self._btn_hayabusa_path.clicked.connect(self._pick_hayabusa_path)
        hayabusa_row.addWidget(self._lbl_hayabusa_path)
        hayabusa_row.addStretch()
        hayabusa_row.addWidget(self._btn_hayabusa_path)
        layout.addLayout(hayabusa_row)

        # Auto-detect or load saved path
        self._hayabusa_path: str | None = None
        self._load_hayabusa_path()

        layout.addWidget(QLabel("Max threads:"))
        self._cmb_threads = QComboBox()
        cpu = os.cpu_count() or 4
        self._cmb_threads.addItem(f"Auto (CPU-1 = {max(1, cpu - 1)})", None)
        # Build dynamic list: powers of 2, half-cpu, cpu-1 — all < cpu, deduped, sorted
        _seen: set[int] = set()
        _cands: list[int] = []
        _p = 1
        while _p < cpu:
            _cands.append(_p); _seen.add(_p); _p *= 2
        for _extra in (max(1, cpu // 2), max(1, cpu - 1)):
            if _extra not in _seen:
                _cands.append(_extra); _seen.add(_extra)
        for n in sorted(_cands):
            self._cmb_threads.addItem(str(n), n)
        layout.addWidget(self._cmb_threads)

        layout.addWidget(_sep())

        # ── VIEW MODE ────────────────────────────────────────────────────
        layout.addWidget(_section_label("View Mode"))
        vm_row = QHBoxLayout()
        self._radio_merge = QRadioButton("Merge All")
        self._radio_merge.setChecked(True)
        self._radio_merge.setToolTip("Combine all files into a single chronological view")
        self._radio_separate = QRadioButton("Separate Tabs")
        self._radio_separate.setToolTip("Each file gets its own tab — browse via file tree")
        vm_row.addWidget(self._radio_merge)
        vm_row.addWidget(self._radio_separate)
        layout.addLayout(vm_row)

        layout.addWidget(_sep())

        # ── ACTION ────────────────────────────────────────────────────────
        layout.addWidget(_section_label("Action"))

        self._btn_parse = QPushButton("▶   PARSE")
        self._btn_parse.setObjectName("parseBtn")
        self._btn_parse.setMinimumHeight(32)
        layout.addWidget(self._btn_parse)

        self._btn_stop = QPushButton("■   STOP")
        self._btn_stop.setObjectName("stopBtn")
        self._btn_stop.setEnabled(False)
        layout.addWidget(self._btn_stop)

        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setFormat("%p%")
        self._progress_bar.setTextVisible(True)
        layout.addWidget(self._progress_bar)

        self._lbl_matched = QLabel("Events: —")
        self._lbl_matched.setObjectName("statsLabel")
        self._lbl_speed = QLabel("Speed: —")
        self._lbl_speed.setObjectName("statsLabel")
        self._lbl_elapsed = QLabel("Time: —")
        self._lbl_elapsed.setObjectName("statsLabel")
        layout.addWidget(self._lbl_matched)
        layout.addWidget(self._lbl_speed)
        layout.addWidget(self._lbl_elapsed)

        layout.addWidget(_sep())

        self._btn_export = QPushButton("⬇   Export Report")
        self._btn_export.setObjectName("exportBtn")
        self._btn_export.setEnabled(False)
        layout.addWidget(self._btn_export)

        layout.addStretch()

        scroll.setWidget(container)
        return scroll

    # =========================================================================
    # CENTER: EVENTS TABLE + FILTER BAR
    # =========================================================================

    def _build_events_panel(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Live filter bar ───────────────────────────────────────────────
        filter_row = QHBoxLayout()
        # Qt assigns 9 px style-based margins to sub-layouts by default;
        # explicitly zero them so there is no blank gap above/below the filter bar.
        filter_row.setContentsMargins(4, 0, 4, 0)
        filter_row.setSpacing(6)

        # Advanced filter button (funnel icon)
        self._btn_adv_filter = QPushButton("🔍  Filter")
        self._btn_adv_filter.setObjectName("advFilterBtn")
        self._btn_adv_filter.setToolTip("Open advanced filter dialog  (Event Log Explorer style)")
        self._btn_adv_filter.setMaximumHeight(24)
        self._btn_adv_filter.setFixedWidth(90)
        self._btn_adv_filter.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_header']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 2px 8px;
                font-size: 8pt;
            }}
            QPushButton:hover {{
                background: {COLORS.get('accent', '#7a5c1e')};
                color: white;
            }}
        """)
        self._btn_adv_filter.clicked.connect(self._on_advanced_filter_clicked)
        filter_row.addWidget(self._btn_adv_filter)

        # Advanced filter active badge (hidden by default)
        self._lbl_adv_filter_badge = QLabel("⚡ Filter Active")
        self._lbl_adv_filter_badge.setStyleSheet(
            f"color:{COLORS.get('accent', '#7a5c1e')}; font-size:8pt; "
            f"font-weight:bold; padding:1px 6px; "
            f"border:1px solid {COLORS.get('accent', '#7a5c1e')}; "
            f"border-radius:3px;"
        )
        self._lbl_adv_filter_badge.setVisible(False)
        filter_row.addWidget(self._lbl_adv_filter_badge)

        # Clear advanced filter button (hidden by default)
        self._btn_clear_adv = QPushButton("✕")
        self._btn_clear_adv.setMaximumSize(20, 20)
        self._btn_clear_adv.setToolTip("Clear advanced filter")
        self._btn_clear_adv.setStyleSheet(
            f"QPushButton{{font-size:7pt; padding:0; border:none; color:{COLORS['text_dim']};}}"
            f"QPushButton:hover{{color:#a01800;}}"
        )
        self._btn_clear_adv.setVisible(False)
        self._btn_clear_adv.clicked.connect(self._clear_advanced_filter)
        filter_row.addWidget(self._btn_clear_adv)

        # ── Clear ALL filters — always visible ─────────────────────────────
        self._btn_clear_all_filters = QPushButton("⟳  Clear All Filters")
        self._btn_clear_all_filters.setMaximumHeight(24)
        self._btn_clear_all_filters.setFixedWidth(130)
        self._btn_clear_all_filters.setToolTip(
            "Reset everything: text search, advanced filter, quick filters, "
            "session filter, tactic filter, bookmark/IOC pivot"
        )
        self._btn_clear_all_filters.setStyleSheet("""
            QPushButton {
                background: #3d2e0a;
                color: #d4a843;
                border: 1px solid #7a5c1e;
                border-radius: 3px;
                padding: 2px 10px;
                font-size: 8pt;
                font-weight: bold;
            }
            QPushButton:hover {
                background: #7a5c1e;
                color: white;
            }
            QPushButton:pressed {
                background: #5a3e0e;
            }
        """)
        self._btn_clear_all_filters.clicked.connect(self._clear_all_filters)
        filter_row.addWidget(self._btn_clear_all_filters)

        self._lbl_count = QLabel("0 events")
        self._lbl_count.setObjectName("countLabel")
        self._lbl_count.setMinimumWidth(100)
        self._lbl_count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        filter_row.addWidget(self._lbl_count)
        layout.addLayout(filter_row)

        # ── Tactic filter indicator (hidden until a tactic filter is active) ─
        self._tactic_filter_widget = QWidget()
        tactic_ind_row = QHBoxLayout(self._tactic_filter_widget)
        tactic_ind_row.setContentsMargins(2, 0, 2, 0)
        tactic_ind_row.setSpacing(6)

        self._lbl_tactic_active = QLabel()
        self._lbl_tactic_active.setStyleSheet(
            "color:#7a4c00; font-size:8pt; font-weight:bold; padding:1px 4px;"
        )
        self._btn_clear_tactic = QPushButton("✕  Clear Tactic Filter")
        self._btn_clear_tactic.setMaximumHeight(22)
        self._btn_clear_tactic.setStyleSheet(
            "QPushButton{font-size:8pt; padding:0 6px;}"
        )
        self._btn_clear_tactic.clicked.connect(self._clear_tactic_filter)

        tactic_ind_row.addWidget(self._lbl_tactic_active)
        tactic_ind_row.addStretch()
        tactic_ind_row.addWidget(self._btn_clear_tactic)
        layout.addWidget(self._tactic_filter_widget)
        self._tactic_filter_widget.setVisible(False)

        # ── Quick Filter indicator (hidden until a quick filter is applied) ──
        self._quick_filter_widget = QWidget()
        qf_row = QHBoxLayout(self._quick_filter_widget)
        qf_row.setContentsMargins(2, 0, 2, 0)
        qf_row.setSpacing(6)

        self._btn_clear_quick = QPushButton("✕  Clear Quick Filters")
        self._btn_clear_quick.setMaximumHeight(22)
        self._btn_clear_quick.setStyleSheet(
            "QPushButton{font-size:8pt; padding:0 6px;}"
        )
        self._btn_clear_quick.clicked.connect(self._clear_quick_filters)

        qf_row.addStretch()
        qf_row.addWidget(self._btn_clear_quick)
        layout.addWidget(self._quick_filter_widget)
        self._quick_filter_widget.setVisible(False)

        # ── Session filter indicator (hidden until a session filter is active) ─
        self._session_filter_widget = QWidget()
        sf_row = QHBoxLayout(self._session_filter_widget)
        sf_row.setContentsMargins(2, 0, 2, 0)
        sf_row.setSpacing(6)

        self._lbl_session_filter = QLabel()
        self._lbl_session_filter.setStyleSheet(
            "color:#7a3a00; font-size:8pt; font-weight:bold; padding:1px 4px;"
        )
        self._btn_clear_session = QPushButton("✕  Clear Session Filter")
        self._btn_clear_session.setMaximumHeight(22)
        self._btn_clear_session.setStyleSheet(
            "QPushButton{font-size:8pt; padding:0 6px;}"
        )
        self._btn_clear_session.clicked.connect(self._clear_session_filter)

        sf_row.addWidget(self._lbl_session_filter)
        sf_row.addStretch()
        sf_row.addWidget(self._btn_clear_session)
        layout.addWidget(self._session_filter_widget)
        self._session_filter_widget.setVisible(False)

        # ── Merged-mode table (always exists) ────────────────────────────
        self._event_model  = EventTableModel()
        self._proxy_model  = EventFilterProxyModel()
        self._proxy_model.setSourceModel(self._event_model)

        self._table = self._create_configured_table(self._proxy_model)

        # ── File tree panel (left side, hidden until separate mode) ────
        self._file_tree_panel = QWidget()
        self._file_tree_panel.setMinimumWidth(120)
        tree_layout = QVBoxLayout(self._file_tree_panel)
        tree_layout.setContentsMargins(0, 0, 0, 0)
        tree_layout.setSpacing(0)

        tree_hdr_row = QHBoxLayout()
        tree_hdr_row.setContentsMargins(6, 4, 4, 4)
        lbl_tree = QLabel("FILES")
        lbl_tree.setStyleSheet(
            f"color:{COLORS['text_dim']}; font-size:7pt; font-weight:bold; letter-spacing:1px;"
        )
        tree_hdr_row.addWidget(lbl_tree)
        tree_hdr_row.addStretch()
        tree_layout.addLayout(tree_hdr_row)

        self._file_tree = QTreeWidget()
        self._file_tree.setObjectName("fileTree")
        self._file_tree.setHeaderHidden(True)
        self._file_tree.setColumnCount(1)
        self._file_tree.setRootIsDecorated(False)
        self._file_tree.setIndentation(8)
        self._file_tree.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._file_tree.header().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._file_tree.itemClicked.connect(self._on_tree_item_clicked)
        self._file_tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._file_tree.customContextMenuRequested.connect(self._on_tree_context_menu)
        self._file_tree.setStyleSheet(f"""
            QTreeWidget {{
                background: {COLORS['bg_main']};
                border: none;
                border-right: 1px solid {COLORS['border']};
            }}
            QTreeWidget::item {{
                padding: 4px 8px;
            }}
            QTreeWidget::item:selected {{
                background: {COLORS.get('selected_bg', '#ddd4bc')};
                color: {COLORS.get('text', '#1e1a14')};
            }}
            QTreeWidget::item:hover {{
                background: {COLORS.get('bg_hover', '#1c2130')};
            }}
        """)
        tree_layout.addWidget(self._file_tree)
        self._file_tree_panel.setVisible(False)  # hidden in merged mode

        # ── Tab widget for events (holds merged table or per-file tabs) ─
        self._events_tab_widget = _EventsTabWidget()
        self._events_tab_widget.setBarCollapsed(True)   # merged mode: no tab bar gap
        self._events_tab_widget.setTabsClosable(True)
        self._events_tab_widget.setMovable(True)
        self._events_tab_widget.tabCloseRequested.connect(self._on_file_tab_close_requested)
        self._events_tab_widget.currentChanged.connect(self._on_file_tab_changed)

        # Add merged table as default tab (not closeable)
        self._events_tab_widget.addTab(self._table, "All Events")
        # Remove close button from the "All Events" tab
        self._events_tab_widget.tabBar().setTabButton(0, self._events_tab_widget.tabBar().ButtonPosition.RightSide, None)

        # ── Splitter: tree panel (left) + tab widget (right) ──────────
        self._events_content_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._events_content_splitter.setChildrenCollapsible(False)
        self._events_content_splitter.addWidget(self._file_tree_panel)
        self._events_content_splitter.addWidget(self._events_tab_widget)
        self._events_content_splitter.setSizes([0, 1])  # tree hidden initially
        # A horizontal QSplitter has vertical size-policy=Preferred by default,
        # which means it does NOT absorb extra vertical space from the parent
        # VBoxLayout.  When the right_splitter gives this panel more height,
        # the leftover space is distributed to other items (including the filter
        # bar), making it grow and center its content with gaps above/below.
        # Setting Expanding + stretch=1 ensures the splitter always claims all
        # spare vertical space, keeping the filter bar at its natural height.
        self._events_content_splitter.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self._events_content_splitter, 1)  # stretch=1: absorbs all extra height

        # ── Tree toggle button (in filter bar, left of adv filter) ────
        self._btn_tree_toggle = QPushButton("🗂")
        self._btn_tree_toggle.setToolTip("Toggle file tree (separate mode only)")
        self._btn_tree_toggle.setMaximumSize(28, 24)
        self._btn_tree_toggle.setStyleSheet(f"""
            QPushButton {{
                background: {COLORS['bg_header']};
                color: {COLORS['text_dim']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                font-size: 9pt;
                padding: 0;
            }}
            QPushButton:hover {{ background: {COLORS.get('accent', '#7a5c1e')}; color: white; }}
            QPushButton:checked {{ background: {COLORS.get('accent', '#7a5c1e')}; color: white; }}
        """)
        self._btn_tree_toggle.setCheckable(True)
        self._btn_tree_toggle.setChecked(False)
        self._btn_tree_toggle.setEnabled(False)  # disabled until separate mode
        self._btn_tree_toggle.clicked.connect(self._toggle_file_tree)
        # Insert into filter_row (before adv filter button)
        filter_row.insertWidget(0, self._btn_tree_toggle)

        return w

    # ── Table factory (reused for merged + per-file tabs) ─────────────

    def _create_configured_table(self, proxy: EventFilterProxyModel) -> QTableView:
        """Create and configure a QTableView with standard settings."""
        table = QTableView()
        table.setModel(proxy)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        
        # Fixed row height is enforced via setDefaultSectionSize(22) +
        # setSectionResizeMode(Fixed) below — no per-row query needed.
        # (setUniformRowHeights is QTreeView-only, not available on QTableView.)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(22)
        table.verticalHeader().setMinimumSectionSize(22)
        table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(self._on_table_context_menu)

        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hdr.setStretchLastSection(False)
        hdr.setSectionsClickable(True)
        hdr.sectionClicked.connect(self._on_col_header_clicked)

        # ── Header right-click: context menu ──────────────────────────────
        hdr.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        hdr.customContextMenuRequested.connect(
            lambda pos, tbl=table: self._on_header_context_menu(pos, tbl)
        )

        hdr.setSortIndicatorShown(False)

        # ── Default column widths for all 20 columns ──────────────────────
        col_widths = {
            0: 40,   # #
            1: 70,   # Event ID
            2: 90,   # Level
            3: 170,  # Timestamp
            4: 130,  # Computer
            5: 150,  # Channel
            6: 110,  # User
            7: 80,   # ATT&CK
            8: 130,  # Source File
            9: 110,  # Keywords
            10: 100, # Operational Code
            11: 130, # Log
            12: 75,  # Process ID
            13: 75,  # Thread ID
            14: 80,  # Processor ID
            15: 75,  # Session ID
            16: 80,  # Kernel Time
            17: 80,  # User Time
            18: 90,  # Processor Time
            19: 120, # Correlation Id
            20: 90,  # Record ID
        }
        for i, w_val in col_widths.items():
            table.setColumnWidth(i, w_val)

        # Apply current column visibility
        self._apply_col_visibility(table, self._visible_cols)

        return table

    # =========================================================================
    # BOTTOM PANEL (detail + analysis tabs)
    # =========================================================================

    def _build_bottom_panel(self) -> QWidget:
        bottom_split = QSplitter(Qt.Orientation.Horizontal)
        bottom_split.setChildrenCollapsible(False)

        # Event detail (left half of bottom)
        detail_widget = self._build_detail_widget()
        # Analysis tabs (right half of bottom)
        analysis_widget = self._build_analysis_tabs()

        bottom_split.addWidget(detail_widget)
        bottom_split.addWidget(analysis_widget)
        bottom_split.setSizes([550, 550])
        return bottom_split

    def _build_detail_widget(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(28)
        header.setStyleSheet(f"background:{COLORS['bg_header']};border-bottom:1px solid {COLORS['border']};")
        hdr_layout = QHBoxLayout(header)
        hdr_layout.setContentsMargins(8, 0, 8, 0)
        lbl = QLabel("EVENT DETAIL")
        lbl.setObjectName("sectionHeader")
        lbl.setStyleSheet("color:#9a8878;font-size:8pt;font-weight:bold;letter-spacing:1px;border:none;")
        # Brief / Full toggle
        self._btn_detail_mode = QPushButton("Brief")
        self._btn_detail_mode.setMaximumHeight(22)
        self._btn_detail_mode.setCheckable(True)
        self._btn_detail_mode.setChecked(False)   # Full mode is default (not "Brief")
        self._btn_detail_mode.setToolTip(
            "Toggle between Full detail (all fields) and Brief (header only)"
        )
        self._btn_detail_mode.setStyleSheet(
            "QPushButton { background:#e4ddd3; color:#5a4e42; border:1px solid #c4bba8;"
            " border-radius:3px; padding:1px 8px; font-size:8pt; }"
            "QPushButton:checked { background:#ddd4bc; color:#7a5c1e; border-color:#7a5c1e; }"
            "QPushButton:hover { color:#1e1a14; }"
        )
        self._btn_detail_mode.toggled.connect(self._on_detail_mode_toggled)

        # Bookmark toggle button — disabled until an event is selected
        self._btn_bookmark_event = QPushButton("☆ Bookmark")
        self._btn_bookmark_event.setMaximumHeight(22)
        self._btn_bookmark_event.setCheckable(True)
        self._btn_bookmark_event.setEnabled(False)
        self._btn_bookmark_event.setToolTip("Bookmark this event for quick reference (Bookmarks tab)")
        self._btn_bookmark_event.setStyleSheet(
            "QPushButton { background:#e4ddd3; color:#5a4e42; border:1px solid #c4bba8;"
            " border-radius:3px; padding:1px 8px; font-size:8pt; }"
            "QPushButton:checked { background:#e8dcc8; color:#7a5c1e; border-color:#c4a535; }"
            "QPushButton:hover { color:#1e1a14; }"
        )
        self._btn_bookmark_event.clicked.connect(self._on_bookmark_toggle)

        hdr_layout.addWidget(lbl)
        hdr_layout.addStretch()
        hdr_layout.addWidget(self._btn_bookmark_event)
        hdr_layout.addWidget(self._btn_detail_mode)
        layout.addWidget(header)

        self._detail_browser = QTextBrowser()
        self._detail_browser.setOpenLinks(False)
        layout.addWidget(self._detail_browser)
        return w

    def _build_analysis_tabs(self) -> QWidget:
        # Wrapper so we can add a scope toggle above the tabs
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        # ── Analysis scope row (hidden until separate mode) ───────────────
        self._scope_row_widget = QWidget()
        self._scope_row_widget.setFixedHeight(28)
        self._scope_row_widget.setStyleSheet(
            f"background:{COLORS['bg_header']};"
            f"border-bottom:1px solid {COLORS['border']};"
        )
        scope_row = QHBoxLayout(self._scope_row_widget)
        scope_row.setContentsMargins(8, 0, 8, 0)
        scope_row.setSpacing(8)

        lbl_scope = QLabel("Analysis:")
        lbl_scope.setStyleSheet(
            f"color:{COLORS['text_dim']}; font-size:8pt; background:transparent; border:none;"
        )
        scope_row.addWidget(lbl_scope)

        self._cmb_analysis_scope = QComboBox()
        self._cmb_analysis_scope.addItems(["This File", "All Files"])
        self._cmb_analysis_scope.setMaximumWidth(110)
        self._cmb_analysis_scope.setFixedHeight(20)
        self._cmb_analysis_scope.setToolTip(
            "This File — show analysis for the currently active file tab\n"
            "All Files — show analysis for all parsed events combined"
        )
        self._cmb_analysis_scope.currentTextChanged.connect(self._on_analysis_scope_changed)
        scope_row.addWidget(self._cmb_analysis_scope)
        scope_row.addStretch()

        self._scope_row_widget.setVisible(False)  # shown only in separate mode
        wrapper_layout.addWidget(self._scope_row_widget)

        # ── Main analysis tab widget ──────────────────────────────────────
        self._analysis_tabs = QTabWidget()

        # ATT&CK tab
        self._tab_attack = self._build_attack_tab()
        self._analysis_tabs.addTab(self._tab_attack, "ATT&CK")

        # IOCs tab
        self._tab_iocs = self._build_iocs_tab()
        self._analysis_tabs.addTab(self._tab_iocs, "IOCs")

        # Chains tab
        self._tab_chains = self._build_chains_tab()
        self._analysis_tabs.addTab(self._tab_chains, "Chains")

        # Bookmarks tab
        self._tab_bookmarks = self._build_bookmarks_tab()
        self._analysis_tabs.addTab(self._tab_bookmarks, "Bookmarks")

        wrapper_layout.addWidget(self._analysis_tabs)
        return wrapper

    def _build_attack_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        self._lbl_attack_summary = QLabel("No ATT&CK data — run with ATT&CK Mapping enabled.")
        self._lbl_attack_summary.setObjectName("statsLabel")
        layout.addWidget(self._lbl_attack_summary)

        self._tbl_attack = QTableWidget(0, 4)
        self._tbl_attack.setHorizontalHeaderLabels(["Tactic", "Events", "Top Technique", "TID"])
        self._tbl_attack.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tbl_attack.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        _atk_hdr = self._tbl_attack.horizontalHeader()
        _atk_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)  # all cols user-draggable
        _atk_hdr.setStretchLastSection(False)
        self._tbl_attack.setColumnWidth(0, 160)  # Tactic
        self._tbl_attack.setColumnWidth(1, 65)   # Events
        self._tbl_attack.setColumnWidth(2, 200)  # Top Technique
        self._tbl_attack.setColumnWidth(3, 90)   # TID
        self._tbl_attack.verticalHeader().setVisible(False)
        self._tbl_attack.setShowGrid(False)
        self._tbl_attack.setAlternatingRowColors(True)

        # Left-click → context menu (or clear if same tactic already filtered)
        self._tbl_attack.cellClicked.connect(self._on_attack_row_clicked)
        # Right-click → same context menu
        self._tbl_attack.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tbl_attack.customContextMenuRequested.connect(
            self._on_attack_context_menu_requested
        )

        layout.addWidget(self._tbl_attack)
        return w

    def _build_iocs_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Header row: summary label + buttons
        hdr = QHBoxLayout()
        self._lbl_ioc_summary = QLabel("No IOC data — run with IOC Extraction enabled.")
        self._lbl_ioc_summary.setObjectName("statsLabel")
        hdr.addWidget(self._lbl_ioc_summary)
        hdr.addStretch()

        self._btn_threat_intel = QPushButton("🔍  Threat Intel")
        self._btn_threat_intel.setObjectName("exportBtn")
        self._btn_threat_intel.setToolTip(
            "Check IOC values against offline known-bad lists or VirusTotal API.\n"
            "Supports CSV, TXT, STIX 2.1 JSON (offline) and VT API v3 (online).\n"
            "Free VT tier: 4 req/min · 500 req/day."
        )
        self._btn_threat_intel.setEnabled(False)
        self._btn_threat_intel.clicked.connect(self._on_threat_intel_clicked)
        hdr.addWidget(self._btn_threat_intel)

        self._btn_export_iocs = QPushButton("⬇  Export IOCs")
        self._btn_export_iocs.setObjectName("exportBtn")
        self._btn_export_iocs.setToolTip(
            "Save extracted IOC values to CSV, TXT, STIX 2.1, MISP, YARA, or clipboard.\n"
            "Right-click any row in the tables below to copy individual values."
        )
        self._btn_export_iocs.setEnabled(False)
        self._btn_export_iocs.clicked.connect(self._on_export_iocs_clicked)
        hdr.addWidget(self._btn_export_iocs)
        layout.addLayout(hdr)

        self._ioc_tabs = QTabWidget()
        layout.addWidget(self._ioc_tabs)
        return w

    def _build_chains_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(4, 4, 4, 4)

        self._lbl_chains_summary = QLabel("No correlation data — run with Correlation Engine enabled.")
        self._lbl_chains_summary.setObjectName("statsLabel")
        layout.addWidget(self._lbl_chains_summary)

        self._tree_chains = QTreeWidget()
        self._tree_chains.setColumnCount(5)
        self._tree_chains.setHeaderLabels(["Severity", "Rule", "Computers", "Events", "First Seen"])
        self._tree_chains.setAlternatingRowColors(True)
        self._tree_chains.setRootIsDecorated(True)
        _ch_hdr = self._tree_chains.header()
        _ch_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        _ch_hdr.setStretchLastSection(False)
        for _ci, _cw in enumerate([80, 260, 110, 65, 140]):
            self._tree_chains.setColumnWidth(_ci, _cw)
        # Allow the user to Ctrl/Shift-click multiple chains, then right-click → new tab
        self._tree_chains.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._tree_chains.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree_chains.customContextMenuRequested.connect(self._on_chains_context_menu)
        self._tree_chains.itemDoubleClicked.connect(self._on_chain_double_click)
        layout.addWidget(self._tree_chains)
        return w

    # =========================================================================
    # STATUS BAR
    # =========================================================================

    def _build_status_bar(self) -> None:
        sb = QStatusBar()
        self._lbl_status       = QLabel("Ready")
        self._lbl_status_files = QLabel("")
        self._lbl_status_stats = QLabel("")
        self._lbl_analysis_progress = QLabel("")
        self._lbl_analysis_progress.setStyleSheet(
            "font-size: 11px; color: #8cf; padding-right: 10px;"
        )
        self._lbl_analysis_progress.setVisible(False)
        self._component_pcts: dict[str, int] = {}
        sb.addWidget(self._lbl_status)
        sb.addPermanentWidget(self._lbl_analysis_progress)
        sb.addPermanentWidget(self._lbl_status_stats)
        sb.addPermanentWidget(self._lbl_status_files)
        self.setStatusBar(sb)

    def _set_status(self, text: str, files: str = "", stats: str = "") -> None:
        self._lbl_status.setText(text)
        self._lbl_status_files.setText(files)
        self._lbl_status_stats.setText(stats)

    # =========================================================================
    # SIGNAL CONNECTIONS
    # =========================================================================

    def _connect_signals(self) -> None:
        self._btn_parse.clicked.connect(self._on_parse_clicked)
        self._btn_stop.clicked.connect(self._on_stop_clicked)
        self._btn_export.clicked.connect(self._on_export_clicked)

        # Table selection → detail panel
        self._table.selectionModel().selectionChanged.connect(self._on_row_selected)

    # =========================================================================
    # ACTIVE TAB INDIRECTION (merged vs per-file)
    # =========================================================================

    @property
    def _active_model(self) -> EventTableModel:
        if self._active_file_tab:
            state = self._file_tabs.get(self._active_file_tab)
            if state:
                return state.model
        return self._event_model

    @property
    def _active_proxy(self) -> EventFilterProxyModel:
        if self._active_file_tab:
            state = self._file_tabs.get(self._active_file_tab)
            if state:
                return state.proxy
        return self._proxy_model

    @property
    def _active_table(self) -> QTableView:
        if self._active_file_tab:
            state = self._file_tabs.get(self._active_file_tab)
            if state:
                return state.table
        return self._table

    @property
    def _active_events(self) -> list[dict]:
        if self._active_file_tab:
            state = self._file_tabs.get(self._active_file_tab)
            if state:
                return state.events
        return self._events

    # =========================================================================
    # FILE TREE + TAB MANAGEMENT
    # =========================================================================

    def _toggle_file_tree(self) -> None:
        """Show/hide the file tree panel."""
        visible = self._btn_tree_toggle.isChecked()
        self._file_tree_panel.setVisible(visible)
        if visible:
            self._events_content_splitter.setSizes([180, 800])
        else:
            self._events_content_splitter.setSizes([0, 1])

    def _on_tree_item_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Click on file tree item → open or switch to that file's tab."""
        filepath = item.data(0, Qt.ItemDataRole.UserRole)
        if not filepath:
            return
        if filepath == "__all_events__":
            self._open_all_events_tab()
            return
        if filepath in self._file_tabs:
            # Tab exists — switch to it
            state = self._file_tabs[filepath]
            idx = self._events_tab_widget.indexOf(state.table)
            if idx >= 0:
                self._events_tab_widget.setCurrentIndex(idx)
        elif self._hw_model is not None and filepath in getattr(self, "_jm_pending", {}):
            # Juggernaut separate mode — create tab on demand
            self._open_jm_file_tab(filepath)
        else:
            # Normal mode — create tab from per-file data
            self._create_file_tab(filepath)

    def _open_jm_file_tab(self, filepath: str) -> None:
        """Create and open a per-file tab in Juggernaut separate-tabs mode."""
        from evtx_tool.gui.heavyweight_model import ArrowTableModel

        pending = getattr(self, "_jm_pending", {})
        arrow_table = pending.get(filepath)
        if arrow_table is None or self._hw_model is None:
            return

        parquet_dir  = self._hw_db_path or ""
        display_name = os.path.basename(filepath)

        # Pass the shared full arrow_table with a fixed source_file filter rather
        # than materialising a filtered copy — saves one copy of per-file rows.
        file_model = ArrowTableModel(
            arrow_table,
            parquet_dir=parquet_dir,
            fixed_where="source_file = ?",
            fixed_params=[filepath],
            parent=self,
        )
        self._jm_file_models.append(file_model)

        file_view = self._create_configured_table(file_model)
        file_view.horizontalHeader().setSortIndicatorShown(False)
        self._apply_col_visibility(file_view, self._visible_cols)
        file_view.selectionModel().selectionChanged.connect(self._on_hw_row_selected)
        file_model.busy_started.connect(self._on_hw_filter_busy_started)
        file_model.busy_finished.connect(self._on_hw_filter_busy_finished)

        tab_idx = self._events_tab_widget.addTab(file_view, display_name)
        self._events_tab_widget.setTabToolTip(tab_idx, filepath)

        # Close button
        _btn_x = QPushButton("×")
        _btn_x.setFixedSize(16, 16)
        _btn_x.setStyleSheet(
            "QPushButton{color:#7a5c1e;font-size:12pt;font-weight:bold;"
            "border:none;background:transparent;padding:0;margin:0;}"
            "QPushButton:hover{color:#a01800;background:#f5e0dc;border-radius:2px;}"
        )
        _btn_x.clicked.connect(
            lambda _=False, t=file_view: self._on_file_tab_close_requested(
                self._events_tab_widget.indexOf(t)
            )
        )
        self._events_tab_widget.tabBar().setTabButton(
            tab_idx,
            self._events_tab_widget.tabBar().ButtonPosition.RightSide,
            _btn_x,
        )

        shim = _JMProxyShim(file_model)
        self._file_tabs[filepath] = FileTabState(
            filepath=filepath,
            display_name=display_name,
            events=[],
            search_cache=[],
            model=file_model,
            proxy=shim,
            table=file_view,
        )

        self._update_tree_item_style(filepath, is_open=True)
        self._events_tab_widget.setCurrentIndex(tab_idx)

    def _on_tree_context_menu(self, pos) -> None:
        """Right-click context menu on file tree items."""
        item = self._file_tree.itemAt(pos)
        if not item:
            return
        filepath = item.data(0, Qt.ItemDataRole.UserRole)
        if not filepath:
            return

        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)

        if filepath == "__all_events__":
            if self._events_tab_widget.isTabVisible(0):
                act = menu.addAction("Close Tab")
                act.triggered.connect(lambda: self._on_file_tab_close_requested(0))
            else:
                act = menu.addAction("Open All Events")
                act.triggered.connect(self._open_all_events_tab)
            menu.exec(self._file_tree.viewport().mapToGlobal(pos))
            return
        if filepath.startswith("__chain__"):
            # Chain-events tab: only allow closing it (no real file to remove)
            act_close = menu.addAction("Close Chain Tab")
            act_close.triggered.connect(lambda: self._close_file_tab(filepath))
        elif filepath in self._file_tabs:
            act_close = menu.addAction("Close Tab")
            act_close.triggered.connect(lambda: self._close_file_tab(filepath))
            menu.addSeparator()
            act_remove = menu.addAction("Remove File")
            act_remove.triggered.connect(lambda: self._remove_loaded_file(filepath))
        else:
            act_open = menu.addAction("Open in Tab")
            act_open.triggered.connect(lambda: self._create_file_tab(filepath))
            menu.addSeparator()
            act_remove = menu.addAction("Remove File")
            act_remove.triggered.connect(lambda: self._remove_loaded_file(filepath))

        menu.exec(self._file_tree.viewport().mapToGlobal(pos))

    def _create_file_tab(self, filepath: str) -> FileTabState | None:
        """Create a new tab for a specific file's events."""
        if filepath not in self._per_file_data:
            return None
        if filepath in self._file_tabs:
            # Already open — just switch to it
            state = self._file_tabs[filepath]
            idx = self._events_tab_widget.indexOf(state.table)
            if idx >= 0:
                self._events_tab_widget.setCurrentIndex(idx)
            return state

        data = self._per_file_data[filepath]
        events = data["events"]
        cache = data["search_cache"]

        model = EventTableModel()
        proxy = EventFilterProxyModel()
        proxy.setSourceModel(model)

        table = self._create_configured_table(proxy)

        # Load data with detach/re-attach optimization
        table.setUpdatesEnabled(False)
        table.setSortingEnabled(False)
        proxy.setDynamicSortFilter(False)
        table.setModel(None)

        model.set_events(events, search_cache=cache)

        proxy.setDynamicSortFilter(False)
        table.setModel(proxy)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.selectionModel().selectionChanged.connect(self._on_row_selected)

        # Column widths + visibility already applied by _create_configured_table.
        # Re-apply visibility after model re-attach (setModel(None) above resets hidden state).
        self._apply_col_visibility(table, self._visible_cols)

        proxy.setDynamicSortFilter(True)
        table.setUpdatesEnabled(True)

        display_name = os.path.basename(filepath)
        tab_idx = self._events_tab_widget.addTab(table, display_name)
        self._events_tab_widget.setTabToolTip(tab_idx, filepath)

        # Brown × close button (replaces Qt's default platform close button)
        _btn_close = QPushButton("×")
        _btn_close.setFixedSize(16, 16)
        _btn_close.setStyleSheet(
            "QPushButton { color: #7a5c1e; font-size: 12pt; font-weight: bold;"
            " border: none; background: transparent; padding: 0; margin: 0; }"
            "QPushButton:hover { color: #a01800; background: #f5e0dc; border-radius: 2px; }"
        )
        _btn_close.clicked.connect(
            lambda _=False, t=table: self._on_file_tab_close_requested(
                self._events_tab_widget.indexOf(t)
            )
        )
        self._events_tab_widget.tabBar().setTabButton(
            tab_idx,
            self._events_tab_widget.tabBar().ButtonPosition.RightSide,
            _btn_close,
        )

        state = FileTabState(
            filepath=filepath,
            display_name=display_name,
            events=events,
            search_cache=cache,
            model=model,
            proxy=proxy,
            table=table,
        )
        self._file_tabs[filepath] = state

        # Bold the tree item
        self._update_tree_item_style(filepath, is_open=True)

        # Switch to the new tab
        self._events_tab_widget.setCurrentIndex(tab_idx)
        return state

    def _close_file_tab(self, filepath: str) -> None:
        """Close a file tab by filepath (works for both real-file tabs and chain tabs)."""
        state = self._file_tabs.get(filepath)
        if not state:
            return
        idx = self._events_tab_widget.indexOf(state.table)
        if idx >= 0:
            self._events_tab_widget.removeTab(idx)
        # Free model resources
        state.proxy.setSourceModel(None)
        state.model.set_events([])
        del self._file_tabs[filepath]

        if filepath.startswith("__chain__"):
            # Remove the chain's entry from the file tree
            root = self._file_tree.invisibleRootItem()
            for i in range(root.childCount()):
                _ti = root.child(i)
                if _ti and _ti.data(0, Qt.ItemDataRole.UserRole) == filepath:
                    root.removeChild(_ti)
                    break

            # In merged mode: if no chain tabs remain, restore the collapsed state
            if self._view_mode != "separate":
                _remaining = [k for k in self._file_tabs if k.startswith("__chain__")]
                if not _remaining:
                    self._events_tab_widget.setBarCollapsed(True)
                    self._file_tree_panel.setVisible(False)
                    self._btn_tree_toggle.setEnabled(False)
                    self._btn_tree_toggle.setChecked(False)
                    self._events_content_splitter.setSizes([0, 1])
        else:
            self._update_tree_item_style(filepath, is_open=False)

    def _on_file_tab_close_requested(self, index: int) -> None:
        """Handle tab close button click."""
        widget = self._events_tab_widget.widget(index)
        if widget is self._table:
            # In separate mode the All Events tab is closeable (hide, not destroy)
            if self._view_mode == "separate":
                self._events_tab_widget.setTabVisible(0, False)
                self._update_tree_item_style("__all_events__", is_open=False)
            return
        for fp, state in list(self._file_tabs.items()):
            if state.table is widget:
                self._close_file_tab(fp)
                return

    def _on_file_tab_changed(self, index: int) -> None:
        """Handle switching between file tabs."""
        if index < 0:
            return
        widget = self._events_tab_widget.widget(index)
        if widget is None:
            return

        # Determine which file this tab belongs to
        old_active = self._active_file_tab
        if widget is self._table:
            self._active_file_tab = None
        else:
            for fp, state in self._file_tabs.items():
                if state.table is widget:
                    self._active_file_tab = fp
                    break
            else:
                self._active_file_tab = None

        self._update_count_label()
        # Bug 6 fix: refresh header ▼ indicators to match the newly active tab.
        # Guard with _table (plain attribute) — _active_table is a property that
        # always exists, so hasattr on it would never be False.
        if hasattr(self, "_table"):
            self._update_header_indicators()
        # _detail_browser is built in _build_bottom_panel(), which runs after
        # _build_events_panel().  The first addTab() fires currentChanged(0)
        # before _detail_browser exists, so guard against that.
        if hasattr(self, "_detail_browser"):
            self._detail_browser.clear()
            self._last_detail_key = None  # invalidate render cache on tab switch

        # Bug 12 fix: ATT&CK refresh only relevant in normal mode (not JM)
        if self._view_mode == "separate" and self._hw_model is None:
            QTimer.singleShot(0, self._refresh_attack_tab)

    def _remove_loaded_file(self, filepath: str) -> None:
        """Remove a file completely — close tab + free memory."""
        self._close_file_tab(filepath)
        self._per_file_data.pop(filepath, None)
        # Remove from tree
        root = self._file_tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item and item.data(0, Qt.ItemDataRole.UserRole) == filepath:
                root.removeChild(item)
                break

    def _update_tree_item_style(self, filepath: str, is_open: bool) -> None:
        """Bold tree items that have an open tab."""
        root = self._file_tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            if item and item.data(0, Qt.ItemDataRole.UserRole) == filepath:
                f = item.font(0)
                f.setBold(is_open)
                item.setFont(0, f)
                break

    def _attach_all_events_close_btn(self) -> None:
        """Attach a close button to the All Events tab (index 0) for separate mode."""
        bar = self._events_tab_widget.tabBar()
        # Remove any existing button first to avoid duplicates on re-parse
        existing = bar.tabButton(0, bar.ButtonPosition.RightSide)
        if existing is not None:
            existing.deleteLater()
        btn = QPushButton("×")
        btn.setFixedSize(16, 16)
        btn.setStyleSheet(
            "QPushButton { color: #7a5c1e; font-size: 12pt; font-weight: bold;"
            " border: none; background: transparent; padding: 0; margin: 0; }"
            "QPushButton:hover { color: #a01800; background: #f5e0dc; border-radius: 2px; }"
        )
        btn.clicked.connect(lambda: self._on_file_tab_close_requested(0))
        bar.setTabButton(0, bar.ButtonPosition.RightSide, btn)

    def _open_all_events_tab(self) -> None:
        """Show the All Events tab (restoring it if previously closed)."""
        self._events_tab_widget.setTabVisible(0, True)
        self._attach_all_events_close_btn()
        self._events_tab_widget.setCurrentIndex(0)
        self._active_file_tab = None
        self._update_tree_item_style("__all_events__", is_open=True)

    def _populate_file_tree(self) -> None:
        """Fill the file tree with loaded file names."""
        self._file_tree.clear()
        # "All Events" entry at top so user can reopen the merged tab
        all_item = QTreeWidgetItem(["All Events"])
        all_item.setData(0, Qt.ItemDataRole.UserRole, "__all_events__")
        all_item.setToolTip(0, "View all events from all files combined")
        f = all_item.font(0)
        f.setBold(True)
        all_item.setFont(0, f)
        self._file_tree.addTopLevelItem(all_item)
        for filepath in sorted(self._per_file_data.keys()):
            item = QTreeWidgetItem([os.path.basename(filepath)])
            item.setData(0, Qt.ItemDataRole.UserRole, filepath)
            item.setToolTip(0, filepath)
            self._file_tree.addTopLevelItem(item)

    # =========================================================================
    # FILE MANAGEMENT
    # =========================================================================

    def _add_path(self, path: str) -> None:
        """Add a single path to the file list widget (dedup)."""
        existing = [self._file_list.item(i).data(Qt.ItemDataRole.UserRole)
                    for i in range(self._file_list.count())]
        if path in existing:
            return
        item = QListWidgetItem(os.path.basename(path) if os.path.isfile(path) else path)
        item.setData(Qt.ItemDataRole.UserRole, path)
        item.setToolTip(path)
        self._file_list.addItem(item)
        self._act_ps_extract.setEnabled(True)

    def _on_add_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Select EVTX Files", "", "EVTX Files (*.evtx);;All Files (*)"
        )
        for p in paths:
            self._add_path(p)

    def _on_add_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select Directory containing EVTX files")
        if d:
            self._add_path(d)

    def _collect_files(self) -> list[str]:
        """Recursively collect .evtx files from all entries in the file list."""
        paths = [self._file_list.item(i).data(Qt.ItemDataRole.UserRole)
                 for i in range(self._file_list.count())]
        files: list[str] = []
        seen: set[str] = set()
        for p in paths:
            pp = Path(p)
            if pp.is_dir():
                for f in sorted(pp.rglob("*.evtx")):
                    s = str(f)
                    if s not in seen:
                        seen.add(s)
                        files.append(s)
            elif pp.is_file() and pp.suffix.lower() == ".evtx":
                s = str(pp)
                if s not in seen:
                    seen.add(s)
                    files.append(s)
        return files

    # ── Volume validation (Safety Gate) ──────────────────────────────────

    _RECOMMENDED_MAX_SIZE = 700 * 1024 ** 2  # 700 MB

    @staticmethod
    def _human_size(n: int) -> str:
        """Convert bytes to a human-readable string (e.g. '1.23 GB')."""
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(n) < 1024:
                return f"{n:.2f} {unit}" if unit != "B" else f"{n} B"
            n /= 1024  # type: ignore[assignment]
        return f"{n:.2f} PB"

    def _check_volume(self, files: list[str]) -> str:
        """
        Calculate total size of EVTX files and warn if over the limit.

        Returns
        -------
        'proceed'    – user accepted Normal Mode risk
        'juggernaut' – user chose Juggernaut Mode
        'cancel'     – user cancelled
        """
        import os
        total = sum(os.path.getsize(f) for f in files if os.path.isfile(f))
        if total <= self._RECOMMENDED_MAX_SIZE:
            return "proceed"

        human = self._human_size(total)
        msg = QMessageBox(self)
        msg.setWindowTitle("\u26a0  Large Data Volume Detected")
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setText(
            f"<b>Total size: {human}</b>  ({len(files)} files)<br><br>"
            f"This exceeds the recommended limit of "
            f"<b>{self._human_size(self._RECOMMENDED_MAX_SIZE)}</b> for "
            f"Normal Mode.<br><br>"
            f"Loading this much data in-memory may cause the tool to "
            f"<b>lag or crash</b>.<br><br>"
            f"<span style='color:#4fc3f7'>&#9889; <b>Juggernaut Mode</b></span> "
            f"processes large log sets without loading everything into RAM."
        )
        msg.setStyleSheet(
            "QLabel { font-size: 13px; } "
            "QPushButton { min-width: 140px; padding: 6px 14px; }"
        )
        btn_juggernaut = msg.addButton("\u26a1 Use Juggernaut Mode", QMessageBox.ButtonRole.ApplyRole)
        btn_proceed    = msg.addButton("Proceed Anyway",          QMessageBox.ButtonRole.AcceptRole)
        btn_cancel     = msg.addButton("Cancel",                   QMessageBox.ButtonRole.RejectRole)
        msg.setDefaultButton(btn_juggernaut)
        msg.exec()

        clicked = msg.clickedButton()
        if clicked == btn_juggernaut:
            return "juggernaut"
        if clicked == btn_proceed:
            return "proceed"
        return "cancel"

    # =========================================================================
    # JUGGERNAUT MODE (HEAVYWEIGHT)
    # =========================================================================

    _hw_worker  = None   # type: HeavyweightParseWorker | None
    _hw_model   = None   # type: HeavyweightTableModel  | None
    _hw_con     = None   # type: object | None  (sqlite3.Connection)
    _hw_db_path = None   # type: str | None  (path to SQLite session file)
    _hw_profile_signal_connected = False
    _hw_profile_filter_timer = None   # type: QTimer | None  (150ms debounce)
    _hw_profile_signal_cb    = None   # type: callable | None  (stored for disconnect)
    _hw_loading_dlg       = None   # type: QDialog | None  — "Please Wait" modal overlay
    _hw_loading_lbl       = None   # type: QLabel  | None  — detail line inside loading dlg
    _hw_loading_bar       = None   # type: QProgressBar | None  — progress bar inside loading dlg
    _hw_filter_busy_timer = None   # type: QTimer | None  — delays overlay so fast ops don't flash

    # ── Juggernaut loading overlay ────────────────────────────────────────────────

    def _show_hw_loading_dialog(
        self,
        heading: str = "Please Wait — Loading Events",
        detail: str = "Starting parse…",
    ) -> None:
        """Show a modal 'Please Wait' dialog that blocks the main window.

        The dialog has no close button and cannot be dismissed manually.
        Closed automatically by _close_hw_loading_dialog() when the operation
        completes (parse, filter, or sort).

        Parameters
        ----------
        heading : str
            Bold title line shown inside the dialog.
        detail : str
            Smaller subtitle; can be updated live via _hw_loading_lbl.
        """
        # Guard: only one dialog at a time
        if self._hw_loading_dlg is not None:
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("⚡  Juggernaut Mode")
        # Remove the close / minimise / maximise buttons entirely
        dlg.setWindowFlags(
            Qt.WindowType.Dialog |
            Qt.WindowType.CustomizeWindowHint |
            Qt.WindowType.WindowTitleHint
        )
        # Window-modal: blocks this window only (other open dialogs still work)
        dlg.setWindowModality(Qt.WindowModality.WindowModal)
        dlg.setFixedSize(440, 155)

        root = QVBoxLayout(dlg)
        root.setContentsMargins(28, 22, 28, 22)
        root.setSpacing(10)

        # ── Heading ───────────────────────────────────────────────────────────
        heading_lbl = QLabel(heading)
        hf = heading_lbl.font()
        hf.setPointSize(11)
        hf.setBold(True)
        heading_lbl.setFont(hf)
        heading_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(heading_lbl)

        # ── Detail line (updated live by callers) ─────────────────────────────
        detail_lbl = QLabel(detail)
        detail_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(detail_lbl)

        # ── Progress bar (indeterminate — marquee animation) ──────────────────
        bar = QProgressBar()
        bar.setRange(0, 0)
        bar.setTextVisible(False)
        bar.setFixedHeight(10)
        root.addWidget(bar)

        # ── Hint text ─────────────────────────────────────────────────────────
        hint = QLabel("The window will unlock automatically when done.")
        hnt_f = hint.font()
        hnt_f.setPointSize(8)
        hint.setFont(hnt_f)
        hint.setStyleSheet("color: gray;")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(hint)

        dlg.show()

        # Centre on the parent window
        parent_geo = self.frameGeometry()
        dlg.move(parent_geo.center() - dlg.rect().center())

        self._hw_loading_dlg = dlg
        self._hw_loading_lbl = detail_lbl
        self._hw_loading_bar = bar

    def _close_hw_loading_dialog(self) -> None:
        """Dismiss and destroy the 'Please Wait' loading dialog."""
        if self._hw_loading_dlg is not None:
            self._hw_loading_dlg.close()
            self._hw_loading_dlg.deleteLater()
            self._hw_loading_dlg = None
            self._hw_loading_lbl = None
            self._hw_loading_bar = None

    # ── Filter / sort busy overlay (Juggernaut mode only) ─────────────────────
    #
    # HeavyweightTableModel emits busy_started when _invalidate() or sort() is
    # called and busy_finished when the deferred COUNT(*) completes.
    #
    # A 150 ms delay timer prevents a flash for fast index-covered queries
    # (e.g. event_id filter with idx_event_id) while still showing the overlay
    # for slow INSTR text searches (200–500 ms on large datasets).

    @Slot()
    def _on_hw_filter_busy_started(self) -> None:
        """Model signalled that a filter/sort invalidation has started."""
        if self._hw_filter_busy_timer is None:
            self._hw_filter_busy_timer = QTimer(self)
            self._hw_filter_busy_timer.setSingleShot(True)
            self._hw_filter_busy_timer.timeout.connect(self._on_hw_filter_busy_show)
        # (Re-)start the delay; if busy_finished fires within 150 ms the timer
        # is cancelled and no dialog appears — zero visual disruption for fast ops.
        self._hw_filter_busy_timer.start(150)

    @Slot()
    def _on_hw_filter_busy_finished(self) -> None:
        """Model signalled that the filter/sort COUNT has completed."""
        if self._hw_filter_busy_timer is not None:
            self._hw_filter_busy_timer.stop()
        self._close_hw_loading_dialog()

    def _on_hw_filter_busy_show(self) -> None:
        """Called 150 ms after busy_started if the query is still running."""
        self._show_hw_loading_dialog(
            heading="Please Wait — Updating Results",
            detail="Querying events…",
        )

    def _launch_juggernaut_mode(self, files: list[str]) -> None:
        """Start Juggernaut Mode: parse via pyevtx-rs → SQLite."""
        from evtx_tool.gui.heavyweight_worker import HeavyweightParseWorker

        # Capture view mode NOW — the normal parse path sets this AFTER the
        # juggernaut branch so it would always stay "merged" without this fix.
        self._view_mode = "separate" if self._radio_separate.isChecked() else "merged"

        # Cancel any running analysis from previous parse
        if self._analysis_runner is not None and self._analysis_runner.is_running():
            self._analysis_runner.request_stop()
            self._analysis_runner = None

        self._last_parsed_files = files   # needed by Hayabusa in JM mode

        self._clear_results()
        self._parse_start_ts = time.monotonic()
        self._progress_bar.setValue(0)
        self._btn_parse.setEnabled(False)
        self._btn_stop.setEnabled(True)

        # Build filter config from current UI state
        fc = self._build_filter_config() if hasattr(self, "_build_filter_config") else None

        self._hw_worker = HeavyweightParseWorker(
            files=files,
            filter_config=fc,
        )
        self._hw_worker.progress.connect(self._on_hw_progress)
        self._hw_worker.finished.connect(self._on_hw_finished)
        self._hw_worker.error.connect(self._on_parse_error)
        self._hw_worker.start()

        # Show the "Please Wait" overlay — disables the main window until
        # _on_hw_finished (or _on_parse_error) calls _close_hw_loading_dialog().
        self._show_hw_loading_dialog()

        self._set_status("Parsing (Juggernaut Mode)...")

    @Slot(int, int, int, float)
    def _on_hw_progress(self, done_files: int, total_files: int,
                        done_events: int, eps: float) -> None:
        """Update progress bar, status, and loading dialog during heavyweight parse."""
        if total_files > 0:
            pct = int(done_files / total_files * 100)
            self._progress_bar.setValue(pct)
        self._set_status(
            f"\u26a1 Juggernaut: {done_files}/{total_files} files",
            stats=f"{done_events:,} events  |  {eps:,.0f} rec/s",
        )
        # Keep the loading dialog's detail line in sync with parse progress
        if self._hw_loading_lbl is not None and self._hw_loading_bar is not None:
            all_done = total_files > 0 and done_files >= total_files
            if all_done:
                # Files are parsed — now in the post-load phase (indexes, ANALYZE…)
                self._hw_loading_lbl.setText(
                    f"Finalizing — building indexes…  ({done_events:,} events parsed)"
                )
                # Switch bar back to indeterminate for the index-build gap
                self._hw_loading_bar.setRange(0, 0)
            else:
                self._hw_loading_lbl.setText(
                    f"Parsing file {done_files + 1} of {total_files} "
                    f"— {done_events:,} events  ({eps:,.0f} ev/s)"
                )
                if total_files > 0:
                    # Determinate progress while files are being consumed
                    self._hw_loading_bar.setRange(0, total_files)
                    self._hw_loading_bar.setValue(done_files)

    @Slot(str)
    def _on_hw_finished(self, parquet_dir: str) -> None:
        """Juggernaut parse complete — load Arrow table and build ArrowTableModel."""
        from evtx_tool.core.heavyweight.engine import load_arrow_table
        from evtx_tool.gui.heavyweight_model import ArrowTableModel

        self._hw_db_path = parquet_dir   # stored for cleanup (dir deletion)
        self._hw_con     = None          # no persistent DuckDB connection needed

        # Load all events into an in-memory Arrow table (~114 MB for 6M rows).
        # ArrowTableModel's _FilterThread owns the single DuckDB connection.
        arrow_table = load_arrow_table(parquet_dir)
        self._hw_model = ArrowTableModel(
            arrow_table, parquet_dir=parquet_dir, parent=self
        )

        # ── Helper: wire a QTableView to a JM ArrowTableModel ─────────────────
        def _wire_jm_table(tbl, mdl) -> None:
            tbl.horizontalHeader().setSortIndicatorShown(False)
            self._apply_col_visibility(tbl, self._visible_cols)
            tbl.selectionModel().selectionChanged.connect(self._on_hw_row_selected)
            mdl.busy_started.connect(self._on_hw_filter_busy_started)
            mdl.busy_finished.connect(self._on_hw_filter_busy_finished)

        # ── Set main "All Events" model ────────────────────────────────────────
        main_table = self._table   # always the merged "All Events" QTableView
        main_table.setModel(self._hw_model)
        _wire_jm_table(main_table, self._hw_model)

        # ── Separate-tabs mode: populate file tree, open tabs on demand ───────
        # No tabs are pre-created. The user clicks a file in the tree to open
        # it — _on_tree_item_clicked detects JM mode and calls _open_jm_file_tab.
        if self._view_mode == "separate":
            # unique() on a dict-encoded column is O(n_dictionary) not O(n_rows)
            # — 23 ms vs 4000+ ms for to_pylist() on the full 6M-row column.
            source_files = sorted(
                v for v in arrow_table["source_file"].unique().to_pylist() if v
            )

            # Store the full Arrow table keyed by filepath so _open_jm_file_tab
            # can filter it on demand. Zero-copy — all file references share
            # the same underlying Arrow buffers.
            self._jm_pending: dict[str, object] = {
                fp: arrow_table for fp in source_files
            }
            self._jm_file_models: list = []

            # Populate file tree — "All Events" at top, then per-file entries
            self._file_tree.clear()
            all_item = QTreeWidgetItem(["All Events"])
            all_item.setData(0, Qt.ItemDataRole.UserRole, "__all_events__")
            all_item.setToolTip(0, "View all events from all files combined")
            f = all_item.font(0)
            f.setBold(True)
            all_item.setFont(0, f)
            self._file_tree.addTopLevelItem(all_item)
            for fp in source_files:
                ti = QTreeWidgetItem([os.path.basename(fp)])
                ti.setData(0, Qt.ItemDataRole.UserRole, fp)
                ti.setToolTip(0, fp)
                self._file_tree.addTopLevelItem(ti)

            # Show the All Events tab with a close button
            self._events_tab_widget.setTabVisible(0, True)
            self._attach_all_events_close_btn()

            # Show file tree panel — per-file tabs open on demand
            self._events_tab_widget.setBarCollapsed(False)
            self._file_tree_panel.setVisible(True)
            self._btn_tree_toggle.setEnabled(True)
            self._btn_tree_toggle.setChecked(True)
            self._events_content_splitter.setSizes([180, 800])
            self._scope_row_widget.setVisible(True)

        # ── Populate FilterDialog metadata from DuckDB (deferred) ────────────
        # In Juggernaut mode the analysis runner never fires, so _metadata
        # stays {}. Query distinct values directly from DuckDB so the Filter
        # dialog dropdowns (computers, channels, providers, event IDs) work.
        #
        # Deferred via QTimer.singleShot(0, ...) so the table view renders
        # first (user sees data immediately) and THEN we run the 4 DISTINCT
        # queries.  On 10M-row databases each DISTINCT took 100-500 ms;
        # running them synchronously here caused a visible freeze right after
        # the parse-complete status update appeared.
        QTimer.singleShot(0, lambda p=parquet_dir: self._load_jm_metadata(p))

        # ── Disable heavy analysis — ATT&CK / IOC / Correlation need full
        # in-memory event list which doesn't exist in Juggernaut mode.
        # Hayabusa (subprocess against .evtx files) works fine in JM.
        _jm_tip = "Not available in Juggernaut Mode"
        for chk in (self._chk_attack, self._chk_ioc, self._chk_correlate):
            chk.setEnabled(False)
            chk.setToolTip(_jm_tip)

        self._chk_hayabusa.setEnabled(True)
        self._chk_hayabusa.setToolTip("Run Hayabusa threat-detection rules against the loaded .evtx files")

        # Launch Hayabusa if the checkbox is ticked
        QTimer.singleShot(0, lambda: self._jm_launch_analysis(parquet_dir))

        # ── Wire profile combo for live post-parse filtering ──────────────
        # Profiles were applied at parse time as a pre-filter. Now also wire
        # them so that changing the profile selection post-parse re-applies
        # the filter against the already-loaded DuckDB data.
        #
        # Debounce: CheckableComboBox fires itemChanged once per checkbox tick.
        # Checking 5 profiles in sequence would trigger 5 back-to-back filter
        # rebuilds + COUNT(*) queries. A 150ms QTimer coalesces rapid toggles
        # into a single apply when the user finishes clicking.
        try:
            if self._hw_profile_filter_timer is None:
                from PySide6.QtCore import QTimer as _QT
                self._hw_profile_filter_timer = _QT(self)
                self._hw_profile_filter_timer.setSingleShot(True)
                self._hw_profile_filter_timer.timeout.connect(
                    self._on_hw_profile_filter_changed
                )
                self._hw_profile_signal_cb = (
                    lambda: self._hw_profile_filter_timer.start(150)
                )
            # Only connect if not already connected — prevents signal multiplication
            # when the user runs Juggernaut mode a second time in the same session.
            # The cleanup function (_stop_and_reset_hw) resets this flag on disconnect.
            if not self._hw_profile_signal_connected:
                self._profile_combo._chk_model.itemChanged.connect(
                    self._hw_profile_signal_cb
                )
                self._hw_profile_signal_connected = True
        except Exception:
            pass

        total = self._hw_model.total_event_count()
        elapsed = time.monotonic() - self._parse_start_ts
        rps = total / elapsed if elapsed > 0 else 0

        # ── Diagnostic: verify model sees the events ─────────────────────
        import logging as _logging
        _mw_log = _logging.getLogger(__name__)
        if total == 0:
            _mw_log.warning(
                "_on_hw_finished: model reports 0 events - parquet_dir=%s  "
                "Check worker/engine logs above for root cause.",
                parquet_dir,
            )
        else:
            _mw_log.info(
                "_on_hw_finished: model loaded %d events from %s", total, parquet_dir,
            )

        self._progress_bar.setValue(100)
        self._btn_parse.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._set_status(
            f"\u26a1 Juggernaut Mode",
            stats=f"{total:,} events  |  {rps:,.0f} rec/s  |  {elapsed:.1f}s",
        )
        self.setWindowTitle(
            f"EventHawk \u2014 \u26a1 Juggernaut Mode ({total:,} events)"
        )
        self._update_count_label()
        self._btn_export.setEnabled(True)
        self._act_export.setEnabled(True)
        # Dismiss the "Please Wait" overlay — data is now visible in the table.
        self._close_hw_loading_dialog()
        self._hw_worker = None

    def _load_jm_metadata(self, parquet_dir: str) -> None:
        """Populate FilterDialog metadata from the Arrow table in a background thread.

        Runs in a daemon thread; the result is posted back to the main thread
        via QTimer.singleShot(0, ...) once all queries finish.
        """
        import threading

        if self._hw_model is None:
            return
        # Capture Arrow table reference on the main thread (immutable, thread-safe).
        arrow_table = self._hw_model._full_table

        def _worker() -> None:
            import logging as _log
            _logger = _log.getLogger(__name__)
            meta: dict = {}
            try:
                import duckdb
                _con = duckdb.connect()
                _con.register("events", arrow_table)
                # Keys must match build_metadata() in metadata.py so FilterDialog
                # picker buttons ("...") work identically in normal and Juggernaut mode.
                for col, key in (
                    ("provider", "source"),
                    ("channel",  "category"),
                    ("user_id",  "user"),
                    ("computer", "computer"),
                ):
                    rows = _con.execute(
                        f"SELECT DISTINCT {col} FROM events "
                        f"WHERE {col} IS NOT NULL AND {col} != '' "
                        f"ORDER BY {col} LIMIT 500"
                    ).fetchall()
                    meta[key] = {r[0]: 1 for r in rows}
                eid_rows = _con.execute(
                    "SELECT DISTINCT event_id FROM events ORDER BY event_id LIMIT 2000"
                ).fetchall()
                meta["event_id"] = {str(r[0]): 1 for r in eid_rows}
                _con.close()
            except Exception as exc:
                _logger.warning("_load_jm_metadata background worker failed: %s", exc)

            # Post result back to main thread — QTimer.singleShot is thread-safe.
            QTimer.singleShot(0, lambda m=meta: self._on_jm_metadata_loaded(m))

        threading.Thread(target=_worker, daemon=True, name="jm-metadata").start()

    def _on_jm_metadata_loaded(self, meta: dict) -> None:
        """Receive FilterDialog metadata loaded by the background worker thread."""
        self._metadata = meta

    def _on_hw_row_selected(self) -> None:
        """Handle row selection in Juggernaut Mode — fetch event via active tab's model."""
        if self._hw_model is None:
            return
        indexes = self._active_table.selectionModel().selectedRows()
        if not indexes:
            return
        # In separate-tabs mode each file tab has its own ArrowTableModel.
        # Use the model directly set on the active QTableView so row indices
        # map to the right file's events, not the merged "All Events" model.
        from evtx_tool.gui.heavyweight_model import ArrowTableModel as _ATM
        active_model = self._active_table.model()
        model = active_model if isinstance(active_model, _ATM) else self._hw_model
        ev = model.get_event(indexes[0].row())
        if ev:
            self._render_event_detail(ev)
            self._update_bookmark_button(ev)

    def _cleanup_juggernaut(self) -> None:
        """Release heavyweight resources and restore normal-mode UI state."""
        # Safety: close loading dialog and cancel any pending busy timer so
        # they don't fire into a torn-down model after cleanup.
        if self._hw_filter_busy_timer is not None:
            self._hw_filter_busy_timer.stop()
        self._close_hw_loading_dialog()

        # Stop any in-flight column popup workers FIRST so their finished signals
        # don't fire into a torn-down state after the connection is closed.
        for _w in getattr(self, "_col_value_workers", []):
            if _w.isRunning():
                try:
                    _w.finished.disconnect()  # detach so emit goes nowhere
                except Exception:
                    pass
                _w.quit()
                _w.wait(500)  # fast GROUP BY — 500ms is generous
        self._col_value_workers = []

        if self._hw_worker is not None:
            self._hw_worker.request_stop()
            self._hw_worker = None
        # Close the model BEFORE closing the connection.
        # Pending QTimer.singleShot(50, ...) prefetch lambdas and the
        # _count_timer hold a reference to the model and will fire after
        # this method returns.  model.close() nulls _con so every guard in
        # _get_page/_prefetch_page/_refresh_count short-circuits safely —
        # the connection can then be closed without a use-after-close crash.
        if self._hw_model is not None:
            self._hw_model.close()
            self._hw_model = None

        # Clear pending JM file table references
        self._jm_pending = {}

        # Close per-file ArrowTableModels created in JM separate-tabs mode
        for _fm in getattr(self, "_jm_file_models", []):
            try:
                _fm.close()
            except Exception:
                pass
        self._jm_file_models = []
        if self._hw_con is not None:
            try:
                self._hw_con.close()
            except Exception:
                pass
            self._hw_con = None

        # Remove the Parquet session directory (parquet_dir) and all its contents.
        # DuckDB session file + .parquet shards are all inside this directory.
        if self._hw_db_path:
            try:
                import shutil as _shutil
                if _shutil.os.path.isdir(self._hw_db_path):
                    _shutil.rmtree(self._hw_db_path, ignore_errors=True)
            except Exception:
                pass
            self._hw_db_path = None

        # Re-enable Analysis checkboxes for normal mode
        for chk in (
            self._chk_attack, self._chk_ioc, self._chk_correlate,
            self._chk_hayabusa,
        ):
            chk.setEnabled(True)
            chk.setToolTip("")

        # Disconnect the profile combo debounce callback (only if connected)
        if self._hw_profile_signal_connected and self._hw_profile_signal_cb is not None:
            try:
                self._profile_combo._chk_model.itemChanged.disconnect(
                    self._hw_profile_signal_cb
                )
            except Exception:
                pass
            self._hw_profile_signal_connected = False
        # Stop the debounce timer so a pending callback doesn't fire after cleanup
        if self._hw_profile_filter_timer is not None:
            self._hw_profile_filter_timer.stop()

    def _on_hw_profile_filter_changed(self) -> None:
        """Re-apply the profile selection as a SQL filter in Juggernaut mode.

        Called whenever the user checks/unchecks a profile while Juggernaut
        Mode is active.  Converts the selected profiles to a filter_config
        (same as parse-time), translates it to SQL via filter_config_to_sql,
        and applies it to the live SQLite model — no re-parse needed.
        """
        if self._hw_model is None:
            return
        fc = self._build_filter_config()
        self._hw_model.apply_filter(fc)
        self._update_adv_filter_badge()
        self._update_count_label()

    # =========================================================================
    # PROFILES
    # =========================================================================

    def _refresh_profiles(self) -> None:
        """Reload profiles from disk, preserving current selections."""
        prev_checked = set()
        if hasattr(self, "_profile_combo"):
            prev_checked = set(self._profile_combo.checkedItems())

        try:
            from evtx_tool.profiles.manager import ProfileManager
            pm = ProfileManager()
            profiles = pm.list_profiles()
        except Exception:
            return

        self._profile_combo.clearItems()
        for p in profiles:
            self._profile_combo.addCheckItem(
                p["name"],
                checked=(p["name"] in prev_checked),
                tooltip=p.get("description", ""),
            )

    def _setup_profile_watcher(self) -> None:
        """Watch default and user profile directories for changes."""
        from pathlib import Path
        dirs_to_watch = []
        try:
            from evtx_tool.profiles.manager import DEFAULTS_DIR, DEFAULT_USER_DIR
            if DEFAULTS_DIR.exists():
                dirs_to_watch.append(str(DEFAULTS_DIR))
            DEFAULT_USER_DIR.mkdir(parents=True, exist_ok=True)
            dirs_to_watch.append(str(DEFAULT_USER_DIR))
        except Exception:
            fallback = Path("profiles")
            fallback.mkdir(parents=True, exist_ok=True)
            dirs_to_watch.append(str(fallback))

        if dirs_to_watch:
            self._profile_watcher.addPaths(dirs_to_watch)

    def _select_all_profiles(self) -> None:
        self._profile_combo.checkAll()

    def _select_no_profiles(self) -> None:
        self._profile_combo.uncheckAll()

    def _get_checked_profiles(self) -> list[str]:
        return self._profile_combo.checkedItems()

    def _on_new_profile(self) -> None:
        """Open the Profile Editor to create a new custom profile."""
        from evtx_tool.gui.profile_editor import ProfileEditorDialog
        dlg = ProfileEditorDialog(profile=None, parent=self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            self._refresh_profiles()

    def _on_edit_profile(self) -> None:
        """Open the Profile Editor for the currently selected profile.

        If multiple profiles are checked, opens the first one.
        If none are checked, opens a blank New Profile dialog.
        """
        from evtx_tool.gui.profile_editor import ProfileEditorDialog
        from evtx_tool.profiles.manager import ProfileManager

        checked = self._get_checked_profiles()
        if not checked:
            self._on_new_profile()
            return

        pm = ProfileManager()
        profile = pm.get(checked[0])
        dlg = ProfileEditorDialog(profile=profile, parent=self)
        if dlg.exec() == dlg.DialogCode.Accepted:
            self._refresh_profiles()

    # =========================================================================
    # COLUMN HEADER DROPDOWN FILTER
    # =========================================================================

    def _on_col_header_clicked(self, logical_index: int) -> None:
        """Open a dropdown filter popup for the clicked column."""
        if logical_index not in ColumnFilterPopup.FILTERABLE:
            return

        col_key = ColumnFilterPopup.FILTERABLE[logical_index]

        # Juggernaut Mode: run GROUP BY on a background thread to avoid
        # blocking the main thread for large datasets.
        if self._hw_model is not None:
            self._start_col_value_worker(logical_index, col_key)
            return

        if not self._active_events:
            return
        # Run counting on a background thread — avoids blocking the main thread
        # for large event lists (same async pattern as Juggernaut mode).
        from evtx_tool.gui.jm_col_worker import NormalColValueWorker
        worker = NormalColValueWorker(self._active_events, col_key, parent=self)
        worker.finished.connect(
            lambda vals, idx=logical_index: (
                self._show_col_filter_popup(idx, vals) if vals else None
            )
        )
        worker.start()
        if not hasattr(self, "_col_value_workers"):
            self._col_value_workers = []
        self._col_value_workers = [w for w in self._col_value_workers if w.isRunning()]
        self._col_value_workers.append(worker)

    def _start_col_value_worker(self, logical_index: int, col_key: str) -> None:
        """Start async ColValueWorker for Juggernaut Mode column filter popup."""
        from evtx_tool.gui.jm_col_worker import ColValueWorker
        if self._hw_model is None:
            return
        # If a per-file tab is active, scope GROUP BY to that file only.
        active_fp = getattr(self, "_active_file_tab", None)
        file_state = self._file_tabs.get(active_fp) if active_fp else None
        if file_state and active_fp:
            where_sql, where_params = "source_file = ?", [active_fp]
        else:
            where_sql, where_params = None, None
        worker = ColValueWorker(
            self._hw_model._full_table, col_key,
            where_sql=where_sql, where_params=where_params,
            parent=self,
        )
        worker.finished.connect(
            lambda vals, idx=logical_index: (
                self._show_col_filter_popup(idx, vals) if self._hw_model else None
            )
        )
        worker.start()
        # Keep a reference so the worker isn't GC'd before it finishes
        if not hasattr(self, "_col_value_workers"):
            self._col_value_workers = []
        # Prune finished workers from the list to prevent accumulation
        self._col_value_workers = [w for w in self._col_value_workers if w.isRunning()]
        self._col_value_workers.append(worker)

    def _show_col_filter_popup(self, logical_index: int, values: dict) -> None:
        """Create and show the column filter popup with the given value counts."""
        if not values:
            return

        # Position popup below the header section
        hdr = self._active_table.horizontalHeader()
        section_x = hdr.sectionPosition(logical_index) - hdr.offset()
        global_pos = hdr.mapToGlobal(QPoint(section_x, hdr.height()))

        popup = ColumnFilterPopup(logical_index, values, parent=self)

        # Bug 7 fix: derive pre-uncheck state from the active tab's actual quick filters
        # rather than the global _col_filters (which is shared across tabs)
        _popup_col_key = ColumnFilterPopup.FILTERABLE.get(logical_index, "")
        if _popup_col_key:
            if self._hw_model is not None:
                from evtx_tool.gui.heavyweight_model import ArrowTableModel as _ATM
                _am = self._active_table.model()
                _qf_src = _am if isinstance(_am, _ATM) else self._hw_model
                _active_qf = _qf_src.get_quick_filters()
            else:
                _active_qf = self._active_proxy.get_quick_filters()
            excluded_set = {
                qf["value"] for qf in _active_qf
                if qf.get("key") == _popup_col_key and not qf.get("include", True)
            }
            if excluded_set:
                for chk in popup._checkboxes:
                    if chk.property("filter_value") in excluded_set:
                        chk.setChecked(False)

        popup.filterApplied.connect(self._on_col_filter_applied)
        popup.sortRequested.connect(
            lambda col, order, tbl=self._active_table:
                self._on_sort_by_column(col, tbl, force_order=order)
        )
        popup.move(global_pos)
        popup.show()

    def _on_col_filter_applied(self, col_index: int, excluded: list) -> None:
        """Apply column filter selections by setting Quick Filters."""
        col_key = ColumnFilterPopup.FILTERABLE.get(col_index, "")
        if not col_key:
            return

        # In separate-tabs mode ask which files to target before committing state.
        # Call _filter_target_tabs() exactly once and reuse scope_dlg below to avoid
        # a NameError if the first call returns empty or state changes between two calls.
        scope_dlg = None
        if self._view_mode == "separate":
            target_tabs = self._filter_target_tabs()
            if target_tabs:
                scope_dlg = _FilterTargetDialog(target_tabs, self)
                if scope_dlg.exec() != QDialog.DialogCode.Accepted:
                    return  # cancelled — _col_filters stays unchanged

        # Commit column filter state now that we know we're applying
        if excluded:
            self._col_filters[col_index] = excluded
        else:
            self._col_filters.pop(col_index, None)

        # Build the full quick-filter list from all current column filters
        new_qf: list[dict] = []
        for ci, excl_values in self._col_filters.items():
            ck = ColumnFilterPopup.FILTERABLE.get(ci, "")
            if ck:
                for val in excl_values:
                    new_qf.append({"key": ck, "value": val, "include": False})

        if self._view_mode == "separate":
            if scope_dlg is not None:
                is_jm = self._hw_model is not None
                for fp in scope_dlg.selected():
                    if fp == "__all_events__":
                        if is_jm:
                            self._hw_model.set_quick_filters(new_qf)
                        else:
                            self._proxy_model.set_quick_filters(new_qf)
                        continue
                    state = self._file_tabs.get(fp)
                    if state is None:
                        continue
                    if is_jm:
                        state.model.set_quick_filters(new_qf)
                    else:
                        state.proxy.set_quick_filters(new_qf)
                self._update_quick_filter_badge()
                self._update_count_label()
                self._update_header_indicators()
            return  # Always return in separate mode — never fall through to merged path

        # Merged mode — apply to active model as before
        if self._hw_model is not None:
            self._hw_model.set_quick_filters(new_qf)
            self._update_quick_filter_badge()
            self._update_count_label()
            self._update_header_indicators()
            return

        self._active_proxy.set_quick_filters(new_qf)
        self._update_quick_filter_badge()
        self._update_count_label()
        self._update_header_indicators()

    def _build_column_values(self, col_key: str) -> dict:
        """Build {value: count} dict from the current events for a given key."""
        counts: dict[str, int] = {}
        for ev in self._active_events:
            val = str(ev.get(col_key, ""))
            counts[val] = counts.get(val, 0) + 1
        return counts

    def _build_column_values_hw(self, col_key: str) -> dict:
        """Build {value: count} from the Arrow table for Juggernaut mode column filters.

        Synchronous fallback — async path uses ColValueWorker instead.
        """
        if self._hw_model is None:
            return {}
        _COL_MAP = {
            "event_id":    "CAST(event_id AS VARCHAR)",
            "level_name":  "level_name",
            "computer":    "computer",
            "channel":     "channel",
            "user_id":     "user_id",
            "source_file": "source_file",
        }
        expr = _COL_MAP.get(col_key)
        if not expr:
            return {}
        try:
            import duckdb as _duckdb
            _con = _duckdb.connect()
            try:
                _con.register("events", self._hw_model._full_table)
                rows = _con.execute(
                    f"SELECT {expr}, COUNT(*) FROM events "
                    f"WHERE {expr} IS NOT NULL "
                    f"GROUP BY {expr} ORDER BY COUNT(*) DESC LIMIT 1000"
                ).fetchall()
            finally:
                _con.close()
            return {(str(r[0]) if r[0] is not None else ""): r[1] for r in rows}
        except Exception:
            return {}

    def _update_header_indicators(self) -> None:
        """Add ▼ indicator to column headers that have active filters."""
        if self._hw_model is not None:
            # Juggernaut mode: update HW model's _header_overrides dict
            if not hasattr(self._hw_model, "_header_overrides"):
                self._hw_model._header_overrides = {}
            self._hw_model._header_overrides.clear()
            for col in self._col_filters:
                if self._col_filters[col] and col < len(COLUMNS):
                    self._hw_model._header_overrides[col] = f"▼ {COLUMNS[col]}"
            self._hw_model.headerDataChanged.emit(
                Qt.Orientation.Horizontal, 0, self._hw_model.columnCount() - 1
            )
            return
        model = self._active_model
        model._header_overrides.clear()
        for col in self._col_filters:
            if self._col_filters[col] and col < len(COLUMNS):
                model._header_overrides[col] = f"▼ {COLUMNS[col]}"
        model.headerDataChanged.emit(
            Qt.Orientation.Horizontal, 0, model.columnCount() - 1
        )


    # =========================================================================
    # BUILD FILTER
    # =========================================================================

    def _build_filter_config(self) -> dict:
        from evtx_tool.core.filters import empty_filter
        fc = empty_filter()

        # Apply profiles (parse-time event ID / provider filtering)
        checked_profiles = self._get_checked_profiles()
        if checked_profiles:
            try:
                from evtx_tool.profiles.manager import ProfileManager
                fc = ProfileManager().build_filter(checked_profiles, base_filter=fc)
            except Exception:
                pass

        return fc

    # ── Hayabusa path helpers ─────────────────────────────────────────────

    def _load_hayabusa_path(self) -> None:
        """Load saved Hayabusa path from QSettings, or auto-detect."""
        from PySide6.QtCore import QSettings
        settings = QSettings()
        saved = settings.value("hayabusa/binary_path", "", type=str)
        if saved and os.path.isfile(saved):
            self._hayabusa_path = saved
        else:
            # Auto-detect
            from evtx_tool.analysis.hayabusa_runner import find_hayabusa
            self._hayabusa_path = find_hayabusa()

        if self._hayabusa_path:
            name = os.path.basename(self._hayabusa_path)
            self._lbl_hayabusa_path.setText(f"✓ {name}")
            self._lbl_hayabusa_path.setToolTip(self._hayabusa_path)
            self._lbl_hayabusa_path.setStyleSheet("font-size: 11px; color: #5f5;")
        else:
            self._lbl_hayabusa_path.setText("⚠ Not configured")
            self._lbl_hayabusa_path.setToolTip(
                "Hayabusa executable not found.\n"
                "Click Browse and select hayabusa.exe.\n"
                "Download from: github.com/Yamato-Security/hayabusa/releases"
            )
            self._lbl_hayabusa_path.setStyleSheet("font-size: 11px; color: #c07000;")

    def _pick_hayabusa_path(self) -> None:
        """Open file dialog to select Hayabusa binary."""
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Hayabusa binary",
            "",
            "Executables (*.exe);;All Files (*)" if sys.platform == "win32" else "All Files (*)",
        )
        if path and os.path.isfile(path):
            self._hayabusa_path = path
            from PySide6.QtCore import QSettings
            settings = QSettings()
            settings.setValue("hayabusa/binary_path", path)
            name = os.path.basename(path)
            self._lbl_hayabusa_path.setText(f"✓ {name}")
            self._lbl_hayabusa_path.setToolTip(path)
            self._lbl_hayabusa_path.setStyleSheet("font-size: 11px; color: #5f5;")


    # =========================================================================
    # PARSE FLOW
    # =========================================================================

    def _on_parse_clicked(self) -> None:
        files = self._collect_files()
        if not files:
            QMessageBox.warning(self, "No Files", "Add EVTX files or a directory first.")
            return

        # ── Volume safety gate ───────────────────────────────────────────
        _volume_choice = self._check_volume(files)
        if _volume_choice == "cancel":
            return
        if _volume_choice == "juggernaut":
            return self._launch_juggernaut_mode(files)

        # Cleanup previous juggernaut state if any
        self._cleanup_juggernaut()

        # Cancel any running analysis from previous parse
        if self._analysis_runner is not None and self._analysis_runner.is_running():
            self._analysis_runner.request_stop()
            self._analysis_runner = None

        # Capture view mode choice before clearing
        self._view_mode = "separate" if self._radio_separate.isChecked() else "merged"
        self._last_parsed_files: list[str] = files  # saved so _on_parse_finished can populate 0-event files

        self._clear_results()
        self._parse_start_ts = time.monotonic()
        self._progress_bar.setValue(0)
        self._btn_parse.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._btn_export.setEnabled(False)
        self._act_export.setEnabled(False)
        self._set_status(f"Parsing {len(files)} file(s)...")

        max_threads = self._cmb_threads.currentData()  # None = Auto

        self._worker = ParseWorker(
            files         = files,
            filter_config = self._build_filter_config(),
            do_attack     = self._chk_attack.isChecked(),
            do_ioc        = self._chk_ioc.isChecked(),
            do_correlate  = self._chk_correlate.isChecked(),
            max_workers   = max_threads,
        )
        self._worker.progress.connect(self._on_parse_progress)
        self._worker.finished.connect(self._on_parse_finished)
        self._worker.error.connect(self._on_parse_error)
        self._worker.start()

    def _on_stop_clicked(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
        if self._hw_worker is not None and self._hw_worker.isRunning():  # Bug 2 fix
            self._hw_worker.request_stop()
        if self._analysis_runner is not None and self._analysis_runner.is_running():
            self._analysis_runner.request_stop()
        self._set_status("Stopping...")
        self._btn_stop.setEnabled(False)

    @Slot(object)
    def _on_parse_progress(self, state: dict) -> None:
        total = state.get("total_files", 1) or 1
        done  = state.get("done_files", 0)
        matched = state.get("total_events_matched", 0)
        rps   = state.get("events_per_sec", 0)
        elapsed = state.get("elapsed_sec", 0)

        pct = int(done / total * 100)
        self._progress_bar.setValue(pct)
        self._lbl_matched.setText(f"Events: {matched:,}")
        self._lbl_speed.setText(f"Speed: {rps:,.0f} rec/s")
        self._lbl_elapsed.setText(f"Time: {elapsed:.1f}s")
        self._set_status(
            f"Parsing...  {done}/{total} files",
            stats=f"{matched:,} events  |  {rps:,.0f} rec/s",
        )

    @Slot(object, object, object, object, object, object)
    def _on_parse_finished(
        self,
        events: list[dict],
        attack_summary,
        do_ioc: bool,
        do_correlate: bool,
        search_cache: list[str] | None = None,
    ) -> None:
        elapsed = time.monotonic() - self._parse_start_ts

        self._events         = events
        self._attack_summary = attack_summary
        self._iocs           = None
        self._chains         = []
        self._metadata       = {}

        # Clear stale filter state
        self._active_tactic_filter = None
        self._active_technique_filter = None
        self._tactic_filter_widget.setVisible(False)
        self._col_filters.clear()

        if self._view_mode == "separate" and events:
            # ── SEPARATE MODE: split by source_file → per-file tabs ──────
            self._per_file_data.clear()
            for i, ev in enumerate(events):
                sf = ev.get("source_file", "unknown")
                bucket = self._per_file_data.setdefault(sf, {"events": [], "search_cache": []})
                bucket["events"].append(ev)
                if search_cache and i < len(search_cache):
                    bucket["search_cache"].append(search_cache[i])

            # Ensure ALL parsed files appear in the tree, even those with 0 matching events
            for fp in getattr(self, "_last_parsed_files", []):
                if fp not in self._per_file_data:
                    self._per_file_data[fp] = {"events": [], "search_cache": []}

            # Populate the merged "All Events" table (same as merged mode)
            self._table.setUpdatesEnabled(False)
            self._table.setSortingEnabled(False)
            self._proxy_model.setDynamicSortFilter(False)
            _old_sel = self._table.selectionModel()
            if _old_sel is not None:
                try:
                    _old_sel.selectionChanged.disconnect(self._on_row_selected)
                except (RuntimeError, TypeError):
                    pass
            self._table.setModel(None)
            self._proxy_model.set_tactic_filter(None)
            self._proxy_model.clear_advanced_filter()
            self._proxy_model.clear_quick_filters()
            self._event_model.set_events(events, search_cache=search_cache)
            self._table.setModel(self._proxy_model)
            self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            self._table.selectionModel().selectionChanged.connect(self._on_row_selected)
            col_widths = [40, 70, 90, 170, 130, 150, 110, 80]
            for i, w_val in enumerate(col_widths):
                self._table.setColumnWidth(i, w_val)
            self._apply_col_visibility(self._table, self._visible_cols)
            self._proxy_model.setDynamicSortFilter(True)
            self._table.setUpdatesEnabled(True)

            # Show the "All Events" tab with a close button, show tab bar and tree
            self._events_tab_widget.setTabVisible(0, True)
            self._events_tab_widget.setBarCollapsed(False)
            self._attach_all_events_close_btn()
            self._populate_file_tree()
            self._file_tree_panel.setVisible(True)
            self._btn_tree_toggle.setEnabled(True)
            self._btn_tree_toggle.setChecked(True)
            self._events_content_splitter.setSizes([180, 800])

            # Show analysis scope toggle and reset to "This File"
            self._scope_row_widget.setVisible(True)
            self._cmb_analysis_scope.setCurrentIndex(0)   # "This File"
            self._analysis_scope = "file"

            # Switch to All Events tab and auto-open the first file's tab
            self._events_tab_widget.setCurrentIndex(0)
            self._active_file_tab = None
            first_fp = sorted(self._per_file_data.keys())[0]
            self._create_file_tab(first_fp)

        else:
            # ── MERGED MODE: single combined view (existing behaviour) ───
            self._file_tree_panel.setVisible(False)
            self._btn_tree_toggle.setEnabled(False)
            self._btn_tree_toggle.setChecked(False)
            self._scope_row_widget.setVisible(False)
            self._events_tab_widget.setTabVisible(0, True)
            self._events_tab_widget.setBarCollapsed(True)   # merged mode: no tab bar

            # Fast load: detach proxy from view to avoid 407K filterAcceptsRow calls
            self._table.setUpdatesEnabled(False)
            self._table.setSortingEnabled(False)
            self._proxy_model.setDynamicSortFilter(False)

            # Disconnect from OLD selection model BEFORE setModel(None) replaces it.
            # Disconnecting after setModel(None) operates on the new empty model which
            # never had the signal connected, causing a PySide6 RuntimeWarning.
            _old_sel = self._table.selectionModel()
            if _old_sel is not None:
                try:
                    _old_sel.selectionChanged.disconnect(self._on_row_selected)
                except (RuntimeError, TypeError):
                    pass

            self._table.setModel(None)

            self._proxy_model.set_tactic_filter(None)
            self._proxy_model.clear_advanced_filter()
            self._proxy_model.clear_quick_filters()

            self._event_model.set_events(events, search_cache=search_cache)

            self._table.setModel(self._proxy_model)

            self._table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            self._table.selectionModel().selectionChanged.connect(self._on_row_selected)

            col_widths = [40, 70, 90, 170, 130, 150, 110, 80]
            for i, w_val in enumerate(col_widths):
                self._table.setColumnWidth(i, w_val)

            # Re-apply user's column visibility — setModel() above resets all
            # hidden-column state so every column becomes visible again.
            self._apply_col_visibility(self._table, self._visible_cols)

            self._proxy_model.setDynamicSortFilter(True)
            self._table.setUpdatesEnabled(True)

            # Switch to the merged tab
            self._events_tab_widget.setCurrentIndex(0)
            self._active_file_tab = None

        self._update_header_indicators()
        self._update_count_label()
        self._progress_bar.setValue(100)

        # ── Show events + ATT&CK tab immediately ──────────────────────
        QTimer.singleShot(0, self._refresh_attack_tab)

        self._btn_parse.setEnabled(True)
        export_ok = len(events) > 0
        self._btn_export.setEnabled(export_ok)
        self._act_export.setEnabled(export_ok)

        self._lbl_matched.setText(f"Events: {len(events):,}")
        self._lbl_elapsed.setText(f"Time: {elapsed:.1f}s")

        parts = [f"{len(events):,} events", f"{elapsed:.1f}s"]
        if attack_summary:
            parts.append(f"ATT&CK: {attack_summary.get('total_tagged',0):,}")

        self._worker = None

        # ── Phase 2: Launch background analysis (metadata + optional IOC/Correlate)
        if events:
            self._set_status("Analysing…", stats="  |  ".join(parts))
            self._btn_stop.setEnabled(True)
            self._ioc_pivot_map = {}   # invalidate stale pivot data from previous run
            self._analysis_runner = AnalysisRunner(parent=self)
            self._analysis_runner.progress.connect(self._on_analysis_progress)
            self._analysis_runner.component_progress.connect(self._on_component_progress)
            self._analysis_runner.finished.connect(self._on_analysis_finished)
            self._analysis_runner.error.connect(self._on_analysis_error)
            do_hayabusa = self._chk_hayabusa.isChecked()
            self._analysis_runner.start(
                events=events,
                do_ioc=do_ioc,
                do_correlate=do_correlate,
                do_hayabusa=do_hayabusa,
                hayabusa_path=self._hayabusa_path if do_hayabusa else None,
                evtx_paths=getattr(self, '_last_parsed_files', None) if do_hayabusa else None,
            )
        else:
            self._btn_stop.setEnabled(False)
            self._set_status("Done", stats="  |  ".join(parts))

    # ── Analysis phase callbacks ─────────────────────────────────────────

    @Slot(str)
    def _on_analysis_progress(self, step_name: str) -> None:
        self._set_status(f"Analysing…  {step_name}")

    @Slot(str, int)
    def _on_component_progress(self, component: str, pct: int) -> None:
        """Update per-component progress in the status bar."""
        self._component_pcts[component] = pct
        parts = []
        for name, p in self._component_pcts.items():
            if p >= 100:
                parts.append(f"{name}: ✓")
            else:
                parts.append(f"{name}: {p}%")
        self._lbl_analysis_progress.setText("  |  ".join(parts))
        self._lbl_analysis_progress.setVisible(True)

        # If all components are 100%, auto-hide after 1.5s
        if all(v >= 100 for v in self._component_pcts.values()):
            QTimer.singleShot(1500, self._hide_component_progress)

    def _hide_component_progress(self) -> None:
        self._lbl_analysis_progress.setVisible(False)
        self._lbl_analysis_progress.setText("")
        self._component_pcts.clear()

    @Slot(object, object, object)
    def _on_analysis_finished(self, iocs, chains, metadata) -> None:
        self._iocs     = iocs
        self._chains   = chains or []
        self._metadata = metadata or {}

        # Build IOC pivot map — (category_key, value) → frozenset[record_id].
        # This is the single source of truth for exact event linking at pivot time.
        # Category keys match the ioc_types list in _refresh_iocs_tab.
        self._ioc_pivot_map = {}
        _PIVOT_CATEGORIES = (
            "ipv4", "ipv6", "domains", "urls",
            "sha256", "sha1", "md5",
            "processes", "commandlines", "registry", "filepaths",
            "services", "tasks", "named_pipes", "shares", "dlls",
            "users", "computers",
        )
        for _cat in _PIVOT_CATEGORIES:
            for _entry in (iocs or {}).get(_cat) or []:
                if isinstance(_entry, dict):
                    _rids = _entry.get("record_ids") or []
                    if _rids:
                        self._ioc_pivot_map[(_cat, _entry["value"])] = frozenset(_rids)

        # Populate analysis tabs
        QTimer.singleShot(0,   self._refresh_iocs_tab)
        QTimer.singleShot(50,  self._refresh_chains_tab)

        self._btn_stop.setEnabled(False)
        self._analysis_runner = None

        # Update status with full stats
        elapsed = time.monotonic() - self._parse_start_ts
        n_events = (
            self._hw_model.total_event_count()
            if (self._hw_model is not None and not self._events)
            else len(self._events)
        )
        parts = [f"{n_events:,} events", f"{elapsed:.1f}s"]
        if self._attack_summary:
            parts.append(f"ATT&CK: {self._attack_summary.get('total_tagged',0):,}")
        if iocs:
            s = iocs.get("summary", {})
            total_iocs = sum(s.values())
            if total_iocs:
                parts.append(f"IOCs: {total_iocs}")
        if chains:
            parts.append(f"Chains: {len(chains)}")
        self._set_status("Done", stats="  |  ".join(parts))

    @Slot(str)
    def _on_analysis_error(self, msg: str) -> None:
        self._btn_stop.setEnabled(False)
        self._analysis_runner = None
        self._set_status("Done (analysis failed)")


    @Slot(str)
    def _on_parse_error(self, msg: str) -> None:
        self._btn_parse.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._set_status("Error")
        QMessageBox.critical(self, "Parse Error", f"An error occurred:\n\n{msg}")
        self._worker = None
        self._hw_worker = None  # Bug 10 fix: clear hw_worker on error too
        # FINDING-22: clean up stale DuckDB connection and JM model on error.
        # Without this, _hw_con stays open, locking temp files or consuming RAM.
        self._cleanup_juggernaut()

    # =========================================================================
    # TABLE — LIVE FILTER + SELECTION
    # =========================================================================

    # ── Filter target helper ──────────────────────────────────────────────

    def _filter_target_tabs(self) -> dict:
        """
        Build the {key: state} dict passed to _FilterTargetDialog.
        Includes a synthetic "All Events" entry when that combined tab is visible,
        since __all_events__ is never stored in _file_tabs.
        """
        from types import SimpleNamespace
        tabs: dict = {}
        if self._events_tab_widget.isTabVisible(0):
            tabs["__all_events__"] = SimpleNamespace(display_name="All Events")
        for fp, state in self._file_tabs.items():
            if not fp.startswith("__chain__"):
                tabs[fp] = state
        return tabs

    # ── Advanced Filter Dialog ────────────────────────────────────────────

    def _on_advanced_filter_clicked(self) -> None:
        """Open the ELE-style advanced filter dialog."""
        dlg = FilterDialog(
            metadata=self._metadata,
            current_filter=self._adv_filter_cfg,
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cfg = dlg.get_filter_config()

        # In separate-tabs mode ask which files to target before committing cfg
        if self._view_mode == "separate":
            target_tabs = self._filter_target_tabs()
            if target_tabs:
                scope_dlg = _FilterTargetDialog(target_tabs, self)
                if scope_dlg.exec() != QDialog.DialogCode.Accepted:
                    return  # cancelled — _adv_filter_cfg stays unchanged
                self._adv_filter_cfg = cfg
                is_jm = self._hw_model is not None
                for fp in scope_dlg.selected():
                    if fp == "__all_events__":
                        if is_jm:
                            self._hw_model.apply_filter(cfg)
                        else:
                            self._proxy_model.set_advanced_filter(cfg)
                        continue
                    state = self._file_tabs.get(fp)
                    if state is None:
                        continue
                    if is_jm:
                        state.model.apply_filter(cfg)
                    else:
                        state.proxy.set_advanced_filter(cfg)
                self._update_adv_filter_badge()
                self._update_count_label()
                return

        # Merged mode (or no file tabs yet) — apply to active model as before
        self._adv_filter_cfg = cfg
        if self._hw_model is not None:
            self._hw_model.apply_filter(cfg)
            self._update_adv_filter_badge()
            self._update_count_label()
            return
        self._active_proxy.set_advanced_filter(cfg)
        self._update_adv_filter_badge()
        self._update_count_label()

    def _clear_advanced_filter(self) -> None:
        """Remove the advanced filter and hide the badge."""
        self._adv_filter_cfg = None
        # Bug 3 fix: in Juggernaut Mode clear via hw_model
        if self._hw_model is not None:
            self._hw_model.clear_filter()
            self._update_adv_filter_badge()
            self._update_count_label()
            return
        self._active_proxy.clear_advanced_filter()
        self._update_adv_filter_badge()
        self._update_count_label()

    def _clear_all_filters(self) -> None:
        """Reset every active filter layer and return to the full unfiltered view.

        Covers: text search bar, advanced filter, quick column filters,
        session LogonId filter, ATT&CK tactic filter, bookmark/IOC pivot
        (record-ID filter).  Safe to call even when no filters are active.
        """
        # 1. Advanced filter
        self._adv_filter_cfg = None

        # 3. Record-ID filter (IOC pivot, missing-record-ID) + bookmark filter
        if self._hw_model is not None:
            # Batch all state resets then call _invalidate() once to avoid
            # queuing 4 separate filter-thread requests per button click.
            self._hw_model._base_where_sql       = "1=1"
            self._hw_model._base_params          = []
            self._hw_model._has_advanced_filter  = False
            self._hw_model._conditions_cfg       = {}
            self._hw_model._text_search_cfg      = {}
            self._hw_model._text_where_sql       = ""
            self._hw_model._text_params          = []
            self._hw_model._record_id_where_sql  = ""
            self._hw_model._record_id_params     = []
            self._hw_model._invalidate()
        else:
            # Batch: clear all filter layers in one invalidateFilter() call.
            self._active_proxy.clear_all_filters()
            # Also clear per-file tab proxies in one pass each.
            for state in self._file_tabs.values():
                state.proxy.clear_all_filters()

        # 4. Quick column filters — JM only (normal mode handled above)
        if self._hw_model is not None:
            if self._hw_model._quick_filters:
                self._hw_model._quick_filters.clear()
                self._hw_model._quick_where_sql = ""
                self._hw_model._quick_params    = []
                self._hw_model._invalidate()
            # Also clear filters on any open per-file JM tab models
            for _fp, _st in self._file_tabs.items():
                if not _fp.startswith("__chain__"):
                    _st.model.clear_filter()
                    _st.model.clear_quick_filters()

        # 5. Session filter — JM: already cleared in step 3
        #    Normal mode: already cleared by clear_all_filters() above

        # 6. ATT&CK tactic filter — always clear (badge could carry over from normal mode)
        self._active_tactic_filter    = None
        self._active_technique_filter = None
        self._tactic_filter_widget.setVisible(False)

        # 7. Column filter tracking state + header indicators
        self._col_filters.clear()
        self._update_header_indicators()

        # 8. Refresh all badges and count label
        self._update_adv_filter_badge()
        self._update_quick_filter_badge()
        self._update_session_filter_badge(None, None)
        self._update_count_label()

    def _update_adv_filter_badge(self) -> None:
        """Show/hide the 'Filter Active' badge."""
        # Bug 12 fix: in Juggernaut Mode ask hw_model directly
        if self._hw_model is not None:
            active = self._hw_model.has_filter()
        else:
            active = self._active_proxy.has_advanced_filter()
        self._lbl_adv_filter_badge.setVisible(active)
        self._btn_clear_adv.setVisible(active)

    def _update_count_label(self) -> None:
        # Bug 5 fix: in Juggernaut Mode read count from hw_model
        if self._hw_model is not None:
            # Per-file tab: show that file's filtered row count, not the global total
            active_fp = getattr(self, "_active_file_tab", None)
            file_state = self._file_tabs.get(active_fp) if active_fp else None
            if file_state:
                n = file_state.model._total_rows
                self._lbl_count.setText(f"{n:,} events")
                return
            n = self._hw_model.total_event_count()
            self._lbl_count.setText(f"{n:,} events")
            # Warn when Qt silently truncates the display.  rowCount() caps at
            # MAX_QT_SAFE_ROWS (71 M); events beyond that are invisible with no
            # error.  The flag is set by _refresh_count() after each COUNT(*).
            if getattr(self._hw_model, "_display_truncated", False):
                from evtx_tool.gui.heavyweight_model import MAX_QT_SAFE_ROWS
                self._set_status(
                    "⚠ Display truncated",
                    stats=(
                        f"Showing {MAX_QT_SAFE_ROWS:,} of {n:,} events "
                        f"(Qt 71 M row limit — export full dataset via CSV/JSON)"
                    ),
                )
            return
        total    = self._active_model.event_count()
        filtered = self._active_proxy.rowCount()
        if total == filtered:
            self._lbl_count.setText(f"{total:,} events")
        else:
            self._lbl_count.setText(f"{filtered:,} / {total:,} events")

    def _on_row_selected(self) -> None:
        table = self._active_table
        proxy = self._active_proxy
        indexes = table.selectionModel().selectedRows()
        if not indexes:
            return
        proxy_row = indexes[0].row()
        ev = proxy.get_source_event(proxy_row)
        if ev:
            self._render_event_detail(ev)
            self._update_bookmark_button(ev)

    def _on_table_context_menu(self, pos) -> None:
        from PySide6.QtWidgets import QMenu
        table = self._active_table
        proxy = self._active_proxy
        index = table.indexAt(pos)
        if not index.isValid():
            return
        # Bug 1 fix: in JM separate mode use the per-file model (mirrors _on_hw_row_selected)
        if self._hw_model is not None:
            from evtx_tool.gui.heavyweight_model import ArrowTableModel as _ATM
            _am = self._active_table.model()
            _jm_active = _am if isinstance(_am, _ATM) else self._hw_model
            ev = _jm_active.get_event(index.row())
        else:
            _jm_active = None
            ev = proxy.get_source_event(index.row())
        if not ev:
            return

        # Map proxy column to event dict key + display value
        col = index.column()
        col_key_map = {
            0: None,                  # Row # — can't filter
            1: 'event_id',
            2: 'level_name',
            3: 'timestamp',
            4: 'computer',
            5: 'channel',
            6: 'user_id',
            7: None,                  # ATT&CK — handled separately
            8: 'source_file',
        }
        col_key = col_key_map.get(col)
        cell_val = index.data() or ""

        menu = QMenu(self)

        # ── Quick Filter actions (ELE-style) ──────────────────────────────
        if col_key and cell_val:
            col_name = COLUMNS[col] if col < len(COLUMNS) else str(col)
            act_include = menu.addAction(f"⚡ Quick Filter: {col_name} = {cell_val}")
            act_include.triggered.connect(
                lambda checked=False, k=col_key, v=cell_val: self._apply_quick_filter(k, v, True)
            )
            act_exclude = menu.addAction(f"⚡ Quick Filter: {col_name} ≠ {cell_val}")
            act_exclude.triggered.connect(
                lambda checked=False, k=col_key, v=cell_val: self._apply_quick_filter(k, v, False)
            )
            menu.addSeparator()

        # Bug 2 fix: in JM mode check quick filters on the correct underlying model
        if _jm_active is not None:
            _has_qf = _jm_active.has_quick_filters()
            _qf_list = _jm_active.get_quick_filters() if _has_qf else []
        else:
            _has_qf = proxy.has_quick_filters()
            _qf_list = proxy.get_quick_filters() if _has_qf else []
        if _has_qf:
            n = len(_qf_list)
            act_clear = menu.addAction(f"✕ Clear Quick Filters ({n} active)")
            act_clear.triggered.connect(self._clear_quick_filters)
            menu.addSeparator()

        # Bookmark toggle
        rid = ev.get("record_id")
        if rid is not None:
            bm_key = (ev.get("source_file", ""), int(rid))
            is_bm  = bm_key in self._bookmarked_keys
            act_bm = menu.addAction("★ Remove Bookmark" if is_bm else "☆ Bookmark Event")
            act_bm.triggered.connect(lambda checked=False, e=ev: self._bookmark_event(e))
            menu.addSeparator()

        act_copy = menu.addAction("Copy Row as Text")
        act_copy.triggered.connect(lambda: self._copy_event_row(ev))

        menu.exec(table.viewport().mapToGlobal(pos))

    def _apply_quick_filter(self, key: str, value: str, include: bool) -> None:
        """Add a Quick Filter and update the UI."""
        # In separate-tabs mode ask which files to target
        if self._view_mode == "separate":
            target_tabs = self._filter_target_tabs()
            if target_tabs:
                scope_dlg = _FilterTargetDialog(target_tabs, self)
                if scope_dlg.exec() != QDialog.DialogCode.Accepted:
                    return
                is_jm = self._hw_model is not None
                for fp in scope_dlg.selected():
                    if fp == "__all_events__":
                        if is_jm:
                            self._hw_model.add_quick_filter(key, value, include)
                        else:
                            self._proxy_model.add_quick_filter(key, value, include)
                        continue
                    state = self._file_tabs.get(fp)
                    if state is None:
                        continue
                    if is_jm:
                        state.model.add_quick_filter(key, value, include)
                    else:
                        state.proxy.add_quick_filter(key, value, include)
                self._update_quick_filter_badge()
                self._update_count_label()
                return

        # Merged mode — apply to active model as before
        if self._hw_model is not None:
            self._hw_model.add_quick_filter(key, value, include)
            self._update_quick_filter_badge()
            self._update_count_label()
            return
        self._active_proxy.add_quick_filter(key, value, include)
        self._update_quick_filter_badge()
        self._update_count_label()

    def _clear_quick_filters(self) -> None:
        """Remove all quick filters and update the UI."""
        if self._hw_model is not None:
            # Bug 4 fix: clear merged model AND all per-file JM tab models
            self._hw_model.clear_quick_filters()
            for _st in self._file_tabs.values():
                _st.model.clear_quick_filters()
        else:
            # Bug 5 fix: clear merged proxy AND all per-file tab proxies
            self._proxy_model.clear_quick_filters()
            for _st in self._file_tabs.values():
                _st.proxy.clear_quick_filters()
        self._update_quick_filter_badge()
        self._update_count_label()

    # ── Session filter ─────────────────────────────────────────────────────

    def _on_show_logon_sessions(self) -> None:
        """Open the Logon Session Browser dialog (non-modal)."""
        if self._hw_model is not None:
            self._on_show_logon_sessions_jm()
            return
        events = self._active_events
        if not events:
            QMessageBox.information(self, "Logon Sessions", "No events loaded.")
            return
        dlg = _LogonSessionDialog(
            events=events,
            on_filter_fn=self._set_session_filter,
            parent=self,
        )
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    # ── Juggernaut Mode — post-parse analysis (Hayabusa) ─────────────────────

    def _jm_launch_analysis(self, parquet_dir: str) -> None:
        """
        Kick off Hayabusa analysis in JM mode — subprocess against the original
        .evtx files, zero extra RAM. Gated by the Hayabusa checkbox.
        """
        do_hayabusa = self._chk_hayabusa.isChecked() and bool(self._hayabusa_path)

        if not do_hayabusa:
            return   # nothing to do

        evtx_files = getattr(self, "_last_parsed_files", []) or []

        if do_hayabusa and evtx_files:
            self._set_status("Analysing…", stats="Hayabusa: queued")
            self._btn_stop.setEnabled(True)
            self._ioc_pivot_map = {}
            self._analysis_runner = AnalysisRunner(parent=self)
            self._analysis_runner.progress.connect(self._on_analysis_progress)
            self._analysis_runner.component_progress.connect(self._on_component_progress)
            self._analysis_runner.finished.connect(self._on_analysis_finished)
            self._analysis_runner.error.connect(self._on_analysis_error)
            # Pass empty events list — Hayabusa only needs evtx_paths
            self._analysis_runner.start(
                events=[],
                do_ioc=False,
                do_correlate=False,
                do_hayabusa=True,
                hayabusa_path=self._hayabusa_path,
                evtx_paths=evtx_files,
            )

    def _on_show_logon_sessions_jm(self) -> None:
        """Juggernaut Mode implementation of the Logon Session Browser."""
        import json as _json
        import duckdb as _duckdb

        parquet_dir = getattr(self, "_hw_db_path", None)
        if not parquet_dir:
            QMessageBox.information(self, "Logon Sessions", "No events loaded.")
            return

        manifest_path = os.path.join(parquet_dir, "parquet_manifest.json")
        try:
            with open(manifest_path, "r", encoding="utf-8") as _f:
                shards = _json.load(_f)
        except Exception:
            QMessageBox.information(self, "Logon Sessions", "No events loaded.")
            return

        if not shards:
            QMessageBox.information(self, "Logon Sessions", "No events loaded.")
            return

        # Escape shard paths for DuckDB list literal
        shard_list = "[" + ", ".join(f"'{p.replace(chr(39), chr(39)*2)}'" for p in shards) + "]"

        # Query only the 4 logon-related event types (fast — column-pruned Parquet scan)
        try:
            _con = _duckdb.connect()
            _rows = _con.execute(
                f"SELECT record_id, event_id, computer, timestamp_utc, event_data_json "
                f"FROM parquet_scan({shard_list}) "
                f"WHERE event_id IN (4624, 4634, 4672, 4688) "
                f"ORDER BY timestamp_utc"
            ).fetchall()
            _con.close()
        except Exception as exc:
            QMessageBox.warning(self, "Logon Sessions",
                                f"Failed to query Parquet shards:\n{exc}")
            return

        if not _rows:
            QMessageBox.information(
                self, "Logon Sessions",
                "No logon events (4624 / 4634 / 4672 / 4688) found in the loaded files."
            )
            return

        # Build event dicts in the format _LogonSessionDialog._build_sessions() expects.
        # Also accumulate logon_id → set[record_id] for fast filter pre-seeding.
        _LOGON_ID_SKIP = _LogonSessionDialog._SKIP_IDS
        events: list[dict] = []
        _lid_to_rids: dict[str, set] = {}

        for rec_id, ev_id, computer, ts_utc, ed_json in _rows:
            try:
                ed = _json.loads(ed_json) if ed_json else {}
            except Exception:
                ed = {}
            events.append({
                "event_id":   ev_id,
                "computer":   computer or "",
                "timestamp":  str(ts_utc or ""),
                "event_data": ed,
                "_record_id": rec_id,
            })
            # Collect logon_id → record_id mapping
            if ev_id in (4624, 4634):
                lid = str(ed.get("TargetLogonId", "")).strip()
            else:
                lid = str(ed.get("SubjectLogonId", "")).strip()
            if lid and lid not in _LOGON_ID_SKIP:
                _lid_to_rids.setdefault(lid, set()).add(rec_id)

        # Capture for closure
        _shard_list_captured = shard_list
        _hw_model = self._hw_model

        def _jm_session_filter(logon_id: str | None, session_info: dict | None) -> None:
            if logon_id is None:
                _hw_model.clear_record_id_filter()
                self._update_session_filter_badge(None, None)
                self._update_count_label()
                return

            # Query ALL events from Parquet whose event_data references this logon_id.
            # This is done once per user click so latency is acceptable.
            try:
                _lid_esc = logon_id.replace("'", "''")
                _c = _duckdb.connect()
                _rid_rows = _c.execute(
                    f"SELECT record_id FROM parquet_scan({_shard_list_captured}) "
                    f"WHERE json_extract_string(event_data_json, '$.TargetLogonId') = '{_lid_esc}' "
                    f"   OR json_extract_string(event_data_json, '$.SubjectLogonId') = '{_lid_esc}'"
                ).fetchall()
                _c.close()
                rid_set = frozenset(r[0] for r in _rid_rows if r[0] is not None)
            except Exception:
                # Fallback: use only the pre-seeded record IDs from the 4 event types
                rid_set = frozenset(_lid_to_rids.get(logon_id, set()))

            if not rid_set:
                QMessageBox.information(self, "Logon Sessions",
                                        f"No events found for LogonId {logon_id}.")
                return

            _hw_model.apply_record_id_filter(rid_set)
            self._update_session_filter_badge(logon_id, session_info)
            self._update_count_label()

        dlg = _LogonSessionDialog(
            events=events,
            on_filter_fn=_jm_session_filter,
            parent=self,
        )
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _set_session_filter(self, logon_id: str | None, session_info: dict | None) -> None:
        """Apply or clear the session LogonId filter on all proxy models."""
        # Apply to merged proxy
        self._proxy_model.set_session_filter(logon_id)
        # Apply to all separate-file tab proxies
        for state in self._file_tabs.values():
            state.proxy.set_session_filter(logon_id)
        self._update_session_filter_badge(logon_id, session_info)
        self._update_count_label()

    def _clear_session_filter(self) -> None:
        """Clear the session filter from all proxies and hide the badge."""
        if self._hw_model is not None:
            # Juggernaut mode — filter lives on the ArrowTableModel
            self._hw_model.clear_record_id_filter()
            self._update_session_filter_badge(None, None)
            self._update_count_label()
            return
        self._set_session_filter(None, None)

    def _update_session_filter_badge(self, logon_id: str | None, session_info: dict | None) -> None:
        """Show or hide the session filter indicator bar."""
        if logon_id and session_info:
            user       = session_info.get("user") or "?"
            type_label = session_info.get("logon_type_label") or "?"
            start      = (session_info.get("start_ts") or "").replace("T", " ")[:19]
            duration   = session_info.get("duration") or ""
            dur_part   = f"  duration {duration}" if duration else ""
            self._lbl_session_filter.setText(
                f"\U0001f510 Session filter:  {user}  \u2022  {type_label}"
                f"  \u2022  LogonId {logon_id}  \u2022  started {start}{dur_part}"
            )
            self._session_filter_widget.setVisible(True)
        else:
            self._session_filter_widget.setVisible(False)

    def _update_quick_filter_badge(self) -> None:
        """Show/hide the Quick Filter indicator bar."""
        if self._hw_model is not None:
            # Check merged model first; also check the active per-file tab's model
            # because Bug 4 fix allows quick filters to live on per-file models too.
            active = self._hw_model.has_quick_filters()
            if not active and self._active_file_tab:
                state = self._file_tabs.get(self._active_file_tab)
                if state:
                    active = state.model.has_quick_filters()
            self._quick_filter_widget.setVisible(active)
            return
        active = self._active_proxy.has_quick_filters()
        self._quick_filter_widget.setVisible(active)

    def _copy_event_row(self, ev: dict) -> None:
        text = (
            f"{ev.get('timestamp','')}  "
            f"EID:{ev.get('event_id','')}  "
            f"{ev.get('level_name','')}  "
            f"{ev.get('computer','')}  "
            f"{ev.get('channel','')}"
        )
        QApplication.clipboard().setText(text)

    # =========================================================================
    # EVENT DETAIL
    # =========================================================================

    @staticmethod
    def _flatten_ev_val(v) -> str | None:
        """
        Flatten a complex event_data value to a plain display string.
        Returns None when the value should be skipped (None / empty).

        Handles the shapes pyevtx-rs produces for un-named <Data> elements:
          {'#text': ['v1','v2']}  →  'v1\nv2'
          {'#text': 'v'}          →  'v'
          ['v1', 'v2']            →  'v1\nv2'
          None                    →  None  (skip)
          'plain string'          →  'plain string'
        """
        if v is None:
            return None
        if isinstance(v, dict):
            text = v.get("#text")
            if text is not None:
                if isinstance(text, list):
                    parts = [str(x) for x in text if x is not None and str(x).strip()]
                    return "\n".join(parts) or None
                s = str(text).strip()
                return s or None
            # dict without #text — show non-# keys only
            non_hash = {k2: v2 for k2, v2 in v.items()
                        if not k2.startswith("#") and v2 is not None}
            return str(non_hash) if non_hash else None
        if isinstance(v, list):
            parts = [str(x) for x in v if x is not None and str(x).strip()]
            return "\n".join(parts) or None
        s = str(v).strip()
        return s or None

    def _render_event_detail(self, ev: dict) -> None:
        # Skip re-render when the same event + display mode is already shown.
        detail_key = (ev.get("record_id"), ev.get("source_file"), self._detail_full_mode)
        if detail_key == self._last_detail_key:
            return
        self._last_detail_key = detail_key

        C = COLORS
        ts  = apply_tz(ev.get("timestamp", ""))
        eid = ev.get("event_id", "")
        lvl = ev.get("level_name", "")
        lvl_colors = {
            "Critical": C["level_critical"], "Error": C["level_error"],
            "Warning": C["level_warning"], "Information": C["level_info"],
            "Verbose": C["level_verbose"],
        }
        lvl_color = lvl_colors.get(lvl, C["text_dim"])

        def _kv(label: str, value, color=None) -> str:
            """
            Render one 'Label: value' line.
            Skips only when value is None or truly empty string.
            0, '0', False etc. are shown — they are meaningful field values.
            """
            if value is None:
                return ""
            v = str(value).strip()
            if v == "":
                return ""
            vc = color or C["text"]
            return (
                f"<span style='color:{C['text_dim']}'>{_escape_html(label)}: </span>"
                f"<span style='color:{vc}'>{_escape_html(v)}</span>"
            )

        def _hr() -> str:
            return f"<hr style='border:1px solid {C['border']};margin:4px 0'>"

        def _section(title: str) -> str:
            return f"<span style='color:{C['text_dim']};font-size:8pt'>{title}</span>"

        # ── Header (always shown in both Brief and Full modes) ─────────────────
        lines: list[str] = [
            f"<span style='color:{C['accent_hover']};font-weight:bold'>EventID: {eid}</span>"
            f"&nbsp;&nbsp;&nbsp;"
            f"<span style='color:{lvl_color}'>{_escape_html(lvl)}</span>"
            f"&nbsp;&nbsp;&nbsp;"
            f"<span style='color:{C['text_dim']}'>{_escape_html(ts)}</span>",

            f"<span style='color:{C['text_dim']}'>Computer: </span>"
            f"<span style='color:{C['text']}'>{_escape_html(ev.get('computer',''))}</span>"
            f"&nbsp;&nbsp;"
            f"<span style='color:{C['text_dim']}'>Channel: </span>"
            f"<span style='color:{C['text']}'>{_escape_html(ev.get('channel',''))}</span>",

            f"<span style='color:{C['text_dim']}'>Provider: </span>"
            f"<span style='color:{C['text']}'>{_escape_html(ev.get('provider',''))}</span>"
            f"&nbsp;&nbsp;"
            f"<span style='color:{C['text_dim']}'>RecordID: </span>"
            f"<span style='color:{C['text']}'>{ev.get('record_id','')}</span>",

            f"<span style='color:{C['text_dim']}'>Source: </span>"
            f"<span style='color:{C['text_muted']}'>"
            f"{_escape_html(os.path.basename(ev.get('source_file','')))}</span>",
        ]

        # ── Brief mode stops here ──────────────────────────────────────────────
        if not self._detail_full_mode:
            # Context-aware event description
            try:
                from evtx_tool.analysis.event_descriptions import get_event_description
                desc = get_event_description(ev)
            except Exception:
                desc = None
            if desc:
                lines.append(_hr())
                lines.append(_section("DESCRIPTION"))
                lines.append(
                    f"<span style='color:{C['text']}'>{_escape_html(desc)}</span>"
                )
            html = (
                f"<div style='font-family:Consolas,monospace;font-size:9pt;"
                f"padding:8px;color:{C['text']};background:{C['bg_main']};'>"
                + "<br>".join(lines)
                + "</div>"
            )
            self._detail_browser.setHtml(html)
            return

        # ── SYSTEM METADATA ───────────────────────────────────────────────────
        meta_lines: list[str] = []

        # Identity / security
        for row in [
            _kv("User ID",       ev.get("user_id")),
            _kv("Provider GUID", ev.get("provider_guid")),
            _kv("Qualifiers",    ev.get("qualifiers")),
            _kv("Correlation ID",ev.get("correlation_id")),
        ]:
            if row:
                meta_lines.append(row)

        # Execution context
        exec_info = ev.get("execution") or {}
        pid = ev.get("process_id") if ev.get("process_id") is not None else exec_info.get("process_id")
        tid = ev.get("thread_id")  if ev.get("thread_id")  is not None else exec_info.get("thread_id")
        for row in [
            _kv("Process ID",    pid),
            _kv("Thread ID",     tid),
            _kv("Processor ID",  ev.get("processor_id")),
            _kv("Session ID",    ev.get("session_id")),
        ]:
            if row:
                meta_lines.append(row)

        # Timing
        for row in [
            _kv("Kernel Time",    ev.get("kernel_time")),
            _kv("User Time",      ev.get("user_time")),
            _kv("Processor Time", ev.get("processor_time")),
        ]:
            if row:
                meta_lines.append(row)

        # Event classification
        kw_raw  = ev.get("keywords")
        kw_desc = ev.get("keywords_desc")
        kw_disp = (
            f"{kw_raw}  [{kw_desc}]" if kw_raw is not None and kw_desc
            else kw_raw
        )
        for row in [
            _kv("Version",  ev.get("version")),
            _kv("Task",     ev.get("task")),
            _kv("Opcode",   ev.get("opcode")),
            _kv("Keywords", kw_disp),
            _kv("Log",      ev.get("log")),
        ]:
            if row:
                meta_lines.append(row)

        lines.append(_hr())
        lines.append(_section("SYSTEM METADATA"))
        if meta_lines:
            lines.extend(meta_lines)
        else:
            lines.append(f"<span style='color:{C['text_muted']}'>(no metadata)</span>")

        # ── EVENT DATA ────────────────────────────────────────────────────────
        lines.append(_hr())
        lines.append(_section("EVENT DATA"))
        edata = ev.get("event_data") or {}

        # Load semantic field→desc_key mapping (non-fatal if normalizer absent)
        try:
            from evtx_tool.analysis.normalizer import ED_FIELD_TO_DESC as _ed_to_desc
        except ImportError:
            _ed_to_desc = {}

        if edata:
            for k, raw_v in edata.items():
                flat = self._flatten_ev_val(raw_v)
                if flat is None:
                    continue          # skip None / empty values (e.g. <Binary/>)

                # Look up whether this field has a semantic description
                desc_key = _ed_to_desc.get(str(k).strip().lower())
                desc_val = str(ev.get(desc_key, "")).strip() if desc_key else ""

                key_html = f"<span style='color:{C['text_dim']}'>{_escape_html(str(k))}</span>"
                sep_html = f"<span style='color:{C['border']}'> : </span>"

                if "\n" in flat:
                    # Multi-value / PrivilegeList — show one sub-line per entry.
                    # If a translated desc exists (e.g. privilege_list_desc already
                    # embeds "(Description)" per line), use it directly so users see
                    # the human-readable version; otherwise fall back to raw lines.
                    lines.append(key_html + sep_html)
                    display_lines = desc_val.split("\n") if desc_val else flat.split("\n")
                    for part in display_lines:
                        lines.append(
                            f"&nbsp;&nbsp;&nbsp;"
                            f"<span style='color:{C['text']}'>{_escape_html(part)}</span>"
                        )
                else:
                    val_html = f"<span style='color:{C['text']}'>{_escape_html(flat)}</span>"
                    if desc_val:
                        # Append semantic annotation inline: rawval  →  [Description]
                        anno_html = (
                            f"&nbsp;&nbsp;"
                            f"<span style='color:{C['border']}'>→</span>&nbsp;"
                            f"<span style='color:{C['accent_hover']}'>"
                            f"{_escape_html(desc_val)}</span>"
                        )
                        lines.append(key_html + sep_html + val_html + anno_html)
                    else:
                        lines.append(key_html + sep_html + val_html)
        else:
            lines.append(f"<span style='color:{C['text_muted']}'>(no event data)</span>")

        # ── ATT&CK TAGS ───────────────────────────────────────────────────────
        tags = ev.get("attack_tags") or []
        if tags:
            lines.append(_hr())
            lines.append(_section("ATT&CK TAGS"))
            for tag in tags:
                conf = tag.get("attack_confidence", "")
                conf_color = {
                    "high":   C.get("chain_high",   "#e74c3c"),
                    "medium": C.get("chain_medium",  "#e67e22"),
                    "low":    C.get("chain_low",     "#7f8c8d"),
                }.get(conf, C["text_dim"])
                conf_badge = (
                    f" <span style='color:{conf_color};font-size:8pt'>"
                    f"[{_escape_html(conf)}]</span>"
                ) if conf else ""
                lines.append(
                    f"<span style='color:{C['attack_badge']};font-weight:bold'>"
                    f"[{_escape_html(tag.get('tid',''))}]</span>"
                    f" <span style='color:{C['text']}'>{_escape_html(tag.get('name',''))}</span>"
                    f" <span style='color:{C['text_dim']}'>→ {_escape_html(tag.get('tactic',''))}</span>"
                    f"{conf_badge}"
                )

        html = (
            f"<div style='font-family:Consolas,monospace;font-size:9pt;"
            f"padding:8px;color:{C['text']};background:{C['bg_main']};'>"
            + "<br>".join(lines)
            + "</div>"
        )
        self._detail_browser.setHtml(html)

    def _on_detail_mode_toggled(self, brief: bool) -> None:
        """Called when the Brief/Full toggle button is clicked."""
        self._detail_full_mode = not brief
        self._btn_detail_mode.setText("Brief" if not brief else "Full")
        # Re-render the currently selected event (if any)
        try:
            sel = self._active_table.selectionModel().selectedRows()
            if sel:
                if self._hw_model is not None:
                    # JM mode — use active tab's ArrowTableModel or merged hw_model
                    from evtx_tool.gui.heavyweight_model import ArrowTableModel as _ATM
                    active_model = self._active_table.model()
                    model = active_model if isinstance(active_model, _ATM) else self._hw_model
                    ev = model.get_event(sel[0].row())
                else:
                    ev = self._active_proxy.get_source_event(sel[0].row())
                if ev:
                    self._render_event_detail(ev)
        except Exception:
            pass

    # =========================================================================
    # ANALYSIS TABS — POPULATE
    # =========================================================================

    # ── Analysis scope toggle ─────────────────────────────────────────────────

    def _on_analysis_scope_changed(self, text: str) -> None:
        """Called when the user switches 'This File' / 'All Files' scope."""
        self._analysis_scope = "file" if text == "This File" else "all"
        QTimer.singleShot(0,  self._refresh_attack_tab)
        QTimer.singleShot(50, self._refresh_iocs_tab)

    @staticmethod
    def _derive_attack_summary(events: list[dict]) -> dict | None:
        """
        Compute a lightweight ATT&CK summary dict from an event list.
        Returns None if no events have attack_tags.
        """
        by_tactic: dict[str, int] = {}
        by_technique: dict[str, dict] = {}
        for ev in events:
            for tag in (ev.get("attack_tags") or []):
                tactic = tag.get("tactic", "").lower()
                tid    = tag.get("tid", "")
                name   = tag.get("name", "") or tag.get("technique_name", "") or tid
                if tactic:
                    by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
                if tid:
                    if tid not in by_technique:
                        by_technique[tid] = {"name": name, "tactic": tactic, "count": 0}
                    by_technique[tid]["count"] += 1
        total = sum(by_tactic.values())
        if total == 0:
            return None
        return {"total_tagged": total, "by_tactic": by_tactic, "by_technique": by_technique}

    # ── ATT&CK tab populate ───────────────────────────────────────────────────

    def _refresh_attack_tab(self) -> None:
        # Resolve which attack summary to show based on view mode + scope
        if (self._view_mode == "separate"
                and self._analysis_scope == "file"
                and self._active_file_tab):
            state = self._file_tabs.get(self._active_file_tab)
            if state:
                # Lazy-cache: compute once per file tab, reuse on subsequent switches
                if state.attack_summary is None:
                    state.attack_summary = self._derive_attack_summary(state.events)
                atk = state.attack_summary
            else:
                atk = None
        else:
            atk = self._attack_summary
        self._tbl_attack.setRowCount(0)
        if not atk:
            self._lbl_attack_summary.setText("No ATT&CK data — run with ATT&CK Mapping enabled.")
            return

        total = atk.get("total_tagged", 0)
        by_tactic = atk.get("by_tactic", {})
        by_technique = atk.get("by_technique", {})
        self._lbl_attack_summary.setText(
            f"{total:,} events tagged  |  "
            f"{len(by_tactic)} tactics  |  {len(by_technique)} techniques"
        )

        # Sort tactics by event count descending
        tactic_order = sorted(by_tactic.items(), key=lambda x: -x[1])
        self._tbl_attack.setRowCount(len(tactic_order))

        tactic_colors = {
            "initial access": COLORS["ta_initial"], "execution": COLORS["ta_exec"],
            "persistence": COLORS["ta_persist"], "privilege escalation": COLORS["ta_privesc"],
            "defense evasion": COLORS["ta_defense"], "credential access": COLORS["ta_cred"],
            "discovery": COLORS["ta_discovery"], "lateral movement": COLORS["ta_lateral"],
            "collection": COLORS["ta_collect"], "command and control": COLORS["ta_c2"],
            "exfiltration": COLORS["ta_exfil"], "impact": COLORS["ta_impact"],
            "reconnaissance": COLORS["ta_recon"], "resource development": COLORS["ta_resource"],
        }

        for row, (tactic, count) in enumerate(tactic_order):
            color = tactic_colors.get(tactic.lower(), COLORS["text_dim"])

            # Top technique for this tactic
            top_tech = max(
                [(tid, info) for tid, info in by_technique.items() if info.get("tactic","").lower() == tactic.lower()],
                key=lambda x: x[1].get("count", 0),
                default=(None, {}),
            )

            tactic_item = QTableWidgetItem(tactic.title())
            tactic_item.setForeground(QColor(color))
            self._tbl_attack.setItem(row, 0, tactic_item)
            self._tbl_attack.setItem(row, 1, QTableWidgetItem(f"{count:,}"))
            if top_tech[0]:
                self._tbl_attack.setItem(row, 2, QTableWidgetItem(top_tech[1].get("name", "")))
                tid_item = QTableWidgetItem(top_tech[0])
                tid_item.setForeground(QColor(COLORS["attack_badge"]))
                self._tbl_attack.setItem(row, 3, tid_item)

        self._tbl_attack.resizeColumnToContents(1)
        self._tbl_attack.resizeColumnToContents(3)

    def _refresh_iocs_tab(self) -> None:
        from PySide6.QtGui import QColor, QFont

        # Clear existing sub-tabs
        while self._ioc_tabs.count():
            self._ioc_tabs.removeTab(0)

        iocs = self._iocs
        if not iocs:
            self._lbl_ioc_summary.setText("No IOC data — run with IOC Extraction enabled.")
            self._btn_export_iocs.setEnabled(False)
            self._btn_threat_intel.setEnabled(False)
            return

        # Ordered display list (label, ioc_type_key)
        ioc_types = [
            ("IPv4",        "ipv4"),
            ("IPv6",        "ipv6"),
            ("Domains",     "domains"),
            ("URLs",        "urls"),
            ("SHA-256",     "sha256"),
            ("SHA-1",       "sha1"),
            ("MD5",         "md5"),
            ("Processes",   "processes"),
            ("CmdLines",    "commandlines"),
            ("Registry",    "registry"),
            ("Paths",       "filepaths"),
            ("Services",    "services"),
            ("Tasks",       "tasks"),
            ("Named Pipes", "named_pipes"),
            ("Shares",      "shares"),
            ("DLLs",        "dlls"),
            ("Users",       "users"),
            ("Computers",   "computers"),
        ]

        total = sum(len(iocs.get(k) or []) for _, k in ioc_types)
        self._lbl_ioc_summary.setText(
            f"{total:,} unique IOC values  —  "
            "double-click to pivot  |  right-click to copy  |  Export for full list"
        )
        has_data = total > 0
        self._btn_export_iocs.setEnabled(has_data)
        self._btn_threat_intel.setEnabled(has_data)

        # Score-based row background colors
        _COL_LOW    = QColor("#1a2a1a")   # dark green tint — score 0-30
        _COL_MED    = QColor("#2a2200")   # dark yellow tint — score 31-60
        _COL_HIGH   = QColor("#2a1010")   # dark red tint — score 61-100
        _COL_NORMAL = QColor(0, 0, 0, 0)  # transparent (alternating handled by widget)

        _bold = QFont()
        _bold.setBold(True)

        for label, key in ioc_types:
            entries = iocs.get(key) or []
            if not entries:
                continue

            cols = ["Value", "Count", "First Seen", "Last Seen", "Score"]
            tbl = QTableWidget(len(entries), len(cols))
            tbl.setHorizontalHeaderLabels(cols)
            tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            tbl.setAlternatingRowColors(True)
            _ioc_hdr = tbl.horizontalHeader()
            _ioc_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)  # all cols user-draggable
            _ioc_hdr.setStretchLastSection(False)
            for _ci, _cw in enumerate([280, 60, 140, 140, 55]):
                tbl.setColumnWidth(_ci, _cw)
            tbl.verticalHeader().setVisible(False)
            tbl.setShowGrid(False)
            tbl.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            tbl.customContextMenuRequested.connect(
                lambda pos, t=tbl, k=key: self._ioc_table_context_menu(pos, t, k)
            )
            tbl.cellDoubleClicked.connect(
                lambda row, col, t=tbl, k=key: self._ioc_pivot_from_table(t, row, k)
            )

            for r, entry in enumerate(entries):
                if isinstance(entry, dict):
                    value    = entry.get("value", "")
                    count    = entry.get("count", 1)
                    first    = (entry.get("first_seen") or "")[:19]
                    last     = (entry.get("last_seen")  or "")[:19]
                    score    = entry.get("score", 0)
                    reasons  = entry.get("score_reasons") or []
                    ti       = entry.get("threat_intel")
                else:
                    value = str(entry)
                    count, first, last, score, reasons, ti = 1, "", "", 0, [], None

                # Threat intel prefix on value
                display_val = value
                ti_tooltip  = ""
                if ti:
                    verdict = ti.get("verdict", "")
                    if verdict in ("malicious",):
                        display_val = "⚠ " + value
                    elif verdict in ("suspicious", "potentially_malicious"):
                        display_val = "⚠ " + value
                    elif verdict == "clean":
                        display_val = "✓ " + value
                    pos_str = ""
                    if ti.get("positives") is not None:
                        pos_str = f" ({ti.get('positives', '?')}/{ti.get('total', '?')} engines)"
                    ti_tooltip = f"[{ti.get('source','?')}] {verdict}{pos_str}"
                    if ti.get("permalink"):
                        ti_tooltip += f"\n{ti.get('permalink', '')}"

                # Value item
                val_item = QTableWidgetItem(display_val)
                val_item.setData(Qt.ItemDataRole.UserRole, value)  # raw value for pivot
                if ti_tooltip:
                    val_item.setToolTip(ti_tooltip)
                if ti and ti.get("verdict") in ("malicious", "suspicious", "potentially_malicious"):
                    val_item.setForeground(QColor("#e74c3c"))
                    val_item.setFont(_bold)
                tbl.setItem(r, 0, val_item)

                # Count
                cnt_item = QTableWidgetItem(str(count))
                cnt_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                tbl.setItem(r, 1, cnt_item)

                # First/Last seen
                tbl.setItem(r, 2, QTableWidgetItem(first))
                tbl.setItem(r, 3, QTableWidgetItem(last))

                # Score
                score_item = QTableWidgetItem(str(score))
                score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if reasons:
                    score_item.setToolTip("\n".join(reasons))
                if score >= 61:
                    score_item.setForeground(QColor("#e74c3c"))
                    score_item.setFont(_bold)
                    row_color = _COL_HIGH
                elif score >= 31:
                    score_item.setForeground(QColor("#e67e22"))
                    row_color = _COL_MED
                else:
                    row_color = _COL_NORMAL
                tbl.setItem(r, 4, score_item)

                # Row background tint for high/medium score
                if row_color != _COL_NORMAL:
                    for ci in range(len(cols)):
                        item = tbl.item(r, ci)
                        if item:
                            item.setBackground(row_color)

            self._ioc_tabs.addTab(tbl, f"{label} ({len(entries):,})")

        # ── Correlation tab ────────────────────────────────────────────────
        corr = iocs.get("correlation", {})
        pairs = corr.get("pairs", []) if isinstance(corr, dict) else []
        if pairs:
            corr_cols = ["IOC A Value", "Type A", "IOC B Value", "Type B", "Shared Context"]
            corr_tbl = QTableWidget(len(pairs), len(corr_cols))
            corr_tbl.setHorizontalHeaderLabels(corr_cols)
            corr_tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            corr_tbl.setAlternatingRowColors(True)
            _corr_hdr = corr_tbl.horizontalHeader()
            _corr_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)  # all cols user-draggable
            _corr_hdr.setStretchLastSection(False)
            for _ci, _cw in enumerate([200, 80, 200, 80, 160]):
                corr_tbl.setColumnWidth(_ci, _cw)
            corr_tbl.verticalHeader().setVisible(False)
            corr_tbl.setShowGrid(False)
            corr_tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            corr_tbl.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            corr_tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            corr_tbl.customContextMenuRequested.connect(
                lambda pos, t=corr_tbl: self._corr_table_context_menu(pos, t)
            )

            _CONF_COLOR = {
                "high":   QColor("#e74c3c"),
                "medium": QColor("#e67e22"),
                "low":    QColor("#8b949e"),
            }
            for r, pair in enumerate(pairs):
                corr_tbl.setItem(r, 0, QTableWidgetItem(str(pair.get("value_a", ""))))
                corr_tbl.setItem(r, 1, QTableWidgetItem(str(pair.get("type_a",  ""))))
                corr_tbl.setItem(r, 2, QTableWidgetItem(str(pair.get("value_b", ""))))
                corr_tbl.setItem(r, 3, QTableWidgetItem(str(pair.get("type_b",  ""))))
                shared_item = QTableWidgetItem(
                    f"{pair.get('shared_context', 0)}  [{pair.get('confidence', '')}]"
                )
                shared_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                conf_col = _CONF_COLOR.get(pair.get("confidence", ""), QColor("#8b949e"))
                shared_item.setForeground(conf_col)
                corr_tbl.setItem(r, 4, shared_item)

            self._ioc_tabs.addTab(corr_tbl, f"🔗 Correlation ({len(pairs):,})")

    # ── IOC pivot / threat intel ──────────────────────────────────────────────

    def _ioc_pivot_from_table(self, tbl: QTableWidget, row: int, ioc_type: str) -> None:
        """Double-click handler: pivot main event table to show events for this IOC."""
        item = tbl.item(row, 0)
        if not item:
            return
        # Prefer the stored raw value (UserRole) over display text (which may have ⚠ prefix)
        raw = item.data(Qt.ItemDataRole.UserRole) or item.text()
        if raw.startswith(("⚠ ", "✓ ")):
            raw = raw[2:]
        self._ioc_pivot_to_events(ioc_type, raw.strip())

    def _ioc_pivot_to_events(self, ioc_type: str, value: str) -> None:
        """Filter the main event table to the exact events that produced this IOC.

        Looks up the frozenset of record_ids from self._ioc_pivot_map, which is
        built at analysis completion from the extractor's record_ids field.
        The event count shown will always match the IOC count exactly.

        If the map has no entry for this IOC (analysis not yet run, or run with
        code that predates record_id tracking), shows a status message and returns
        without changing the filter — never falls back to text search.
        """
        if not value:
            return

        id_set = self._ioc_pivot_map.get((ioc_type, value))
        if not id_set:
            self._set_status(
                "IOC pivot: no event links available — "
                "re-run IOC Analysis to enable exact event filtering"
            )
            return

        if self._hw_model is not None:
            self._hw_model.apply_record_id_filter(id_set)
        else:
            self._active_proxy.set_record_id_filter(id_set)

        self._update_count_label()
        n = len(id_set)
        self._set_status(
            f"IOC pivot: {ioc_type}={value!r}  "
            f"({n} exact event{'s' if n != 1 else ''})"
        )

    def _on_threat_intel_clicked(self) -> None:
        """Open the Threat Intelligence enrichment dialog."""
        if not self._iocs:
            return
        try:
            from evtx_tool.gui.threat_intel_dialog import ThreatIntelDialog
            dlg = ThreatIntelDialog(parent=self)
            dlg.exec()
        except Exception as exc:
            QMessageBox.critical(self, "Threat Intel Error", str(exc))

    # ── IOC right-click context menu ──────────────────────────────────────────

    def _ioc_table_context_menu(self, pos, tbl: QTableWidget, ioc_type: str = "") -> None:
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)

        # Get current row's value
        cur_row = tbl.currentRow()
        cur_item = tbl.item(cur_row, 0) if cur_row >= 0 else None
        cur_val = ""
        if cur_item:
            cur_val = cur_item.data(Qt.ItemDataRole.UserRole) or cur_item.text()
            if cur_val.startswith(("⚠ ", "✓ ")):
                cur_val = cur_val[2:]

        act_pivot    = menu.addAction("🔍  Pivot to Events")
        act_pivot.setEnabled(bool(cur_val))
        act_copy_tv  = menu.addAction("📋  Copy as type:value")
        act_copy_tv.setEnabled(bool(cur_val and ioc_type))
        menu.addSeparator()
        act_copy     = menu.addAction("Copy Selected")
        act_copy_all = menu.addAction("Copy All in This Tab")
        action = menu.exec(tbl.mapToGlobal(pos))

        if action == act_pivot and cur_val:
            self._ioc_pivot_to_events(ioc_type, cur_val)

        elif action == act_copy_tv and cur_val:
            from evtx_tool.output.ioc_formats import _BULK_TYPE_PREFIX
            prefix = _BULK_TYPE_PREFIX.get(ioc_type, ioc_type)
            QApplication.clipboard().setText(f"{prefix}:{cur_val}")

        elif action == act_copy:
            rows = sorted({idx.row() for idx in tbl.selectedIndexes()})
            lines = []
            for r in rows:
                it = tbl.item(r, 0)
                if it:
                    v = it.data(Qt.ItemDataRole.UserRole) or it.text()
                    if v.startswith(("⚠ ", "✓ ")):
                        v = v[2:]
                    lines.append(v)
            if lines:
                QApplication.clipboard().setText("\n".join(lines))

        elif action == act_copy_all:
            lines = []
            for r in range(tbl.rowCount()):
                it = tbl.item(r, 0)
                if it:
                    v = it.data(Qt.ItemDataRole.UserRole) or it.text()
                    if v.startswith(("⚠ ", "✓ ")):
                        v = v[2:]
                    lines.append(v)
            if lines:
                QApplication.clipboard().setText("\n".join(lines))

    def _corr_table_context_menu(self, pos, tbl: QTableWidget) -> None:
        """Right-click context menu for the Correlation table (tab-separated multi-column copy)."""
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        act_copy     = menu.addAction("Copy Selected Rows")
        act_copy_all = menu.addAction("Copy All Rows")
        action = menu.exec(tbl.mapToGlobal(pos))

        def _row_text(r: int) -> str:
            return "\t".join(
                tbl.item(r, c).text() if tbl.item(r, c) else ""
                for c in range(tbl.columnCount())
            )

        if action == act_copy:
            rows = sorted({idx.row() for idx in tbl.selectedIndexes()})
            lines = [_row_text(r) for r in rows]
            if lines:
                QApplication.clipboard().setText("\n".join(lines))
        elif action == act_copy_all:
            lines = [_row_text(r) for r in range(tbl.rowCount())]
            if lines:
                QApplication.clipboard().setText("\n".join(lines))

    # ── ATT&CK table interactivity ────────────────────────────────────────────

    def _get_attack_row_tactic(self, row: int) -> str | None:
        """Return the lowercase tactic name from the given ATT&CK table row."""
        item = self._tbl_attack.item(row, 0)
        return item.text().lower() if item else None

    def _get_attack_row_techniques(self, tactic: str) -> list[tuple[str, str]]:
        """
        Return sorted list of (TID, technique_name) for the given tactic,
        derived from the current events dataset.
        """
        seen: dict[str, str] = {}
        tactic_lower = tactic.lower()
        for ev in self._events:
            for tag in (ev.get("attack_tags") or []):
                if tag.get("tactic", "").lower() == tactic_lower:
                    tid  = tag.get("tid", "")
                    name = tag.get("name", "") or tag.get("technique_name", "") or tid
                    if tid and tid not in seen:
                        seen[tid] = name
        return sorted(seen.items())

    def _on_attack_row_clicked(self, row: int, col: int) -> None:
        """
        Left-click on ATT&CK table row.
        If clicking the row whose tactic is already the active filter → clear filter.
        Otherwise show the context menu at the current cursor position.
        """
        from PySide6.QtGui import QCursor
        tactic = self._get_attack_row_tactic(row)
        if not tactic:
            return
        if tactic == self._active_tactic_filter:
            self._clear_tactic_filter()
            return
        self._show_attack_context_menu(QCursor.pos(), tactic)

    def _on_attack_context_menu_requested(self, pos) -> None:
        """Right-click context menu on ATT&CK table."""
        index = self._tbl_attack.indexAt(pos)
        if not index.isValid():
            return
        tactic = self._get_attack_row_tactic(index.row())
        if not tactic:
            return
        self._show_attack_context_menu(self._tbl_attack.mapToGlobal(pos), tactic)

    def _show_attack_context_menu(self, global_pos, tactic: str) -> None:
        """Build and display the two-option ATT&CK context menu."""
        from PySide6.QtWidgets import QMenu
        menu = QMenu(self)
        act_export = menu.addAction(f"Export '{tactic.title()}' Events as CSV")
        act_filter = menu.addAction(f"Filter Table to '{tactic.title()}'")
        if self._active_tactic_filter:
            menu.addSeparator()
            act_clear = menu.addAction("Clear Tactic Filter")
            act_clear.triggered.connect(self._clear_tactic_filter)

        action = menu.exec(global_pos)
        if action == act_export:
            self._export_tactic_csv(tactic)
        elif action == act_filter:
            self._filter_by_tactic_dialog(tactic)

    def _export_tactic_csv(self, tactic: str) -> None:
        """Export all events matching the given tactic to a CSV file."""
        import csv
        import os as _os

        tactic_lower = tactic.lower()
        filtered = [
            ev for ev in self._events
            if any(t.get("tactic", "").lower() == tactic_lower
                   for t in (ev.get("attack_tags") or []))
        ]
        if not filtered:
            QMessageBox.information(
                self, "No Events",
                f"No events found for tactic '{tactic.title()}'."
            )
            return

        default_name = f"tactic_{tactic_lower.replace(' ', '_')}.csv"
        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export '{tactic.title()}' Events",
            default_name,
            "CSV Files (*.csv);;All Files (*)",
        )
        if not path:
            return

        try:
            headers = [
                "Event ID", "Level", "Timestamp", "Computer",
                "Channel", "User", "ATT&CK", "Source File",
            ]
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)
                for ev in filtered:
                    tags = ev.get("attack_tags") or []
                    tids = ";".join(t.get("tid", "") for t in tags)
                    writer.writerow([
                        ev.get("event_id", ""),
                        ev.get("level_name", ""),
                        ev.get("timestamp", ""),
                        ev.get("computer", ""),
                        ev.get("channel", ""),
                        ev.get("user_id", ""),
                        tids,
                        _os.path.basename(ev.get("source_file", "")),
                    ])
            QMessageBox.information(
                self, "Export Complete",
                f"Exported {len(filtered):,} events to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _filter_by_tactic_dialog(self, tactic: str) -> None:
        """
        Show a dialog letting the user choose between filtering all events
        under this tactic or a specific technique within it.
        """
        techniques = self._get_attack_row_techniques(tactic)
        all_label = f"All events under '{tactic.title()}'"
        items = [all_label] + [f"{tid}  —  {name}" for tid, name in techniques]

        choice, ok = QInputDialog.getItem(
            self,
            "Filter by Tactic",
            f"Select scope for tactic '{tactic.title()}':",
            items,
            0,
            False,
        )
        if not ok:
            return

        if choice == all_label:
            self._apply_tactic_filter(tactic, None)
        else:
            idx = items.index(choice) - 1  # -1 to skip the "All events" entry
            if 0 <= idx < len(techniques):
                tid, _name = techniques[idx]
                self._apply_tactic_filter(tactic, tid)

    def _apply_tactic_filter(self, tactic: str, technique: str | None) -> None:
        """Apply a tactic (and optionally technique) filter to the events table."""
        self._active_tactic_filter    = tactic.lower()
        self._active_technique_filter = technique.lower() if technique else None
        self._active_proxy.set_tactic_filter(tactic, technique)
        self._update_count_label()

        if technique:
            label_text = (
                f"\u25b6  Tactic filter: {tactic.title()}  /  {technique}"
            )
        else:
            label_text = f"\u25b6  Tactic filter: {tactic.title()}"
        self._lbl_tactic_active.setText(label_text)
        self._tactic_filter_widget.setVisible(True)

        # Switch to the ATT&CK tab in the analysis panel for visual context
        self._analysis_tabs.setCurrentWidget(self._tab_attack)

    def _clear_tactic_filter(self) -> None:
        """Remove the active tactic filter and restore the full events table."""
        self._active_tactic_filter    = None
        self._active_technique_filter = None
        self._active_proxy.set_tactic_filter(None)
        self._update_count_label()
        self._tactic_filter_widget.setVisible(False)
        self._tbl_attack.clearSelection()

    # ── Export all IOCs to CSV / TXT ──────────────────────────────────────────

    def _on_export_iocs_clicked(self) -> None:
        if not self._iocs:
            return

        path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export IOCs", "",
            "CSV — type + value + score (*.csv);;"
            "Text — one value per line (*.txt);;"
            "STIX 2.1 Bundle (*.json);;"
            "MISP Event JSON (*.json);;"
            "YARA Rule (*.yar);;"
            "Bulk Clipboard — type:value (*.txt)",
        )
        if not path:
            return

        # Determine format from extension + selected filter
        pl = path.lower()
        is_stix  = pl.endswith(".json") and "STIX" in selected_filter
        is_misp  = pl.endswith(".json") and "MISP" in selected_filter
        is_yara  = pl.endswith(".yar")
        is_bulk  = "Bulk" in selected_filter
        is_csv   = pl.endswith(".csv")

        try:
            from evtx_tool.output.ioc_formats import (
                export_stix, export_misp, export_yara, format_bulk_clipboard,
            )

            if is_stix:
                count = export_stix(self._iocs, path)
                msg   = f"Exported {count:,} STIX indicator objects to:\n{path}"

            elif is_misp:
                count = export_misp(self._iocs, path)
                msg   = f"Exported {count:,} MISP attributes to:\n{path}"

            elif is_yara:
                count = export_yara(self._iocs, path)
                msg   = f"Exported {count:,} YARA strings to:\n{path}"

            elif is_bulk:
                text = format_bulk_clipboard(self._iocs)
                QApplication.clipboard().setText(text)
                count = text.count("\n") + 1 if text else 0
                QMessageBox.information(
                    self, "IOCs Copied",
                    f"Copied {count:,} IOC lines (type:value format) to clipboard."
                )
                return

            elif is_csv:
                import csv as _csv
                _ioc_keys = [
                    ("IPv4", "ipv4"), ("IPv6", "ipv6"), ("Domains", "domains"),
                    ("URLs", "urls"), ("SHA-256", "sha256"), ("SHA-1", "sha1"),
                    ("MD5", "md5"), ("Processes", "processes"),
                    ("CmdLines", "commandlines"), ("Registry", "registry"),
                    ("Paths", "filepaths"), ("Services", "services"),
                    ("Tasks", "tasks"), ("Named Pipes", "named_pipes"),
                    ("Shares", "shares"), ("DLLs", "dlls"),
                    ("Users", "users"), ("Computers", "computers"),
                ]
                count = 0
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    writer = _csv.writer(fh)
                    writer.writerow(["type", "value", "count", "first_seen",
                                     "last_seen", "score"])
                    for label, key in _ioc_keys:
                        for entry in (self._iocs.get(key) or []):
                            if isinstance(entry, dict):
                                writer.writerow([
                                    label,
                                    entry.get("value", ""),
                                    entry.get("count", 1),
                                    (entry.get("first_seen") or "")[:19],
                                    (entry.get("last_seen")  or "")[:19],
                                    entry.get("score", 0),
                                ])
                            else:
                                writer.writerow([label, str(entry), 1, "", "", 0])
                            count += 1
                msg = f"Exported {count:,} IOC values to:\n{path}"

            else:
                # Plain TXT
                _ioc_keys = [
                    ("IPv4", "ipv4"), ("IPv6", "ipv6"), ("Domains", "domains"),
                    ("URLs", "urls"), ("SHA-256", "sha256"), ("SHA-1", "sha1"),
                    ("MD5", "md5"), ("Processes", "processes"),
                    ("CmdLines", "commandlines"), ("Registry", "registry"),
                    ("Paths", "filepaths"), ("Services", "services"),
                    ("Tasks", "tasks"), ("Named Pipes", "named_pipes"),
                    ("Shares", "shares"), ("DLLs", "dlls"),
                    ("Users", "users"), ("Computers", "computers"),
                ]
                count = 0
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    for label, key in _ioc_keys:
                        items = self._iocs.get(key) or []
                        if items:
                            fh.write(f"# {label}\n")
                            for entry in items:
                                val = entry.get("value", "") if isinstance(entry, dict) else str(entry)
                                fh.write(f"{val}\n")
                                count += 1
                            fh.write("\n")
                msg = f"Exported {count:,} IOC values to:\n{path}"

            QMessageBox.information(self, "IOCs Exported", msg)
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _refresh_chains_tab(self) -> None:
        self._tree_chains.clear()
        chains = self._chains
        if not chains:
            self._lbl_chains_summary.setText(
                "No chains detected — run with Correlation Engine enabled."
            )
            return

        crit = sum(1 for c in chains if c.get("severity") == "critical")
        high = sum(1 for c in chains if c.get("severity") == "high")
        self._lbl_chains_summary.setText(
            f"{len(chains)} chains  |  {crit} critical  |  {high} high"
        )

        # Defined once (not inside the loop) — a single class is shared by all
        # chain wrappers.  Defining it inside the loop created a distinct class
        # object per iteration, wasting memory and breaking any isinstance() checks.
        class _ChainWrapper:
            def __init__(self, data):
                self.data = data

        sev_colors = {
            "critical": COLORS["chain_critical"], "high": COLORS["chain_high"],
            "medium": COLORS["chain_medium"],     "low":  COLORS["chain_low"],
        }
        for chain in chains:
            sev   = chain.get("severity", "low")
            color = sev_colors.get(sev, COLORS["text_dim"])
            top = QTreeWidgetItem([
                sev.upper(),
                chain.get("rule_name", ""),
                ", ".join(chain.get("computers", [])) or "?",
                str(len(chain.get("events", []))),
                (chain.get("first_event_ts") or chain.get("first_ts", ""))[:19],
            ])
            top.setForeground(0, QColor(color))
            top.setForeground(1, QColor(color))
            top.setData(0, Qt.ItemDataRole.UserRole, _ChainWrapper(chain))

            desc = chain.get("description", "")
            if desc:
                desc_item = QTreeWidgetItem([desc, "", "", "", ""])
                desc_item.setForeground(0, QColor(COLORS["text_dim"]))
                top.addChild(desc_item)

            for ev in (chain.get("events") or [])[:10]:
                # events are full event dicts, not plain IDs
                if isinstance(ev, dict):
                    eid = ev.get("event_id", "?")
                    ts  = str(ev.get("timestamp", ""))[:19]
                    comp = ev.get("computer", "")
                else:
                    eid, ts, comp = ev, "", ""
                ev_item = QTreeWidgetItem([
                    f"EID {eid}", "", comp, ts, ""
                ])
                ev_item.setForeground(0, QColor(COLORS["text_dim"]))
                top.addChild(ev_item)

            self._tree_chains.addTopLevelItem(top)

        self._tree_chains.resizeColumnToContents(0)
        self._tree_chains.resizeColumnToContents(3)

    def _on_chain_double_click(self, item: QTreeWidgetItem, col: int) -> None:
        """Filter the events table to show only events matching the chain's event IDs."""
        chain_wrap = item.data(0, Qt.ItemDataRole.UserRole)
        chain = chain_wrap.data if hasattr(chain_wrap, 'data') else None
        if not chain:
            item = item.parent()
            if item:
                chain_wrap = item.data(0, Qt.ItemDataRole.UserRole)
                chain = chain_wrap.data if hasattr(chain_wrap, 'data') else None
        if not chain:
            return
        raw_evs = chain.get("events") or []
        if raw_evs:
            # events are full dicts — extract unique event_id values
            seen_ids: list[str] = []
            for e in raw_evs[:20]:
                eid = str(e.get("event_id", "")) if isinstance(e, dict) else str(e)
                if eid and eid not in seen_ids:
                    seen_ids.append(eid)
                if len(seen_ids) >= 5:
                    break

    def _on_chains_context_menu(self, pos) -> None:
        """Right-click menu on the correlation chains tree."""
        from PySide6.QtWidgets import QMenu

        # Collect selected *top-level* items (child items represent individual events/descriptions)
        selected = [
            item for item in self._tree_chains.selectedItems()
            if item.parent() is None
        ]

        # If nothing is selected but user right-clicked a specific item, use that one
        if not selected:
            item = self._tree_chains.itemAt(pos)
            if item:
                if item.parent() is not None:
                    item = item.parent()
                if item:
                    selected = [item]

        if not selected:
            return

        menu = QMenu(self)
        n = len(selected)
        view_label = (
            "View Chain Events in New Tab"
            if n == 1
            else f"View Events from {n} Chains in New Tab"
        )
        act_view = menu.addAction(f"\u26d3  {view_label}")
        act_view.triggered.connect(lambda: self._open_chain_events_tab(selected))

        menu.exec(self._tree_chains.viewport().mapToGlobal(pos))

    def _open_chain_events_tab(self, chain_items: list) -> None:
        """Open a new events tab containing all events from the selected chain(s)."""
        import uuid as _uuid

        # Extract chain dicts from the QTreeWidgetItems
        chains: list[dict] = []
        for item in chain_items:
            cw = item.data(0, Qt.ItemDataRole.UserRole)
            ch = cw.data if hasattr(cw, 'data') else None
            if isinstance(ch, dict):
                chains.append(ch)
        if not chains:
            return

        # ── Collect + deduplicate events ──────────────────────────────────────
        # Dedup key: (timestamp, event_id, computer, record_id)
        seen: set = set()
        events: list[dict] = []
        for ch in chains:
            for ev in ch.get("events") or []:
                if not isinstance(ev, dict):
                    continue
                key = (
                    ev.get("timestamp", ""),
                    ev.get("event_id", 0),
                    ev.get("computer", ""),
                    ev.get("record_id", ""),
                )
                if key not in seen:
                    seen.add(key)
                    events.append(ev)

        if not events:
            QMessageBox.information(
                self, "No Events", "No events found in the selected chain(s)."
            )
            return

        # Sort chronologically
        events.sort(key=lambda e: e.get("timestamp") or "")

        # ── Tab label ─────────────────────────────────────────────────────────
        if len(chains) == 1:
            rule = chains[0].get("rule_name") or "Chain"
            short = rule if len(rule) <= 28 else rule[:26] + "\u2026"
            tab_label = f"\u26d3 {short}"
        else:
            tab_label = f"\u26d3 {len(chains)} Chains"

        # Unique synthetic key stored in _file_tabs (never matches a real filepath)
        tab_key = f"__chain__{_uuid.uuid4().hex}"

        # ── Build model + proxy + table ───────────────────────────────────────
        search_cache = [EventTableModel._build_search_str(ev) for ev in events]

        model = EventTableModel()
        proxy = EventFilterProxyModel()
        proxy.setSourceModel(model)

        table = self._create_configured_table(proxy)

        table.setUpdatesEnabled(False)
        table.setSortingEnabled(False)
        proxy.setDynamicSortFilter(False)
        table.setModel(None)

        model.set_events(events, search_cache=search_cache)

        proxy.setDynamicSortFilter(False)
        table.setModel(proxy)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.selectionModel().selectionChanged.connect(self._on_row_selected)

        self._apply_col_visibility(table, self._visible_cols)

        proxy.setDynamicSortFilter(True)
        table.setUpdatesEnabled(True)

        # ── Add the tab ───────────────────────────────────────────────────────
        tab_idx = self._events_tab_widget.addTab(table, tab_label)

        # Tooltip: one line per chain + total count
        tooltip_parts: list[str] = []
        for ch in chains:
            sev = (ch.get("severity") or "?").upper()
            rn  = ch.get("rule_name") or "?"
            ec  = ch.get("event_count") or len(ch.get("events") or [])
            tooltip_parts.append(f"[{sev}] {rn}  ({ec} events)")
        tooltip_parts.append(f"\nTotal unique events: {len(events)}")
        self._events_tab_widget.setTabToolTip(tab_idx, "\n".join(tooltip_parts))

        # Close button — identical style to file-tab close buttons
        _btn_close = QPushButton("\u00d7")
        _btn_close.setFixedSize(16, 16)
        _btn_close.setStyleSheet(
            "QPushButton { color: #7a5c1e; font-size: 12pt; font-weight: bold;"
            " border: none; background: transparent; padding: 0; margin: 0; }"
            "QPushButton:hover { color: #a01800; background: #f5e0dc; border-radius: 2px; }"
        )
        _btn_close.clicked.connect(
            lambda _=False, t=table: self._on_file_tab_close_requested(
                self._events_tab_widget.indexOf(t)
            )
        )
        self._events_tab_widget.tabBar().setTabButton(
            tab_idx,
            self._events_tab_widget.tabBar().ButtonPosition.RightSide,
            _btn_close,
        )

        # ── Store in _file_tabs so tab-change / close logic work normally ─────
        state = FileTabState(
            filepath=tab_key,
            display_name=tab_label,
            events=events,
            search_cache=search_cache,
            model=model,
            proxy=proxy,
            table=table,
        )
        self._file_tabs[tab_key] = state

        # Propagate any active session filter to this new proxy
        if self._proxy_model.has_session_filter():
            lid = self._proxy_model.get_session_filter()
            if lid:
                proxy.set_session_filter(lid)

        # ── Tab bar: must be visible so user can navigate between tabs ────────
        # In merged mode the bar is collapsed to save space; un-collapse it now.
        self._events_tab_widget.setBarCollapsed(False)

        # ── File tree: add an entry so the user can navigate back ─────────────
        tree_item = QTreeWidgetItem([tab_label])
        tree_item.setData(0, Qt.ItemDataRole.UserRole, tab_key)
        tree_item.setToolTip(0, "\n".join(tooltip_parts))
        _tf = tree_item.font(0)
        _tf.setBold(True)
        tree_item.setFont(0, _tf)
        self._file_tree.addTopLevelItem(tree_item)

        # Show the file-tree panel if it is hidden (e.g. merged mode)
        if not self._file_tree_panel.isVisible():
            self._file_tree_panel.setVisible(True)
            self._btn_tree_toggle.setEnabled(True)
            self._btn_tree_toggle.setChecked(True)
            self._events_content_splitter.setSizes([180, 800])

        # Switch to the new tab
        self._events_tab_widget.setCurrentIndex(tab_idx)

    # =========================================================================
    # EXPORT
    # =========================================================================

    def _on_export_clicked(self) -> None:
        """Show the export scope chooser and drive the appropriate export path."""
        # Juggernaut Mode: delegate immediately (its own scope dialog)
        if self._hw_model is not None:
            return self._export_juggernaut()
        if not self._events:
            QMessageBox.information(self, "Nothing to Export", "Parse some events first.")
            return

        # Build the list of available source files for "Specific files" option
        all_file_paths = list(self._per_file_data.keys())

        dlg = _ExportScopeDialog(
            all_file_paths=all_file_paths,
            active_file=self._active_file_tab,
            view_mode=self._view_mode,
            total_events=len(self._events),
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        scope = dlg.selected_scope()   # "view" | "combined" | "separate" | "specific"
        specific_files = dlg.selected_files()  # set[str] — only used when scope="specific"

        # ── Export All Separate ────────────────────────────────────────────
        if scope == "separate":
            self._export_separate(all_file_paths)
            return

        # ── Resolve events for the other scopes ───────────────────────────
        if scope == "view":
            # Collect only the rows currently visible through the proxy filter
            _proxy = self._active_proxy
            export_events = [
                ev for i in range(_proxy.rowCount())
                if (ev := _proxy.get_source_event(i)) is not None
            ]
            export_label  = (
                os.path.basename(self._active_file_tab)
                if self._active_file_tab else "Current View"
            )
            export_attack = self._derive_attack_summary(export_events)
            export_iocs   = None
            export_chains = []
        elif scope == "specific":
            export_events = []
            for fp in specific_files:
                data = self._per_file_data.get(fp)
                if data:
                    export_events.extend(data["events"])
            names = ", ".join(os.path.basename(fp) for fp in sorted(specific_files))
            export_label  = f"Selected Files ({len(specific_files)})"
            export_attack = self._derive_attack_summary(export_events)
            export_iocs   = None
            export_chains = []
        else:  # combined
            export_events = self._events
            export_label  = f"All Files ({len(self._events):,} events)"
            export_attack = self._attack_summary
            export_iocs   = self._iocs
            export_chains = self._chains

        if not export_events:
            QMessageBox.information(self, "Nothing to Export",
                                    "No events found for the selected scope.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export Events — {export_label}",
            "",
            "HTML Report (*.html);;PDF Report (*.pdf);;CSV (*.csv);;JSON (*.json);;XML (*.xml)",
        )
        if not path:
            return

        try:
            from evtx_tool.output.exporters import export
            count = export(
                export_events, path, None,
                attack_summary=export_attack,
                iocs=export_iocs,
                chains=export_chains,
            )
            QMessageBox.information(
                self, "Exported",
                f"Exported {count:,} events to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _export_separate(self, file_paths: list[str]) -> None:
        """Export each source file to its own output file (user picks the output folder)."""
        out_dir = QFileDialog.getExistingDirectory(
            self, "Select Output Folder for Separate Exports"
        )
        if not out_dir:
            return

        fmt_map = {
            "html": "HTML Report (*.html)",
            "csv": "CSV (*.csv)",
            "json": "JSON (*.json)",
            "xml": "XML (*.xml)",
        }
        from PySide6.QtWidgets import QInputDialog
        fmt, ok = QInputDialog.getItem(
            self, "Export Format", "Choose output format:",
            ["CSV", "JSON", "HTML", "XML"], 0, False
        )
        if not ok:
            return
        ext = fmt.lower()

        try:
            from evtx_tool.output.exporters import export
            exported_files = 0
            total_events = 0
            for fp in file_paths:
                data = self._per_file_data.get(fp)
                if not data or not data.get("events"):
                    continue
                evts = data["events"]
                base = os.path.splitext(os.path.basename(fp))[0]
                out_path = os.path.join(out_dir, f"{base}.{ext}")
                count = export(evts, out_path, None)
                total_events += count
                exported_files += 1

            QMessageBox.information(
                self, "Exported",
                f"Exported {total_events:,} events across {exported_files} files to:\n{out_dir}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _export_juggernaut(self) -> None:
        """Export events from the Arrow table when Juggernaut Mode is active."""
        if self._hw_model is None:
            QMessageBox.information(self, "Nothing to Export", "No Juggernaut data loaded.")
            return

        # Use the active per-file model if a per-file tab is open, so export
        # is scoped to that file's events (including its fixed source_file filter).
        _active_fp   = getattr(self, "_active_file_tab", None)
        _file_state  = self._file_tabs.get(_active_fp) if _active_fp else None
        _export_model = _file_state.model if _file_state else self._hw_model

        total = _export_model._total_rows   # current filtered count
        if total == 0:
            QMessageBox.information(self, "Nothing to Export",
                                    "No events match the current filters.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            f"Export Events — ⚡ Juggernaut ({total:,} events)",
            "",
            "HTML Report (*.html);;CSV (*.csv);;JSON (*.json);;XML (*.xml)",
        )
        if not path:
            return

        try:
            import duckdb as _duckdb
            from evtx_tool.output.exporters import export

            where_sql, params = _export_model._combined_where()
            sort_col  = _export_model._sort_col
            direction = "ASC" if _export_model._sort_asc else "DESC"

            # Open a temporary in-memory DuckDB connection on the Arrow table.
            # This gives us streaming SQL access without needing _hw_con.
            _exp_con = _duckdb.connect()
            _exp_con.register("events", self._hw_model._full_table)

            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""

            # Fast path: streaming Python writer for CSV/JSON.
            if ext in ("csv", "json"):
                import csv as _csv
                import json as _json
                cursor = _exp_con.execute(
                    f"SELECT * FROM events "
                    f"WHERE {where_sql} "
                    f"ORDER BY {sort_col} {direction}",
                    params,
                )
                col_names = [d[0].strip() for d in cursor.description]
                if ext == "csv":
                    with open(path, "w", newline="", encoding="utf-8") as _f:
                        writer = _csv.writer(_f)
                        writer.writerow(col_names)
                        writer.writerows(cursor)
                else:  # json
                    with open(path, "w", encoding="utf-8") as _f:
                        _f.write("[\n")
                        _first = True
                        for _row in cursor:
                            if not _first:
                                _f.write(",\n")
                            _f.write(_json.dumps(dict(zip(col_names, _row)),
                                                 default=str))
                            _first = False
                        _f.write("\n]\n")
                _exp_con.close()
                QMessageBox.information(
                    self, "Exported",
                    f"Exported {total:,} events to:\n{path}"
                )
                return

            # Slow path: Python reconstruction for HTML/XML.
            _HTML_XML_MAX = 100_000
            export_row_limit = total
            if total > _HTML_XML_MAX:
                reply = QMessageBox.question(
                    self, "Large Export — Memory Safety Cap",
                    f"<b>{total:,} events</b> matched the current filter.<br><br>"
                    f"HTML/XML export is capped at <b>{_HTML_XML_MAX:,} rows</b> "
                    f"to prevent out-of-memory crashes<br>"
                    f"(browsers/editors cannot handle millions of rows either).<br><br>"
                    f"Export the first <b>{_HTML_XML_MAX:,} rows</b>?<br>"
                    f"<i>Use CSV or JSON for the full dataset — no row limit.</i>",
                    QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
                )
                if reply != QMessageBox.StandardButton.Ok:
                    _exp_con.close()
                    return
                export_row_limit = _HTML_XML_MAX

            BATCH = 5_000
            events: list[dict] = []
            offset = 0
            while len(events) < export_row_limit:
                batch_limit = min(BATCH, export_row_limit - len(events))
                cursor = _exp_con.execute(
                    f"SELECT * FROM events "
                    f"WHERE {where_sql} "
                    f"ORDER BY {sort_col} {direction} "
                    f"LIMIT {batch_limit} OFFSET {offset}",
                    params,
                )
                col_names = [d[0].strip() for d in cursor.description]
                rows = cursor.fetchall()
                if not rows:
                    break
                for r in rows:
                    d = dict(zip(col_names, r))
                    events.append({
                        "record_id":      d.get("record_id"),
                        "event_id":       d.get("event_id"),
                        "level_name":     d.get("level_name") or "",
                        "timestamp":      d.get("timestamp_utc") or "",
                        "computer":       d.get("computer") or "",
                        "channel":        d.get("channel") or "",
                        "user_id":        d.get("user_id") or "",
                        "source_file":    d.get("source_file") or "",
                        "provider":       d.get("provider") or "",
                        "keywords":       d.get("keywords") or "",
                        "task":           d.get("task") or 0,
                        "opcode":         d.get("opcode") or 0,
                        "process_id":     d.get("process_id"),
                        "thread_id":      d.get("thread_id"),
                        "correlation_id": d.get("correlation_id") or "",
                        "event_data":     {},
                        "_heavyweight":   True,
                    })
                offset += len(rows)
                if len(rows) < batch_limit:
                    break
            _exp_con.close()

            count = export(
                events, path, None,
                attack_summary=None,
                iocs=None,
                chains=[],
            )
            QMessageBox.information(
                self, "Exported",
                f"Exported {count:,} events to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    # =========================================================================
    # CLEAR
    # =========================================================================
    # LEFT PANEL COLLAPSE / EXPAND
    # =========================================================================

    def _toggle_left_panel(self) -> None:
        """
        Animate the WRAPPER's maximumWidth so the QSplitter redistributes
        freed space to the right panel automatically.
        Collapse target = 16 px (button only). Expand target = stored width.
        State is persisted via QSettings so it survives app restarts.
        """
        wrapper = self._left_panel_wrapper

        if self._panel_open:
            # ── Collapsing ────────────────────────────────────────────────
            # Snapshot the full wrapper width so we can restore it later
            self._panel_stored_width = max(wrapper.width(), 220)
            start_val = self._panel_stored_width
            end_val   = 16   # collapse to button-only width
            self._btn_panel_toggle.setText("▶")
        else:
            # ── Expanding ─────────────────────────────────────────────────
            start_val = 16
            end_val   = self._panel_stored_width
            self._btn_panel_toggle.setText("◀")

        self._panel_open = not self._panel_open

        anim = QPropertyAnimation(wrapper, b"maximumWidth")
        anim.setDuration(260)
        anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        anim.setStartValue(start_val)
        anim.setEndValue(end_val)

        if self._panel_open:
            # After expanding, lift the hard cap so the splitter handle
            # remains freely draggable to resize the panel
            anim.finished.connect(
                lambda: wrapper.setMaximumWidth(16_777_215)
            )

        anim.start()
        self._panel_anim = anim  # keep reference alive (prevent GC)

        # Persist preference
        QSettings("EventHawk", "GUI").setValue(
            "left_panel_open", self._panel_open
        )

    def _restore_panel_state(self) -> None:
        """
        Called once, ~50 ms after the window is shown, to restore the
        panel's open/collapsed state that was saved in the last session.
        Applies instantly (no animation) so the user doesn't see a flash.
        """
        was_open = QSettings("EventHawk", "GUI").value(
            "left_panel_open", True, type=bool
        )
        if not was_open:
            wrapper = self._left_panel_wrapper
            # Snapshot the settled geometry before collapsing
            self._panel_stored_width = max(wrapper.width(), 240)
            wrapper.setMaximumWidth(16)   # collapse to button-only width instantly
            self._btn_panel_toggle.setText("▶")
            self._panel_open = False

    # =========================================================================
    # POWERSHELL FORENSIC EXTRACTION
    # =========================================================================

    def _on_ps_extract(self) -> None:
        """Launch PowerShell forensic artifact extraction in a background thread."""
        from .ps_worker import PSWorker

        # Guard: don't launch if already running
        if getattr(self, "_ps_worker", None) is not None and self._ps_worker.isRunning():
            return

        evtx_files = self._collect_files()
        if not evtx_files:
            QMessageBox.information(
                self, "No Files",
                "Add EVTX files to the file list first, then click PowerShell History."
            )
            return

        output_dir = QFileDialog.getExistingDirectory(
            self, "Choose Output Directory for PowerShell History", ""
        )
        if not output_dir:
            return

        # Build progress dialog with cancel support
        self._ps_dlg = _PSProgressDialog(parent=self)
        self._ps_dlg.cancel_requested.connect(self._on_ps_cancel)
        self._ps_dlg.show()

        self._ps_worker = PSWorker(evtx_files, output_dir, parent=self)
        self._ps_worker.progress.connect(self._on_ps_progress)
        self._ps_worker.extraction_done.connect(self._on_ps_finished)
        self._ps_worker.extraction_error.connect(self._on_ps_error)
        self._act_ps_extract.setEnabled(False)
        self._ps_worker.start()
        self._ps_output_dir = output_dir

    def _on_ps_cancel(self) -> None:
        """Handle cancel request from progress dialog."""
        worker = getattr(self, "_ps_worker", None)
        if worker is not None and worker.isRunning():
            worker.request_cancel()

    @Slot(str, float)
    def _on_ps_progress(self, step: str, pct: float) -> None:
        dlg = getattr(self, "_ps_dlg", None)
        if dlg is None:
            return
        dlg.set_step(step)
        if pct < 0:
            dlg.set_indeterminate(True)
        else:
            dlg.set_indeterminate(False)
            dlg.set_value(int(pct * 100))

    def _cleanup_ps_worker(self) -> None:
        """Wait for PS worker thread to finish and schedule its deletion."""
        worker = getattr(self, "_ps_worker", None)
        if worker is not None:
            worker.wait()
            worker.deleteLater()
            self._ps_worker = None

    @Slot(dict)
    def _on_ps_finished(self, summary: dict) -> None:
        dlg = getattr(self, "_ps_dlg", None)
        if dlg:
            dlg.force_close()
            self._ps_dlg = None

        self._act_ps_extract.setEnabled(True)
        self._cleanup_ps_worker()

        # If extraction was cancelled, show a brief message
        if summary.get("cancelled"):
            QMessageBox.information(self, "PowerShell History", "Extraction cancelled.")
            return

        output_dir = getattr(self, "_ps_output_dir", "")

        ps_events  = summary.get("total_ps_events", 0)
        blocks     = summary.get("script_blocks", 0)
        sessions   = summary.get("sessions", 0)
        partial    = summary.get("partial_blocks", 0)
        safety_net = summary.get("safety_net", 0)
        errors     = summary.get("parse_errors", 0)

        msg = (
            "PowerShell extraction complete.\n\n"
            f"PS events found   : {ps_events:,}\n"
            f"Script blocks     : {blocks:,}"
            + (f"  ({partial} incomplete)" if partial else "") + "\n"
            f"Safety-net blocks : {safety_net:,}\n"
            f"Sessions (400/403): {sessions:,}\n"
            "\nOutput files:\n"
            "  ps_commands.txt\n"
            "  ps_extraction_summary.txt\n"
            "  ps_extraction.json\n"
            "  ps_timeline.xlsx\n"
            f"  scriptblock_<GUID>.txt × {blocks:,}\n"
        )
        if errors:
            msg += f"\nParse errors: {errors}\n"
        msg += f"\nDirectory:\n{output_dir}"

        result_dlg = QMessageBox(self)
        result_dlg.setWindowTitle("PowerShell History — Complete")
        result_dlg.setText(msg)
        result_dlg.setIcon(QMessageBox.Icon.Information)
        open_btn = result_dlg.addButton("Open Folder", QMessageBox.ButtonRole.ActionRole)
        result_dlg.addButton(QMessageBox.StandardButton.Ok)
        result_dlg.exec()
        if result_dlg.clickedButton() is open_btn and output_dir:
            try:
                os.startfile(output_dir)
            except Exception:
                pass

    @Slot(str)
    def _on_ps_error(self, tb: str) -> None:
        dlg = getattr(self, "_ps_dlg", None)
        if dlg:
            dlg.force_close()
            self._ps_dlg = None

        self._act_ps_extract.setEnabled(True)
        self._cleanup_ps_worker()

        err_dlg = QMessageBox(self)
        err_dlg.setWindowTitle("PowerShell History — Failed")
        err_dlg.setIcon(QMessageBox.Icon.Critical)
        err_dlg.setText("PowerShell extraction encountered an error.")
        err_dlg.setDetailedText(tb)
        err_dlg.exec()

    def _on_clear_files(self) -> None:
        """✕ button — clear the file/directory list AND discard parsed results."""
        self._file_list.clear()
        self._clear_results()

    def _clear_results(self) -> None:
        # Fix E: cleanup Juggernaut (DuckDB) state and reset table model
        if self._hw_model is not None:
            # Reset table back to normal-mode proxy before cleanup
            self._table.setModel(self._proxy_model)
            self._table.selectionModel().selectionChanged.connect(self._on_row_selected)
        self._cleanup_juggernaut()

        self._events         = []
        self._attack_summary = None
        self._iocs           = None
        self._chains         = []

        # ── Per-file state cleanup ────────────────────────────────────────
        # Close and destroy all open file tabs
        for fp, state in list(self._file_tabs.items()):
            idx = self._events_tab_widget.indexOf(state.table)
            if idx >= 0:
                self._events_tab_widget.removeTab(idx)
            state.proxy.setSourceModel(None)
            state.model.set_events([])
        self._file_tabs.clear()
        self._per_file_data.clear()
        self._active_file_tab = None

        # Clear file tree
        self._file_tree.clear()

        # Hide tree panel and reset toggle button
        self._file_tree_panel.setVisible(False)
        self._btn_tree_toggle.setEnabled(False)
        self._btn_tree_toggle.setChecked(False)
        self._events_content_splitter.setSizes([0, 1])

        # Show the "All Events" merged tab again, hide tab bar, switch to it
        self._events_tab_widget.setTabVisible(0, True)
        self._events_tab_widget.setBarCollapsed(True)
        self._events_tab_widget.setCurrentIndex(0)
        # Remove close button from All Events tab (not closeable in merged mode)
        bar = self._events_tab_widget.tabBar()
        existing = bar.tabButton(0, bar.ButtonPosition.RightSide)
        if existing is not None:
            existing.deleteLater()
            bar.setTabButton(0, bar.ButtonPosition.RightSide, None)

        # Hide analysis scope row (only shown in separate mode)
        if hasattr(self, "_scope_row_widget"):
            self._scope_row_widget.setVisible(False)
        # ─────────────────────────────────────────────────────────────────

        self._event_model.set_events([])
        self._clear_tactic_filter()
        self._detail_browser.clear()
        self._last_detail_key = None  # invalidate render cache on parse reset
        self._lbl_count.setText("0 events")
        self._progress_bar.setValue(0)
        self._lbl_matched.setText("Events: —")
        self._lbl_speed.setText("Speed: —")
        self._lbl_elapsed.setText("Time: —")
        self._btn_export.setEnabled(False)
        self._act_export.setEnabled(False)
        if self._file_list.count() == 0:
            self._act_ps_extract.setEnabled(False)
        self._refresh_attack_tab()
        self._refresh_iocs_tab()
        self._refresh_chains_tab()
        self._set_status("Ready")

    # =========================================================================
    # DIFF DIALOG
    # =========================================================================

    def _on_diff_dialog(self) -> None:
        dlg = DiffDialog(self)
        dlg.exec()

    # =========================================================================
    # ABOUT
    # =========================================================================

    # =========================================================================
    # SENTINEL BASELINE ENGINE LAUNCH
    # =========================================================================

    def _launch_sentinel(self) -> None:
        """Launch the Sentinel Baseline Engine as a standalone child dialog."""
        try:
            from sentinel.gui.window import SentinelWindow
        except ImportError:
            QMessageBox.information(
                self,
                "Sentinel Not Installed",
                "Sentinel Baseline Engine is not installed.\n\n"
                "Run: pip install -r sentinel/requirements.txt",
            )
            return
        win = SentinelWindow(parent=self)
        win.show()

    def _on_about(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("About EventHawk")
        dlg.setMinimumWidth(560)
        dlg.setStyleSheet(f"""
            QDialog {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
            }}
            QLabel {{
                color: {COLORS['text']};
            }}
        """)

        layout = QVBoxLayout(dlg)
        layout.setSpacing(12)
        layout.setContentsMargins(24, 24, 24, 24)

        # Logo
        logo_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "resources", "images", "eventhawk_logo.png"
        )
        if os.path.isfile(logo_path):
            logo_label = QLabel()
            pixmap = QPixmap(logo_path)
            # Scale to fixed width; height follows aspect ratio
            _logo_w = dlg.minimumWidth() - 48  # dialog width minus margins
            scaled_pixmap = pixmap.scaledToWidth(_logo_w, Qt.TransformationMode.SmoothTransformation)
            logo_label.setPixmap(scaled_pixmap)
            logo_label.setFixedSize(scaled_pixmap.width(), scaled_pixmap.height())
            logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            logo_label.setStyleSheet("background: transparent; border: none;")
            layout.addWidget(logo_label, alignment=Qt.AlignmentFlag.AlignCenter)

        # Title and description
        title = QLabel("<b>EventHawk v1.2</b>")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet(f"font-size: 14pt; color: {COLORS['text']};")
        layout.addWidget(title)

        desc = QLabel(
            "High-performance Windows Event Log (EVTX) parser for DFIR professionals.<br><br>"
            "<b>Features:</b> MITRE ATT&CK mapping, IOC extraction, correlation engine, "
            "timeline investigation, HTML/PDF/CSV/JSON/XML export.<br><br>"
            "<b>Backend:</b> pyevtx-rs (Rust)  |  <b>GUI:</b> PySide6 (Qt 6)"
        )
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc.setWordWrap(True)
        layout.addWidget(desc)

        layout.addStretch()

        btn = QPushButton("OK")
        btn.setFixedWidth(80)
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        btn_layout.addWidget(btn)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        btn.clicked.connect(dlg.accept)
        dlg.exec()

    # =========================================================================
    # TIME ZONE SETTING
    # =========================================================================

    def _on_timezone_action(self) -> None:
        """Open the Event Time Zone dialog; apply the new setting on OK."""
        dlg = EventTimeZoneDialog(
            current_mode=self._tz_mode,
            current_specific=self._tz_specific,
            current_custom_offset_min=self._tz_custom_offset_min,
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return

        # Persist selected values
        self._tz_mode              = dlg.selected_mode()
        self._tz_specific          = dlg.selected_specific_iana()
        self._tz_custom_offset_min = dlg.selected_custom_offset_min()

        # Push config into the shared models module and refresh all views
        self._apply_tz_to_all_models()

    def _apply_tz_to_all_models(self) -> None:
        """
        1. Update the module-level tz config (affects apply_tz() everywhere).
        2. Emit layoutChanged on every live EventTableModel so the table cells
           re-read COL_TS and re-render in the new timezone.
        3. Re-render the detail panel for the currently selected row (if any).
        """
        set_tz_config(
            self._tz_mode,
            self._tz_specific,
            self._tz_custom_offset_min,
        )

        # Refresh merged model
        self._event_model.layoutChanged.emit()

        # Refresh every per-file tab model
        for _state in self._file_tabs.values():
            try:
                _state.model.layoutChanged.emit()
            except Exception:
                pass

        # Refresh Juggernaut Mode model if active
        if getattr(self, "_hw_model", None) is not None:
            try:
                self._hw_model.layoutChanged.emit()
            except Exception:
                pass

        # Re-render detail panel if a row is currently selected
        try:
            _ev = None
            _proxy = self._active_proxy
            _sel = self._active_table.selectionModel().selectedRows()
            if _sel:
                _ev = _proxy.get_source_event(_sel[0].row())
            if _ev:
                self._render_event_detail(_ev)
        except Exception:
            pass

        # Update status bar to show active timezone
        _labels = {
            "local":    "Local",
            "utc":      "UTC",
            "specific": self._tz_specific,
            "custom": (
                f"UTC{'+' if self._tz_custom_offset_min >= 0 else ''}"
                f"{self._tz_custom_offset_min // 60:02d}:"
                f"{abs(self._tz_custom_offset_min) % 60:02d}"
            ),
        }
        self._set_status(f"Timezone: {_labels.get(self._tz_mode, self._tz_mode)}")



    # =========================================================================
    # COLUMN VISIBILITY / HEADER CONTEXT MENU
    # =========================================================================

    def _apply_col_visibility(self, table: QTableView, visible_cols: list[int]) -> None:
        """
        Show/hide columns on *table* according to *visible_cols* (ordered list of
        column indices that should be visible).  All other columns are hidden.
        Visible columns are then moved into the display order specified by the list.
        """
        total = len(COLUMNS)
        # Hide/show each logical column
        for col in range(total):
            table.setColumnHidden(col, col not in visible_cols)

        # Reorder visible columns to match the requested display order
        hdr = table.horizontalHeader()
        for display_pos, col_idx in enumerate(visible_cols):
            current_visual = hdr.visualIndex(col_idx)
            if current_visual != display_pos:
                hdr.moveSection(current_visual, display_pos)

    def _apply_col_visibility_all(self, visible_cols: list[int]) -> None:
        """Apply *visible_cols* to every open table (merged + per-file tabs)."""
        self._visible_cols = visible_cols
        # Merged "All Events" table
        self._apply_col_visibility(self._table, visible_cols)
        # Every open per-file tab
        for _state in self._file_tabs.values():
            try:
                self._apply_col_visibility(_state.table, visible_cols)
            except Exception:
                pass

    def _on_header_context_menu(self, pos: QPoint, table: QTableView) -> None:
        """Right-click on a column header — show the 3-item context menu."""
        from PySide6.QtWidgets import QMenu
        hdr = table.horizontalHeader()
        # Logical column index under the cursor
        visual_col = hdr.logicalIndexAt(pos)
        if visual_col < 0:
            return

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#ede8df; color:#1e1a14; border:1px solid #c4bba8; }"
            "QMenu::item:selected { background:#7a5c1e; color:#ffffff; }"
            "QMenu::separator { height:1px; background:#c4bba8; margin:2px 8px; }"
        )

        act_add_remove = menu.addAction("Add / Remove Columns\u2026")
        menu.addSeparator()
        act_sort = menu.addAction(f"Sort events by \u2018{COLUMNS[visual_col]}\u2019")
        act_group = menu.addAction(f"Group events by \u2018{COLUMNS[visual_col]}\u2019")

        # Record ID-only option
        act_missing = None
        if visual_col == COL_RECORD_ID:
            menu.addSeparator()
            act_missing = menu.addAction("Identify Missing Record IDs\u2026")

        chosen = menu.exec(hdr.mapToGlobal(pos))
        if chosen == act_add_remove:
            self._on_add_remove_columns_dialog()
        elif chosen == act_sort:
            self._on_sort_by_column(visual_col, table)
        elif chosen == act_group:
            self._on_group_by_column(visual_col)
        elif act_missing and chosen == act_missing:
            self._on_identify_missing_record_ids()

    def _on_sort_by_column(
        self,
        col_idx: int,
        table: QTableView,
        force_order: "Qt.SortOrder | None" = None,
    ) -> None:
        """Sort the table by *col_idx* (ascending first, then toggle).

        Parameters
        ----------
        col_idx : int
            Column to sort by (logical index).
        table : QTableView
            The table to sort.
        force_order : Qt.SortOrder | None
            If supplied, use this order instead of toggling.  Used by the
            sort buttons inside the column-filter popup.
        """
        hdr = table.horizontalHeader()
        if force_order is not None:
            new_order = force_order
        elif hdr.sortIndicatorSection() == col_idx:
            # Toggle direction
            new_order = (
                Qt.SortOrder.DescendingOrder
                if hdr.sortIndicatorOrder() == Qt.SortOrder.AscendingOrder
                else Qt.SortOrder.AscendingOrder
            )
        else:
            new_order = Qt.SortOrder.AscendingOrder
        # Show the sort arrow only when an explicit sort is performed.
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(col_idx, new_order)
        model = table.model()
        if model is not None:
            model.sort(col_idx, new_order)

    def _on_group_by_column(self, col_idx: int) -> None:
        """
        'Group by column' — bring all equal values together by sorting on
        that column, then show a friendly status-bar message.
        """
        # Grouping = sort + visual feedback in the status bar
        table = self._active_table
        hdr = table.horizontalHeader()
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(col_idx, Qt.SortOrder.AscendingOrder)
        model = table.model()
        if model is not None:
            model.sort(col_idx, Qt.SortOrder.AscendingOrder)
        col_name = COLUMNS[col_idx] if col_idx < len(COLUMNS) else str(col_idx)
        self._set_status(f"Grouped by \u2018{col_name}\u2019 (sorted ascending)")

    # ── Missing Record ID analysis ─────────────────────────────────────────────

    def _on_identify_missing_record_ids(self) -> None:
        """
        Scan the currently loaded events for gaps in the EventRecordID sequence
        and display the results in a dialog.

        Operates on the unfiltered source events so that active filters don't
        mask gaps.  Analyses each source file independently so that multi-file
        merges don't produce false positives (each EVTX has its own ID space).
        """
        from collections import defaultdict
        by_file: dict[str, list[int]] = defaultdict(list)

        # Juggernaut mode: read directly from Arrow table (full unfiltered table)
        if self._hw_model is not None:
            full_table = getattr(self._hw_model, "_full_table", None)
            if full_table is None or len(full_table) == 0:
                QMessageBox.information(self, "Missing Record IDs", "No events loaded.")
                return
            try:
                rids = full_table.column("record_id").to_pylist()
                srcs = full_table.column("source_file").to_pylist()
                for rid, src in zip(rids, srcs):
                    if rid is not None:
                        by_file[src or "<unknown>"].append(int(rid))
            except Exception as exc:
                QMessageBox.warning(self, "Missing Record IDs",
                                    f"Failed to read record IDs from Arrow table:\n{exc}")
                return
        else:
            events = self._active_events
            if not events:
                QMessageBox.information(self, "Missing Record IDs", "No events loaded.")
                return
            for ev in events:
                rid = ev.get("record_id")
                if rid is not None:
                    src = ev.get("source_file", "<unknown>")
                    by_file[src].append(int(rid))

        if not by_file:
            QMessageBox.information(self, "Missing Record IDs",
                                    "No Record ID data found in the loaded events.")
            return

        # Build report
        report_sections: list[str] = []
        total_missing = 0

        for src, ids in sorted(by_file.items()):
            ids_sorted = sorted(set(ids))
            lo, hi = ids_sorted[0], ids_sorted[-1]
            full_set = set(range(lo, hi + 1))
            missing = sorted(full_set - set(ids_sorted))
            total_missing += len(missing)

            # Compress consecutive missing IDs into ranges  (e.g. 5-8 instead of 5,6,7,8)
            ranges: list[str] = []
            if missing:
                start = prev = missing[0]
                for m in missing[1:]:
                    if m == prev + 1:
                        prev = m
                    else:
                        ranges.append(str(start) if start == prev else f"{start}\u2013{prev}")
                        start = prev = m
                ranges.append(str(start) if start == prev else f"{start}\u2013{prev}")

            import os as _os2
            fname = _os2.path.basename(src)
            section = (
                f"<b>{fname}</b><br>"
                f"&nbsp;&nbsp;Range: {lo:,} \u2013 {hi:,} &nbsp;|&nbsp; "
                f"Events: {len(ids_sorted):,} &nbsp;|&nbsp; "
                f"Expected: {hi - lo + 1:,}<br>"
            )
            if missing:
                section += (
                    f"&nbsp;&nbsp;<span style='color:#a01800;font-weight:bold;'>"
                    f"Missing ({len(missing):,}):</span> "
                    + ", ".join(ranges[:200])
                )
                if len(ranges) > 200:
                    section += f" <i>… and {len(ranges) - 200:,} more ranges</i>"
            else:
                section += (
                    f"&nbsp;&nbsp;<span style='color:#2e6820;font-weight:bold;'>"
                    f"No gaps — sequence is complete.</span>"
                )
            report_sections.append(section)

        dlg = _MissingRecordIdDialog(
            total_missing=total_missing,
            file_count=len(by_file),
            sections=report_sections,
            parent=self,
        )
        dlg.exec()

    def _on_add_remove_columns_dialog(self) -> None:
        """Open the Add/Remove Columns dialog and apply the result."""
        dlg = AddRemoveColumnsDialog(
            visible_cols=list(self._visible_cols),
            parent=self,
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        new_cols = dlg.get_visible_cols()
        if not new_cols:
            # Guard: never hide everything
            return
        self._apply_col_visibility_all(new_cols)

    # =========================================================================
    # CLOSE
    # =========================================================================

    def closeEvent(self, event) -> None:
        self._cleanup_juggernaut()
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
            self._worker.wait(3000)
        if self._analysis_runner is not None and self._analysis_runner.is_running():
            self._analysis_runner.request_stop()
        event.accept()

    # ── BOOKMARKS ─────────────────────────────────────────────────────────────

    def _build_bookmarks_tab(self) -> QWidget:
        """Build the Bookmarks tab — a table of bookmarked events with controls."""
        from PySide6.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        btn_row = QHBoxLayout()
        self._btn_filter_bookmarks = QPushButton("⚡ Filter to Bookmarks")
        self._btn_filter_bookmarks.setToolTip(
            "Filter the main event table to show only bookmarked events"
        )
        self._btn_filter_bookmarks.setEnabled(False)
        self._btn_filter_bookmarks.clicked.connect(self._filter_to_bookmarks)

        self._btn_clear_bookmarks = QPushButton("✕ Clear All")
        self._btn_clear_bookmarks.setToolTip("Remove all bookmarks")
        self._btn_clear_bookmarks.setEnabled(False)
        self._btn_clear_bookmarks.clicked.connect(self._clear_all_bookmarks)

        self._btn_export_bookmarks = QPushButton("⬇ Export")
        self._btn_export_bookmarks.setToolTip("Export bookmarks to CSV or JSON")
        self._btn_export_bookmarks.setEnabled(False)
        self._btn_export_bookmarks.clicked.connect(self._export_bookmarks)

        self._lbl_bm_count = QLabel("No bookmarks")
        self._lbl_bm_count.setObjectName("statsLabel")

        btn_row.addWidget(self._btn_filter_bookmarks)
        btn_row.addWidget(self._btn_clear_bookmarks)
        btn_row.addWidget(self._btn_export_bookmarks)
        btn_row.addStretch()
        btn_row.addWidget(self._lbl_bm_count)
        layout.addLayout(btn_row)

        self._tbl_bookmarks = QTableWidget(0, 5)
        self._tbl_bookmarks.setHorizontalHeaderLabels(
            ["Record ID", "Event ID", "Timestamp", "Computer", "Source File"]
        )
        _bm_hdr = self._tbl_bookmarks.horizontalHeader()
        _bm_hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        _bm_hdr.setStretchLastSection(False)
        for _ci, _cw in enumerate([80, 70, 140, 120, 260]):
            self._tbl_bookmarks.setColumnWidth(_ci, _cw)
        self._tbl_bookmarks.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._tbl_bookmarks.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self._tbl_bookmarks.setAlternatingRowColors(True)
        self._tbl_bookmarks.doubleClicked.connect(self._on_bookmark_double_click)
        layout.addWidget(self._tbl_bookmarks)
        return w

    def _refresh_bookmarks_tab(self) -> None:
        """Repopulate the bookmarks table from self._bookmarks."""
        from PySide6.QtWidgets import QTableWidgetItem
        tbl = self._tbl_bookmarks
        tbl.setRowCount(0)
        for bm in self._bookmarks:
            row = tbl.rowCount()
            tbl.insertRow(row)
            tbl.setItem(row, 0, QTableWidgetItem(str(bm.get("record_id", ""))))
            tbl.setItem(row, 1, QTableWidgetItem(str(bm.get("event_id", ""))))
            tbl.setItem(row, 2, QTableWidgetItem(str(bm.get("timestamp", ""))))
            tbl.setItem(row, 3, QTableWidgetItem(str(bm.get("computer", ""))))
            tbl.setItem(row, 4, QTableWidgetItem(str(bm.get("source_file", ""))))
        n = len(self._bookmarks)
        self._lbl_bm_count.setText(
            f"{n} bookmark{'s' if n != 1 else ''}" if n else "No bookmarks"
        )
        has = n > 0
        self._btn_filter_bookmarks.setEnabled(has)
        self._btn_clear_bookmarks.setEnabled(has)
        self._btn_export_bookmarks.setEnabled(has)

    def _bookmark_event(self, ev: dict) -> None:
        """Toggle bookmark for an event. Adds if not bookmarked, removes if already bookmarked."""
        rid = ev.get("record_id")
        if rid is None:
            return
        rid = int(rid)
        sf  = ev.get("source_file", "")
        key = (sf, rid)
        if key in self._bookmarked_keys:
            self._bookmarked_keys.discard(key)
            self._bookmarks = [
                b for b in self._bookmarks
                if not (int(b.get("record_id", -1)) == rid
                        and b.get("source_file", "") == sf)
            ]
        else:
            self._bookmarked_keys.add(key)
            self._bookmarks.append({
                "record_id":   rid,
                "event_id":    ev.get("event_id", ""),
                "timestamp":   ev.get("timestamp", ""),
                "computer":    ev.get("computer", ""),
                "source_file": sf,
            })
        self._refresh_bookmarks_tab()
        self._update_bookmark_button(ev)

    def _update_bookmark_button(self, ev: dict) -> None:
        """Reflect this event's bookmark status in the detail-pane bookmark button."""
        rid = ev.get("record_id")
        self._btn_bookmark_event.setEnabled(True)
        if rid is not None:
            key = (ev.get("source_file", ""), int(rid))
            if key in self._bookmarked_keys:
                self._btn_bookmark_event.setText("★ Bookmarked")
                self._btn_bookmark_event.setChecked(True)
                return
        self._btn_bookmark_event.setText("☆ Bookmark")
        self._btn_bookmark_event.setChecked(False)

    def _on_bookmark_toggle(self) -> None:
        """Clicked handler for _btn_bookmark_event — toggle bookmark on the selected event."""
        if self._hw_model is not None:
            indexes = self._active_table.selectionModel().selectedRows()
            if not indexes:
                return
            ev = self._hw_model.get_event(indexes[0].row())
        else:
            indexes = self._active_table.selectionModel().selectedRows()
            if not indexes:
                return
            ev = self._active_proxy.get_source_event(indexes[0].row())
        if ev:
            self._bookmark_event(ev)

    def _filter_to_bookmarks(self) -> None:
        """Filter the main event table to show only bookmarked events."""
        if not self._bookmarked_keys:
            self._set_status("No bookmarks to filter to")
            return
        keys = frozenset(self._bookmarked_keys)
        if self._hw_model is not None:
            self._hw_model.apply_bookmark_filter(keys)
        else:
            self._active_proxy.set_bookmark_filter(keys)
        self._update_count_label()
        n = len(keys)
        self._set_status(f"Showing {n} bookmarked event{'s' if n != 1 else ''}")

    def _export_bookmarks(self) -> None:
        """Export the bookmark list to CSV or JSON chosen by the user."""
        import csv
        import json as _json
        if not self._bookmarks:
            return
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Bookmarks",
            "bookmarks",
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        try:
            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
            fields = ["record_id", "event_id", "timestamp", "computer", "source_file"]
            if ext == "csv":
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
                    writer.writeheader()
                    writer.writerows(self._bookmarks)
            else:
                # Default to JSON if extension unrecognised or .json
                if not path.lower().endswith(".json"):
                    path += ".json"
                with open(path, "w", encoding="utf-8") as fh:
                    _json.dump(self._bookmarks, fh, indent=2, default=str)
            n = len(self._bookmarks)
            QMessageBox.information(
                self, "Exported",
                f"Exported {n} bookmark{'s' if n != 1 else ''} to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))

    def _clear_all_bookmarks(self) -> None:
        """Remove all bookmarks after user confirmation."""
        from PySide6.QtWidgets import QMessageBox
        if not self._bookmarks:
            return
        reply = QMessageBox.question(
            self, "Clear Bookmarks",
            f"Remove all {len(self._bookmarks)} bookmark(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return
        self._bookmarks.clear()
        self._bookmarked_keys.clear()
        self._refresh_bookmarks_tab()
        self._btn_bookmark_event.setText("☆ Bookmark")
        self._btn_bookmark_event.setChecked(False)

    def _on_bookmark_double_click(self, index) -> None:
        """Double-click a bookmark row — pivot the main table to that single event."""
        row = index.row()
        item = self._tbl_bookmarks.item(row, 0)
        if not item:
            return
        try:
            rid = int(item.text())
        except ValueError:
            return
        rid_set = frozenset([rid])
        if self._hw_model is not None:
            self._hw_model.apply_record_id_filter(rid_set)
        else:
            self._active_proxy.set_record_id_filter(rid_set)
        self._update_count_label()
        self._set_status(f"Pivot to bookmarked event (record_id={rid})")


# ── PS Extract Progress Dialog ────────────────────────────────────────────────

class _PSProgressDialog(QDialog):
    """Modal progress dialog shown during PowerShell forensic extraction."""

    cancel_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("PowerShell History — Running")
        self.setModal(True)
        self.setMinimumWidth(420)
        self.setWindowFlags(
            self.windowFlags()
            & ~Qt.WindowType.WindowContextHelpButtonHint
            & ~Qt.WindowType.WindowCloseButtonHint
        )
        # Set to True by force_close() so closeEvent knows extraction is done
        # and should allow the close rather than intercepting it as a cancel.
        self._extraction_done = False

        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(16, 16, 16, 16)

        self._lbl = QLabel("Initialising...")
        self._lbl.setWordWrap(True)
        layout.addWidget(self._lbl)

        self._bar = QProgressBar()
        self._bar.setRange(0, 100)
        self._bar.setValue(0)
        layout.addWidget(self._bar)

        self._btn_cancel = QPushButton("Cancel")
        self._btn_cancel.setFixedWidth(90)
        self._btn_cancel.clicked.connect(self._on_cancel_clicked)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(self._btn_cancel)
        layout.addLayout(btn_row)

    def force_close(self) -> None:
        """Close the dialog after extraction has finished (not a cancel)."""
        self._extraction_done = True
        self.close()

    def _on_cancel_clicked(self) -> None:
        self._btn_cancel.setEnabled(False)
        self._btn_cancel.setText("Cancelling\u2026")
        self._lbl.setText("Cancelling \u2014 please wait\u2026")
        self.cancel_requested.emit()

    def set_step(self, text: str) -> None:
        if self._btn_cancel.isEnabled():
            self._lbl.setText(text)

    def set_value(self, pct: int) -> None:
        self._bar.setValue(pct)

    def set_indeterminate(self, on: bool) -> None:
        if on:
            self._bar.setRange(0, 0)
        else:
            self._bar.setRange(0, 100)

    def closeEvent(self, event) -> None:
        """Intercept X-button close — trigger cancel instead of hiding.
        When force_close() is called (extraction complete/error), allow normally."""
        if self._extraction_done:
            event.accept()
        else:
            if self._btn_cancel.isEnabled():
                self._on_cancel_clicked()
            event.ignore()





# ── Diff Dialog ───────────────────────────────────────────────────────────────

class DiffDialog(QDialog):
    """Simple dialog for the diff command — pick two paths, run diff."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("EventHawk Diff Mode — Compare EVTX Sets")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        layout.addWidget(QLabel("Baseline path (normal/clean logs):"))
        row1 = QHBoxLayout()
        self._baseline = QLineEdit()
        btn1 = QPushButton("Browse")
        btn1.clicked.connect(lambda: self._pick_path(self._baseline))
        row1.addWidget(self._baseline)
        row1.addWidget(btn1)
        layout.addLayout(row1)

        layout.addWidget(QLabel("Incident path (logs during incident):"))
        row2 = QHBoxLayout()
        self._incident = QLineEdit()
        btn2 = QPushButton("Browse")
        btn2.clicked.connect(lambda: self._pick_path(self._incident))
        row2.addWidget(self._incident)
        row2.addWidget(btn2)
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Spike factor:"))
        self._spike = QSpinBox()
        self._spike.setRange(2, 100)
        self._spike.setValue(3)
        row3.addWidget(self._spike)
        row3.addStretch()
        layout.addLayout(row3)

        layout.addWidget(QLabel("Output file:"))
        row4 = QHBoxLayout()
        self._out = QLineEdit()
        self._out.setPlaceholderText("diff_report.html")
        btn4 = QPushButton("Save As")
        btn4.clicked.connect(self._pick_save)
        row4.addWidget(self._out)
        row4.addWidget(btn4)
        layout.addLayout(row4)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self._run_diff)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def _pick_path(self, target: QLineEdit) -> None:
        d = QFileDialog.getExistingDirectory(self, "Select directory")
        if d:
            target.setText(d)

    def _pick_save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Diff Report", "diff_report.html",
            "HTML (*.html);;JSON (*.json);;CSV (*.csv)"
        )
        if path:
            self._out.setText(path)

    def _run_diff(self) -> None:
        baseline = self._baseline.text().strip()
        incident = self._incident.text().strip()
        out      = self._out.text().strip()

        if not baseline or not incident:
            QMessageBox.warning(self, "Missing Input", "Both baseline and incident paths are required.")
            return
        if not out:
            QMessageBox.warning(self, "Missing Output", "Specify an output file.")
            return

        try:
            # Run diff in-process using the engine directly
            from pathlib import Path as _Path
            from evtx_tool.core.engine import ProcessingEngine
            from evtx_tool.core.filters import empty_filter
            from evtx_tool.output.exporters import export

            def _collect(p):
                pp = _Path(p)
                if pp.is_dir():
                    return sorted(str(f) for f in pp.rglob("*.evtx"))
                elif pp.is_file():
                    return [str(pp)]
                return []

            base_files = _collect(baseline)
            inc_files  = _collect(incident)
            if not base_files or not inc_files:
                QMessageBox.warning(self, "No Files", "No .evtx files found in one of the paths.")
                return

            fc = empty_filter()
            base_events = ProcessingEngine().run(base_files, fc)
            inc_events  = ProcessingEngine().run(inc_files,  fc)

            def _cnt(evts):
                d = {}
                for ev in evts:
                    eid = ev.get("event_id", 0)
                    d[eid] = d.get(eid, 0) + 1
                return d

            base_cnt = _cnt(base_events)
            inc_cnt  = _cnt(inc_events)
            sf = float(self._spike.value())
            new_eids   = sorted(set(inc_cnt) - set(base_cnt))
            spike_eids = {e for e in (set(base_cnt) & set(inc_cnt))
                          if inc_cnt[e] >= base_cnt[e] * sf}
            diff_events = [ev for ev in inc_events
                           if ev.get("event_id", 0) in (set(new_eids) | spike_eids)]
            diff_events.sort(key=lambda e: e.get("timestamp", ""))

            export(diff_events, out, None)
            QMessageBox.information(self, "Diff Complete",
                                    f"Diff: {len(diff_events):,} events\n"
                                    f"New EIDs: {len(new_eids)}  Spikes: {len(spike_eids)}\n\n"
                                    f"Report saved to:\n{out}")
            self.accept()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))
