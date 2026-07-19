"""
EventHawk — Main Window (PySide6)

Layout (3-panel + status bar):
  Left  : Input panel  — files, profiles, filters, analysis toggles, parse/stop
  Center: Events table (top splitter) + event detail (bottom splitter)
  Bottom: Analysis tabs — ATT&CK | IOCs | Chains | Case
  Status: Stats bar
"""

from __future__ import annotations

import logging
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

from PySide6.QtCore import (
    QModelIndex, QPoint, QSortFilterProxyModel, Qt, QThread, QTimer, Signal, Slot,
    QPropertyAnimation, QEasingCurve, QSettings, QFileSystemWatcher,
)
from PySide6.QtGui import (
    QAction, QColor, QFont, QKeySequence, QIcon, QPainter, QPixmap,
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

    # Signal:  (column_index, mode, values)
    #   mode = "include"  → keep only rows whose value is IN values  (use when popup
    #                       was truncated or user picked a small subset)
    #   mode = "exclude"  → keep all rows EXCEPT those whose value is IN values
    #                       (efficient when user unchecked only a few)
    #   mode = "clear"    → no filter for this column
    # Sending mode explicitly (instead of always emitting "excluded") fixes the
    # truncation bug: the popup caps at the top 1000 unique values, so events
    # with values outside that set used to slip past an EXCLUDE filter.
    filterApplied = Signal(int, str, list)
    sortRequested = Signal(int, Qt.SortOrder)  # (column_index, order)

    # Columns that support dropdown filtering  →  event-dict key
    FILTERABLE = {
        1:  "event_id",        # Event ID
        2:  "level_name",      # Level
        3:  "timestamp_date",  # Timestamp — date-level grouping (YYYY-MM-DD)
        4:  "computer",        # Computer
        5:  "channel",         # Channel
        6:  "user_id",         # User
        8:  "source_file",     # Source File
        # ── Extended columns ──────────────────────────────────────────────
        9:  "keywords",        # Keywords
        10: "opcode",          # Operational Code
        11: "log",             # Log
        12: "process_id",      # Process ID
        13: "thread_id",       # Thread ID
        15: "session_id",      # Session ID
        19: "correlation_id",  # Correlation Id
        21: "provider",        # Provider
    }

    def __init__(self, col_index: int, values: dict, parent=None,
                 search_provider=None):
        """
        Parameters
        ----------
        col_index : int
            Column index (matches COLUMNS list).
        values : dict
            ``{display_value: count}`` — from metadata or live data.
        search_provider : callable | None
            ``search_provider(term: str, callback: Callable[[dict], None])``.
            When provided, typing in the search box triggers a debounced query
            of the FULL underlying dataset (not just the top-1000 values shown
            initially).  Matching values returned via ``callback`` are merged
            into the checkbox list so a rare value (e.g. a specific
            correlation_id outside the top-1000) can still be found & selected.
        """
        super().__init__(parent, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self._col = col_index
        self._all_values = values
        self._search_provider = search_provider
        self._pending_search_term = ""
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
        self._inp_search.textChanged.connect(self._on_search_changed)
        root.addWidget(self._inp_search)

        # Debounce timer for the full-dataset re-query (only used when a
        # search_provider was supplied).  Keystrokes filter the in-memory list
        # instantly; the (potentially expensive) full-dataset query fires only
        # after the user pauses typing.
        self._search_debounce = QTimer(self)
        self._search_debounce.setSingleShot(True)
        self._search_debounce.setInterval(350)
        self._search_debounce.timeout.connect(self._run_full_search)

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
        """Filter the checkbox list as the user types in the search box.

        Auto-check semantics — important for correctness:

          * Visibility uses **substring** match against the value (not the
            label-with-count) so the user sees every candidate that mentions
            their search term.
          * Auto-check is restricted to **exact** value matches.  Substring
            matches stay visible but are auto-UNCHECKED so the user can see
            them and opt in only if they want them.

        Without the exact-match gate, typing ``5464`` in a Process ID column
        would also auto-check ``54640``, ``15464``, ``5464221``, etc. — the
        resulting "exclude everything not containing 5464" filter would then
        let events from all those PIDs through.  Users perceived this as the
        filter "not working".

        The empty-search branch restores the default state (all checked) so
        the popup behaves like "no filter active" the moment the search is
        cleared.
        """
        text_lower = text.lower()
        for chk in self._checkboxes:
            val = str(chk.property("filter_value") or "").lower()
            # Visibility: substring against the value itself (not the label
            # "{value}  ({count})", which would also match the count digits).
            visible = not text_lower or text_lower in val
            chk.setVisible(visible)
        if text_lower:
            # Hidden (no substring match) → unchecked.
            # Visible + exact match     → checked.
            # Visible + partial match   → unchecked (user opts in manually).
            for chk in self._checkboxes:
                if not chk.isVisible():
                    chk.setChecked(False)
                    continue
                val = str(chk.property("filter_value") or "").lower()
                chk.setChecked(val == text_lower)
        else:
            # Search cleared — restore all to checked
            for chk in self._checkboxes:
                chk.setChecked(True)

    def _on_search_changed(self, text: str) -> None:
        """Handle every keystroke in the search box.

        1. Immediately filter the already-loaded checkboxes in memory (fast).
        2. If a full-dataset ``search_provider`` is available and the term is
           non-trivial, (re)start the debounce timer so the underlying dataset
           is queried once the user pauses — surfacing values outside the
           initial top-1000.
        """
        self._filter_list(text)
        if not self._search_provider:
            return
        term = text.strip()
        if term:
            self._pending_search_term = term
            self._search_debounce.start()
        else:
            self._search_debounce.stop()

    def _run_full_search(self) -> None:
        """Debounce fired → query the full dataset for the pending term."""
        if not self._search_provider:
            return
        term = self._pending_search_term
        if not term:
            return
        try:
            self._search_provider(
                term,
                lambda vals, t=term: self._merge_search_results(t, vals),
            )
        except Exception:
            logger.exception("column-filter full-dataset search failed")

    def _merge_search_results(self, term: str, values: dict) -> None:
        """Merge full-dataset search hits into the checkbox list.

        Called (on the GUI thread) when the search worker finishes.  New
        values — ones not already present in the initial top-1000 — are added
        as checkboxes, then ``_filter_list`` is re-run so the existing
        auto-check-exact-match logic selects the value the user searched for.

        A stale-result guard drops results whose term no longer matches the
        current search box text (the user typed something else meanwhile).
        """
        if self._inp_search.text().strip() != term:
            return
        if not values:
            return
        existing = {chk.property("filter_value") for chk in self._checkboxes}
        added = False
        for val, count in sorted(values.items(), key=lambda kv: (-kv[1], str(kv[0]))):
            sval = str(val)
            if sval in existing:
                continue
            display = sval if sval else "(empty)"
            chk = QCheckBox(f"{display}  ({count})")
            chk.setChecked(False)
            chk.setProperty("filter_value", sval)
            self._checkboxes.append(chk)
            # Insert before the trailing stretch item added in _build_ui.
            self._list_layout.insertWidget(self._list_layout.count() - 1, chk)
            existing.add(sval)
            added = True
        if added:
            # Re-apply visibility + auto-check so a newly-merged exact match
            # becomes checked, ready for the user to click OK.  _apply() keys
            # off the LIVE search text (not a merge flag) to decide include vs
            # exclude, so nothing extra needs to be recorded here.
            self._filter_list(self._inp_search.text())

    def _check_all(self) -> None:
        for chk in self._checkboxes:
            if chk.isVisible():
                chk.setChecked(True)

    def _check_none(self) -> None:
        for chk in self._checkboxes:
            if chk.isVisible():
                chk.setChecked(False)

    def _apply(self) -> None:
        """Emit the filter selection in the most efficient *and* correct mode.

        The popup is capped at the top 1000 unique values for performance
        (ColValueWorker / NormalColValueWorker LIMIT 1000).  When the dataset
        actually has more than 1000 unique values, events with values OUTSIDE
        the visible top-1000 are silently absent from the popup.

        The previous behaviour always emitted "exclude unchecked" — which
        broke for the most common use case (the user checks one value to
        keep it):

           User has 5000 unique PIDs, popup shows top 1000.
           User checks only "916", unchecks 999.
           Old emit → exclude=[999 visible values].
           SQL → process_id NOT IN (999 values).
           Result → 916 PLUS the 4000 invisible PIDs all pass through.

        The fix is to choose mode by *which side is smaller*, so the popup
        emits the side that fully describes the user's intent:

          • If checked set is the small side  → emit "include" on checked.
            Untruncated values are correctly excluded (since they're not
            in the include list), matching what the user sees.
          • If unchecked set is the small side → emit "exclude" on unchecked.
            Untruncated values pass through (since they're not in the
            exclude list), matching "I unchecked a few specific things".
          • All checked or empty popup → emit "clear" (no filter).
          • Nothing checked → emit "include" on empty list (matches no rows).
        """
        checked: list[str]   = []
        unchecked: list[str] = []
        for chk in self._checkboxes:
            val = chk.property("filter_value")
            (checked if chk.isChecked() else unchecked).append(val)

        total = len(checked) + len(unchecked)
        if total == 0 or not unchecked:
            # Empty popup, or every value still checked → no filter on this column
            self.filterApplied.emit(self._col, "clear", [])
        elif not checked:
            # Every value unchecked → emit as EXCLUDE on the unchecked list.
            # This preserves the old "match nothing" semantic when the popup is
            # not truncated, while never emitting an empty include list (which
            # would need a fragile sentinel to behave like "match nothing" in
            # heavyweight_model's int-type quick-filter path).
            self.filterApplied.emit(self._col, "exclude", unchecked)
        elif len(checked) <= len(unchecked) or self._inp_search.text().strip():
            # Include list is smaller → emit include.  Also fixes the truncation
            # bug for the common "pick one value to keep" case: untruncated
            # values are correctly excluded because they're absent from the
            # include list, matching what the user sees in the popup.
            #
            # An ACTIVE search term also forces this branch even when checked is
            # the LARGER side.  With a search term the checked set is a
            # search-scoped selection ("keep the values matching what I typed"),
            # and a full-dataset search may have merged extra rows in — so the
            # unchecked set no longer describes the whole tail (the untruncated
            # values that were never loaded are neither checked nor unchecked).
            # Emitting exclude-on-unchecked there would let that tail slip
            # through; include-on-checked names exactly the values to keep.
            #
            # Note this is deliberately gated on the LIVE search text, not a
            # sticky "a merge happened" flag: once the user CLEARS the search
            # and goes back to unchecking a few values, exclude-on-unchecked is
            # correct again (the tail should pass), so the smaller-side
            # heuristic below must be allowed to choose exclude.
            self.filterApplied.emit(self._col, "include", checked)
        else:
            # Exclude list is smaller → emit exclude.  Efficient + correct when
            # the user explicitly saw and unchecked each of these values.
            self.filterApplied.emit(self._col, "exclude", unchecked)
        self.accept()

    def _emit_sort(self, order: Qt.SortOrder) -> None:
        """Emit sortRequested and close the popup without changing filter state."""
        self.sortRequested.emit(self._col, order)
        self.accept()


# ── Empty-table overlay ───────────────────────────────────────────────────────

class _EventTableView(QTableView):
    """QTableView that paints a centred 'No events' message when the model is
    empty (e.g. after a filter yields 0 rows).  Works for both proxy-model and
    direct-model usage because it simply checks rowCount() == 0."""

    _OVERLAY_TEXT = "No events match the current filter"

    def paintEvent(self, event) -> None:  # noqa: N802
        super().paintEvent(event)
        mdl = self.model()
        if mdl is None or mdl.rowCount() > 0:
            return

        # Only show the overlay when data was actually loaded but every row was
        # filtered away.  Without this guard the message also appears on the
        # empty table shown at startup before any file is opened.
        #
        # • Proxy models (normal mode): source model has rows but proxy has 0.
        # • Direct models (JM / ArrowTableModel): expose total_unfiltered_rows.
        # If neither check is satisfiable we stay silent (safe default).
        if hasattr(mdl, "sourceModel"):
            src = mdl.sourceModel()
            has_data = src is not None and src.rowCount() > 0
        else:
            has_data = bool(getattr(mdl, "total_unfiltered_rows", 0))
        if not has_data:
            return

        painter = QPainter(self.viewport())
        painter.save()
        pen_color = self.palette().color(self.palette().ColorRole.PlaceholderText)
        if not pen_color.isValid():
            pen_color = QColor("#888888")
        painter.setPen(pen_color)
        font = painter.font()
        font.setPointSize(max(font.pointSize() + 2, 13))
        painter.setFont(font)
        painter.drawText(
            self.viewport().rect(),
            Qt.AlignmentFlag.AlignCenter,
            self._OVERLAY_TEXT,
        )
        painter.restore()


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

class _JMSessionFetchWorker(QThread):
    """Two-phase background worker for the JM session-filter DuckDB query.

    Phase 1 — COUNT(*): fast metadata read, emits count_ready(n).
    Phase 2 — row fetch: waits for proceed() from the main thread, then
               runs the full SELECT and emits rows_ready(frozenset).

    Both phases run entirely on the worker thread so the main thread never
    blocks on a DuckDB query, regardless of the predicate complexity.

    Flow:
        worker.start()
        # main thread enters QEventLoop
        # worker emits count_ready(n)  →  main thread slot calls proceed(True/False)
        # worker emits rows_ready(keys) or query_failed(msg)
        # main thread slot calls loop.quit()
    """
    from PySide6.QtCore import Signal as _Sig
    count_ready  = _Sig(int)      # emitted after COUNT(*), before fetch
    rows_ready   = _Sig(object)   # frozenset[(source_file, record_id), ...]
    query_failed = _Sig(str)      # error message

    def __init__(self, duckdb_mod, scan_sql: str, where_sql: str,
                 params: list, row_limit: int) -> None:
        super().__init__()
        self._duckdb    = duckdb_mod
        self._scan_sql  = scan_sql
        self._where_sql = where_sql
        self._params    = params
        self._row_limit = row_limit
        import threading
        self._proceed_event = threading.Event()
        self._do_fetch      = True

    def proceed(self, do_fetch: bool = True) -> None:
        """Call from the main thread after receiving count_ready."""
        self._do_fetch = do_fetch
        self._proceed_event.set()

    def run(self) -> None:
        c = None
        try:
            c = self._duckdb.connect()

            # Phase 1: COUNT(*) — fast on Parquet (reads footer metadata).
            row = c.execute(
                f"SELECT COUNT(*) FROM {self._scan_sql} WHERE {self._where_sql}",
                self._params,
            ).fetchone()
            self.count_ready.emit(row[0] if row else 0)

            # Pause here until the main thread calls proceed() or the timeout
            # fires (5-minute safety net so the thread never hangs indefinitely).
            self._proceed_event.wait(timeout=300.0)
            if not self._do_fetch:
                return   # user canceled — rows_ready intentionally not emitted

            # Phase 2: full row fetch.
            rows = c.execute(
                f"SELECT source_file, record_id FROM {self._scan_sql} "
                f"WHERE {self._where_sql} LIMIT {self._row_limit}",
                self._params,
            ).fetchall()
            keys = frozenset(
                (r[0] or "", r[1]) for r in rows if r[1] is not None
            )
            self.rows_ready.emit(keys)
        except Exception as exc:
            self.query_failed.emit(str(exc))
        finally:
            # Always close the connection — covers normal exit, early return,
            # and exception paths so the DuckDB connection is never leaked.
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass


class _JMProxyShim:
    """Duck-type shim so JM per-file tabs satisfy the proxy interface."""

    def __init__(self, model) -> None:
        self._model = model

    # Called by _close_file_tab / _clear_results
    def setSourceModel(self, _) -> None:
        self._model.close()

    # Called by _set_session_filter / _clear_session_filter
    # Session filter for JM is handled at the top-level _hw_model; per-file
    # tabs don't need it separately.  Accept **kwargs so callers can pass
    # linked_lid= (and any future keyword args) without a TypeError.
    def set_session_filter(
        self,
        _logon_id,
        _computer=None,
        _start_ts=None,
        _end_ts=None,
        _end_inclusive=False,
        **_kwargs,      # absorbs linked_lid= and any future keyword args
    ) -> None:
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


# ── Custom QTableWidgetItem subclasses for correct column sorting ─────────────

class _DurationItem(QTableWidgetItem):
    """Sort by total seconds so '2h 05m 30s' > '5m 10s' > '30s' > 'Active' > '?'."""

    @staticmethod
    def _secs(text: str) -> int:
        if not text or text in ("?", "Active", "(wall clock)"):
            return -1
        import re as _re
        total = 0
        for n, unit in _re.findall(r"(\d+)\s*([hms])", text):
            n = int(n)
            if unit == "h":   total += n * 3600
            elif unit == "m": total += n * 60
            else:             total += n
        return total

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        return self._secs(self.text()) < self._secs(other.text())


class _IntItem(QTableWidgetItem):
    """Sort integer-valued cells numerically instead of lexicographically."""

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        try:
            return int(self.text()) < int(other.text())
        except ValueError:
            return self.text() < other.text()


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
        "12": "CachedRemoteInteractive (12)",
        "13": "CachedUnlock (13)",
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
        "11": "Cached credentials used (DC unreachable, local, or Microsoft account)",
        "12": "Cached RDP credentials used (DC unreachable or Microsoft account)",
        "13": "Workstation unlock using cached credentials",
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
        self._apply_display_filters()   # honour default checkbox state on first render

    # ── Session building ───────────────────────────────────────────────────

    def _build_sessions(self, events: list[dict]) -> list[dict]:
        """Scan events and build concrete session instances per (computer, LogonId).

        A single (computer, LogonId) bucket is still not enough because the
        same host can legitimately reuse a LogonId later.  We therefore start a
        new session instance on every 4624 and attach subsequent 4672 / 4688 /
        4634 events to the most recent instance for that (computer, LogonId)
        pair.
        """
        raw: dict[tuple[str, str], list[dict]] = {}

        def _norm_ts(raw_ts: object) -> str:
            ts = str(raw_ts or "").strip()
            if not ts:
                return ""
            ts = ts.rstrip("Z").replace("T", " ").split(".")[0]
            return ts[:19]

        def _latest_session(computer: str, lid: str) -> dict | None:
            sessions = raw.get((computer, lid), [])
            return sessions[-1] if sessions else None

        def _new_session(computer: str, lid: str) -> dict:
            sessions = raw.setdefault((computer, lid), [])
            sess = {
                "session_key":    (computer, lid, len(sessions)),
                "logon":          None,
                "privs":          [],
                "procs":          [],
                "logoff":         None,
                "first_seen_ts":  "",
                "last_seen_ts":   "",
                "related_keys":   set(),
                "linked_lid_raw": "",   # TargetLinkedLogonId from 4624, resolved later
                "linked_lid":     "",   # resolved sibling LogonId after post-pass
                "linked_session_key": None,  # exact sibling session identity
            }
            sessions.append(sess)
            return sess

        def _touch_session(sess: dict, ev: dict) -> None:
            ev_ts = _norm_ts(ev.get("timestamp", ""))
            if ev_ts:
                if not sess["first_seen_ts"] or ev_ts < sess["first_seen_ts"]:
                    sess["first_seen_ts"] = ev_ts
                if not sess["last_seen_ts"] or ev_ts > sess["last_seen_ts"]:
                    sess["last_seen_ts"] = ev_ts
            rid = ev.get("_record_id")
            if rid is not None:
                sess["related_keys"].add((str(ev.get("_source_file", "") or ""), rid))

        for ev in events:
            eid      = ev.get("event_id", 0)
            ed       = ev.get("event_data", {}) or {}
            computer = str(ev.get("computer", "") or "")

            if eid == 4624:
                lid = str(ed.get("TargetLogonId", "")).strip()
                if lid in self._SKIP_IDS:
                    continue
                sess = _new_session(computer, lid)
                sess["logon"] = ev
                _touch_session(sess, ev)
                linked_raw = str(ed.get("TargetLinkedLogonId", "")).strip()
                if linked_raw and linked_raw not in self._SKIP_IDS:
                    sess["linked_lid_raw"] = linked_raw
                continue

            if eid == 4672:
                lid = str(ed.get("SubjectLogonId", "")).strip()
                if lid in self._SKIP_IDS:
                    continue
                sess = _latest_session(computer, lid) or _new_session(computer, lid)
                sess["privs"].append(ev)
                _touch_session(sess, ev)
                continue

            if eid == 4688:
                lid = str(ed.get("SubjectLogonId", "")).strip()
                if lid in self._SKIP_IDS:
                    continue
                sess = _latest_session(computer, lid) or _new_session(computer, lid)
                sess["procs"].append(ev)
                _touch_session(sess, ev)
                continue

            if eid == 4634:
                lid = str(ed.get("TargetLogonId", "")).strip()
                if lid in self._SKIP_IDS:
                    continue
                sess = _latest_session(computer, lid)
                if sess is None or sess.get("logoff") is not None:
                    sess = _new_session(computer, lid)
                sess["logoff"] = ev
                _touch_session(sess, ev)

        # ── Post-pass: resolve TargetLinkedLogonId sibling pairs ──────────
        # Windows creates two sessions for elevated logons (split-token/UAC):
        # a filtered-token session and an elevated-token session, each with a
        # TargetLinkedLogonId pointing to the other.  Cross-link them so the
        # browser can annotate and filter both together.
        for (comp, lid), sess_list in raw.items():
            for sess in sess_list:
                linked_raw = sess.get("linked_lid_raw", "")
                if not linked_raw or sess.get("linked_lid"):
                    continue
                sibling_list = raw.get((comp, linked_raw), [])
                if not sibling_list:
                    continue
                # Match the sibling whose start time is closest to this session.
                own_ts = sess.get("first_seen_ts", "")
                def _ts_dist(ts_a: str, ts_b: str) -> float:
                    try:
                        from datetime import datetime as _dt
                        _fmt = "%Y-%m-%d %H:%M:%S"
                        return abs((_dt.strptime(ts_a[:19].replace("T", " "), _fmt)
                                    - _dt.strptime(ts_b[:19].replace("T", " "), _fmt)
                                    ).total_seconds())
                    except Exception:
                        return float("inf")
                best = min(
                    sibling_list,
                    key=lambda s: _ts_dist(s.get("first_seen_ts", "") or "", own_ts)
                                  if own_ts else 0.0,
                    default=sibling_list[0],
                )
                sess["linked_lid"] = linked_raw
                sess["linked_session_key"] = best.get("session_key")
                if not best.get("linked_lid"):
                    best["linked_lid"] = lid
                if not best.get("linked_session_key"):
                    best["linked_session_key"] = sess.get("session_key")

        result: list[dict] = []
        for (computer, lid), sessions in raw.items():
            for idx, sess in enumerate(sessions):
                logon_ev  = sess.get("logon")
                logoff_ev = sess.get("logoff")

                if logon_ev:
                    ed         = logon_ev.get("event_data", {}) or {}
                    user       = ed.get("TargetUserName") or ed.get("SubjectUserName") or ""
                    logon_type = str(ed.get("LogonType", "")).strip()
                    start_ts   = str(logon_ev.get("timestamp", "") or "")
                else:
                    user = logon_type = start_ts = ""

                scope_start_ts = _norm_ts(start_ts) or sess["first_seen_ts"]

                next_start_ts = ""
                for next_sess in sessions[idx + 1:]:
                    next_logon = next_sess.get("logon")
                    if next_logon:
                        next_start_ts = _norm_ts(next_logon.get("timestamp", ""))
                        if next_start_ts:
                            break

                explicit_end_ts = str(logoff_ev.get("timestamp", "") or "") if logoff_ev else ""
                explicit_end_norm = _norm_ts(explicit_end_ts)
                candidate_end = explicit_end_norm
                if sess["last_seen_ts"] and sess["last_seen_ts"] > candidate_end:
                    candidate_end = sess["last_seen_ts"]

                if next_start_ts and (not candidate_end or candidate_end >= next_start_ts):
                    scope_end_ts = next_start_ts
                    scope_end_inclusive = False
                else:
                    scope_end_ts = candidate_end
                    scope_end_inclusive = bool(scope_end_ts)

                if scope_start_ts and scope_end_ts:
                    dur_str = self._calc_duration(scope_start_ts, scope_end_ts)
                    # RDP/RemoteInteractive sessions can have disconnect gaps where
                    # the session persists but is idle.  Without 4778/4779 events
                    # we can only report wall-clock time, so flag it clearly.
                    if logon_type == "10":
                        dur_str += " (wall clock)"
                    duration = dur_str
                else:
                    duration = "Active" if scope_start_ts else ""

                has_dangerous = any(
                    any(dp in str((p.get("event_data") or {}).get("PrivilegeList", ""))
                        for dp in self._DANGEROUS_PRIVS)
                    for p in sess.get("privs", [])
                )

                result.append({
                    "session_key":         sess["session_key"],
                    "lid":                 lid,
                    "user":                user,
                    "computer":            computer,
                    "logon_type":          logon_type,
                    "logon_type_label":    self._TYPE_NAMES.get(logon_type, f"Type {logon_type}") if logon_type else "",
                    "initiation":          self._TYPE_INITIATION.get(logon_type, "") if logon_type else "",
                    "start_ts":            start_ts,
                    "end_ts":              scope_end_ts,
                    "scope_start_ts":      scope_start_ts,
                    "scope_end_ts":        scope_end_ts,
                    "scope_end_inclusive": scope_end_inclusive,
                    "duration":            duration,
                    "proc_count":          len(sess.get("procs", [])),
                    "priv_count":          len(sess.get("privs", [])),
                    "has_dangerous":       has_dangerous,
                    "logon_ev":            logon_ev,
                    "related_keys":        frozenset(sess["related_keys"]),
                    "linked_related_keys": frozenset(sess["related_keys"]),
                    "linked_lid":          sess.get("linked_lid", ""),
                    "linked_session_key":  sess.get("linked_session_key"),
                })

        # Post-pass: compute union time window for linked sibling pairs so the
        # session filter can span both sessions without cutting off events from
        # whichever sibling has the wider scope. Also carry the union of related
        # record keys so the JM fallback path can include both siblings when the
        # DuckDB query path is unavailable.
        _by_key: dict[tuple[str, str, int], dict] = {
            s["session_key"]: s for s in result
        }
        for _sd in result:
            _lnk_key = _sd.get("linked_session_key")
            if not _lnk_key:
                continue
            _sib = _by_key.get(_lnk_key)
            if not _sib:
                continue
            _starts = [t for t in (_sd["scope_start_ts"], _sib["scope_start_ts"]) if t]
            _ends   = [t for t in (_sd["scope_end_ts"],   _sib["scope_end_ts"])   if t]
            _union_start = min(_starts) if _starts else ""
            _union_end   = max(_ends)   if _ends   else ""
            _sd_end = _sd.get("scope_end_ts") or ""
            _sib_end = _sib.get("scope_end_ts") or ""
            if _sd_end and _sib_end:
                if _sib_end > _sd_end:
                    _union_end_inclusive = bool(_sib.get("scope_end_inclusive"))
                elif _sib_end < _sd_end:
                    _union_end_inclusive = bool(_sd.get("scope_end_inclusive"))
                else:
                    _union_end_inclusive = (
                        bool(_sd.get("scope_end_inclusive"))
                        or bool(_sib.get("scope_end_inclusive"))
                    )
            elif _sd_end:
                _union_end_inclusive = bool(_sd.get("scope_end_inclusive"))
            elif _sib_end:
                _union_end_inclusive = bool(_sib.get("scope_end_inclusive"))
            else:
                _union_end_inclusive = False
            _sd["linked_scope_start_ts"] = _union_start
            _sib["linked_scope_start_ts"] = _union_start
            _sd["linked_scope_end_ts"]   = _union_end
            _sib["linked_scope_end_ts"]   = _union_end
            _sd["linked_scope_end_inclusive"] = _union_end_inclusive
            _sib["linked_scope_end_inclusive"] = _union_end_inclusive
            _union_keys = frozenset(set(_sd["related_keys"]) | set(_sib["related_keys"]))
            _sd["linked_related_keys"] = _union_keys
            _sib["linked_related_keys"] = _union_keys

        result.sort(key=lambda s: (s["scope_start_ts"], s["computer"], s["lid"]))
        return result

    @staticmethod
    def _calc_duration(start: str, end: str) -> str:
        try:
            # Normalise both inputs to "YYYY-MM-DD HH:MM:SS" regardless of
            # whether they arrived with a T separator, trailing Z, or microseconds.
            def _norm(s: str) -> str:
                return s.strip().rstrip("Z").replace("T", " ").split(".")[0][:19]
            fmt     = "%Y-%m-%d %H:%M:%S"
            s_clean = _norm(start)
            e_clean = _norm(end)
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

        # ── Summary (populated by _apply_display_filters on first render) ──
        self._lbl_summary = QLabel()
        self._lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_summary.setStyleSheet("padding: 4px 0; font-size: 9pt; background:transparent;")
        root.addWidget(self._lbl_summary)

        # ── Search bar + display toggles ──────────────────────────────────
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText(
            "Filter by user, computer, session ID, or logon type…"
        )
        self._search_edit.textChanged.connect(self._apply_display_filters)
        search_row.addWidget(self._search_edit, stretch=1)

        self._chk_hide_service = QCheckBox("Hide service sessions (Type 5)")
        self._chk_hide_service.setChecked(True)
        self._chk_hide_service.setToolTip(
            "Service-account logons (Type 5) are usually same-second noise. "
            "Uncheck to include them."
        )
        self._chk_hide_service.toggled.connect(self._apply_display_filters)
        search_row.addWidget(self._chk_hide_service)
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
            elif not s["scope_end_ts"]:
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
                if col == 7:          # Duration — sort by total seconds
                    item = _DurationItem(text)
                elif col in (8, 9):   # Procs, Priv Events — sort numerically
                    item = _IntItem(text)
                else:
                    item = QTableWidgetItem(text)
                align = (
                    Qt.AlignmentFlag.AlignRight if col in right_align_cols
                    else Qt.AlignmentFlag.AlignLeft
                )
                item.setTextAlignment(align | Qt.AlignmentFlag.AlignVCenter)
                # Store the concrete session identity so reused LUIDs on the same
                # host still resolve to the correct browser row.
                item.setData(Qt.ItemDataRole.UserRole, s["session_key"])
                # Annotate the Session ID cell with its split-token sibling, if any.
                if col == 4 and s.get("linked_lid"):
                    item.setToolTip(
                        f"Split-token / UAC pair — linked session: {s['linked_lid']}\n"
                        "Filtering will include events from both sessions."
                    )
                if row_bg:
                    item.setBackground(row_bg)
                if col == 10 and s["has_dangerous"]:   # ⚠ Dangerous column (shifted +1)
                    item.setForeground(danger_fg)
                self._tbl.setItem(row, col, item)

        self._tbl.setSortingEnabled(True)
        self._shown_sessions = sessions

    # ── Interaction ───────────────────────────────────────────────────────

    def _apply_display_filters(self, *_) -> None:
        """Re-filter the session table applying both the search bar and the
        'Hide service sessions' checkbox, then refresh the summary line."""
        hide_service = self._chk_hide_service.isChecked()
        t = self._search_edit.text().strip().lower()
        sessions = self._all_sessions
        if hide_service:
            sessions = [s for s in sessions if s["logon_type"] != "5"]
        if t:
            sessions = [
                s for s in sessions
                if t in s["user"].lower()
                or t in s["computer"].lower()
                or t in s["lid"].lower()
                or t in s["logon_type_label"].lower()
            ]
        self._populate_table(sessions)
        self._update_summary(sessions)

    def _update_summary(self, sessions: list) -> None:
        total     = len(sessions)
        with_4624 = sum(1 for s in sessions if s["logon_ev"])
        active    = sum(1 for s in sessions if s["scope_start_ts"] and not s["scope_end_ts"])
        dangerous = sum(1 for s in sessions if s["has_dangerous"])
        danger_txt = (
            f"<span style='color:#a01800;font-weight:bold;'>⚠ {dangerous} with dangerous privileges</span>"
            if dangerous else
            "<span style='color:#2e6820;'>✓ No dangerous privileges detected</span>"
        )
        self._lbl_summary.setText(
            f"<b>{total}</b> session(s) &nbsp;│&nbsp; "
            f"<b>{with_4624}</b> with logon event &nbsp;│&nbsp; "
            f"<b>{active}</b> active (no logoff recorded) &nbsp;│&nbsp; "
            f"{danger_txt}"
        )

    def _selected_session(self) -> dict | None:
        row = self._tbl.currentRow()
        if row < 0:
            return None
        item = self._tbl.item(row, 4)   # Session ID column (index 4 after Initiation added)
        if not item:
            return None
        key = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(key, tuple) and len(key) == 3:
            for s in self._all_sessions:
                if s.get("session_key") == key:
                    return s
        else:
            # Fallback for any cell whose UserRole was not set (shouldn't happen).
            lid = key or item.text()
            for s in self._all_sessions:
                if s["lid"] == lid:
                    return s
        return None

    def _on_filter_clicked(self) -> None:
        import logging as _log
        sess = self._selected_session()
        if not sess:
            QMessageBox.information(self, "No Selection", "Select a session row first.")
            return
        try:
            _applied = self._on_filter_fn(sess["lid"], sess)
        except Exception:
            _log.getLogger("eventhawk.session").exception(
                "Session filter callback failed for LogonId=%s", sess.get("lid")
            )
            QMessageBox.critical(
                self, "Session Filter Error",
                "An error occurred applying the session filter.\n"
                "Details have been written to eventhawk_gui.log in the tool folder."
            )
            return
        # False means the callback ran but no filter was applied (user canceled,
        # or no matching events).  None / True both mean "filter active".
        if _applied is False:
            return
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

    def notify_filter_cleared(self) -> None:
        """Called by the main window when the session filter is cleared externally
        (e.g. via the 'Clear Session Filter' or 'Clear All Filters' button) so the
        dialog's own badge stays in sync."""
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


# ── WiFi History Browser dialog ───────────────────────────────────────────────

class _WifiHistoryDialog(QDialog):
    """
    Non-modal dialog listing WiFi connection/disconnection sessions parsed from
    Microsoft-Windows-WLAN-AutoConfig/Operational events (EIDs 8001/8003/8004/
    11001/11006).  Mirrors the _LogonSessionDialog architecture.
    """

    _WLAN_CHANNEL = "Microsoft-Windows-WLAN-AutoConfig/Operational"

    _RELEVANT_EIDS = frozenset({8001, 8002, 8003, 8004, 11001, 11006})

    _REASON_CODES: dict[int, str] = {
        # ── 802.11 standard reason codes (IEEE 802.11-2020) ───────────────
        0:  "Success / clean disconnect",
        1:  "Unspecified failure",
        2:  "Authentication timeout / previous auth no longer valid",
        3:  "Deauthenticated — station left or is leaving",
        4:  "Disassociated — inactivity timeout",
        5:  "Disassociated — AP too busy / overloaded",
        6:  "Class 2 frame received from unauthenticated station",
        7:  "Class 3 frame received from unassociated station",
        8:  "Disassociated — STA left or is leaving BSS",
        9:  "Requesting STA is not authenticated",
        10: "Disassociated — power capability element unacceptable",
        11: "Disassociated — supported channels element unacceptable",
        12: "Disassociated — BSS transition management",
        13: "Invalid information element",
        14: "MIC failure",
        15: "4-Way handshake timeout",
        16: "Group key handshake timeout",
        17: "IE in 4-Way handshake differs from (re)assoc request",
        18: "Invalid group cipher",
        19: "Invalid pairwise cipher",
        20: "Invalid AKMP (key management)",
        21: "Unsupported RSNE version",
        22: "Invalid RSNE capabilities field",
        23: "802.1X authentication failed",
        24: "Cipher suite rejected by security policy",
        25: "TDLS direct-link teardown — peer unreachable",
        26: "TDLS direct-link teardown — unspecified reason",
        27: "Disassociated — SSP requested",
        28: "No SSP roaming agreement",
        29: "Requested service rejected — SSP cipher suite",
        30: "Requested service not authorized",
        31: "TS deleted — DLS teardown unreachable",
        32: "DLS teardown — unspecified reason",
        33: "Destination STA not present in DLS",
        34: "Destination STA not QoS-capable",
        35: "Disassociated — QoS listener timeout",
        36: "Disassociated — QoS-related failure",
        37: "Disassociated — insufficient QoS bandwidth",
        38: "Disassociated — excessive frames not acknowledged",
        39: "Disassociated — STA transmitting outside TXOP limit",
        40: "Peer STA requesting disconnect / BSS transition",
        41: "Peer STA not responding (end of TXOP)",
        42: "Peer STA declined addts request",
        43: "Requested from peer — DLS",
        44: "STA does not support requested bandwidth",
        45: "SME cancels authentication exchange",
        46: "Peer declined AddTS",
        47: "Requested from peer (DLS teardown)",
        48: "Mesh peering cancelled — no further reason",
        49: "Mesh maximum number of peers reached",
        50: "Mesh configuration policy violation",
        51: "Mesh close received from peer",
        52: "Mesh maximum retries exceeded — unable to confirm",
        53: "Mesh confirm timeout",
        54: "Mesh invalid GTK",
        55: "Mesh inconsistent parameters",
        56: "Mesh invalid security capability",
        57: "Mesh path selection failure",
        58: "No proxy information available (mesh)",
        59: "Destination not reachable in mesh",
        60: "MAC address already exists in MBSS",
        61: "Mesh channel switch completed",
        62: "Mesh channel switch failed",
        # Extended/non-standard codes used by Windows drivers
        65533: "Peer leaving",
        65534: "Deauthentication frame received",
        65535: "Association expired / lost",

        # ── Windows WLAN API — auto-connect failure codes (0x41000+) ─────
        # WLAN_REASON_CODE_CONNECT_BASE = 0x41000 = 266240
        266241: "Profile not compatible with detected network",          # 0x41001
        266242: "Network not compatible with profile settings",          # 0x41002
        266243: "Profile specifies manual connection only",              # 0x41003
        266244: "Network not visible / out of range",                    # 0x41004
        266245: "Connection blocked by Group Policy",                    # 0x41005
        266246: "Connection denied by user",                             # 0x41006
        266247: "BSS type (infrastructure/ad-hoc) not allowed",          # 0x41007
        266248: "Network is in the failed-connection list",              # 0x41008
        266249: "Network is in the blocked-connection list",             # 0x41009
        266250: "Preferred SSID list too long",                          # 0x4100A
        266251: "WlanConnect call failed",                               # 0x4100B
        266252: "WlanScan call failed",                                  # 0x4100C
        266253: "Network not available (no BSS found)",                  # 0x4100D
        266254: "Profile changed or deleted during connection attempt",  # 0x4100E
        266255: "WEP key mismatch",                                      # 0x4100F
        266256: "User did not respond to credentials prompt",            # 0x41010

        # ── Windows WLAN API — MSMSEC profile validation (0x44000+) ─────
        # WLAN_REASON_CODE_MSMSEC_CONNECT_BASE = 0x44000 = 278528
        278528: "MSMSEC: Invalid WEP key index in profile",              # 0x44000
        278529: "MSMSEC: PSK/passphrase present but not required",       # 0x44001
        278530: "MSMSEC: WEP key length invalid",                        # 0x44002
        278531: "MSMSEC: PSK/passphrase length invalid",                 # 0x44003
        278532: "MSMSEC: No auth/cipher pair specified in profile",      # 0x44004
        278533: "MSMSEC: Too many auth/cipher pairs in profile",         # 0x44005
        278534: "MSMSEC: Duplicate auth/cipher pair in profile",         # 0x44006
        278535: "MSMSEC: Profile raw data is invalid",                   # 0x44007
        278536: "MSMSEC: Invalid auth/cipher combination in profile",    # 0x44008
        278537: "MSMSEC: 802.1X enabled in profile but AP uses PSK",     # 0x44009
        278538: "MSMSEC: FIPS required but not supported by driver",     # 0x4400A
        278539: "MSMSEC: Profile requires key mapping but none found",   # 0x4400B
        278540: "MSMSEC: CSP does not support requested credentials",    # 0x4400C

        # ── Windows WLAN API — MSMSEC runtime/security failure (0x45000+)
        # WLAN_REASON_CODE_MSMSEC_DISCONNECT_BASE = 0x45000 = 282624
        282624: "MSMSEC: Security capability mismatch with AP",          # 0x45000
        282625: "MSMSEC: Security capability mismatch with profile",     # 0x45001
        282626: "MSMSEC: 802.1X authentication failed at runtime",       # 0x45002
        282627: "MSMSEC: IHV reported security capability mismatch",     # 0x45003
        282628: "MSMSEC: Security downgrade attempt detected",           # 0x45004
        282629: "MSMSEC: Authenticator reported failure",                # 0x45005
        282630: "MSMSEC: 802.1X UI request failed",                      # 0x45006
        282631: "MSMSEC: Crypto module failed to start",                 # 0x45007
        282632: "MSMSEC: Crypto module reporting failure",               # 0x45008
        282633: "MSMSEC: Key exchange failed",                           # 0x45009
        282634: "MSMSEC: Failed to set unicast key",                     # 0x4500A
        282635: "MSMSEC: Failed to set multicast/broadcast key",         # 0x4500B
        282636: "MSMSEC: Message 1 of 4-way handshake timeout",          # 0x4500C
        282637: "MSMSEC: Message 3 of 4-way handshake timeout",          # 0x4500D
        282638: "MSMSEC: Message 1 of group key handshake timeout",      # 0x4500E
        282639: "MSMSEC: Message 1 of group key handshake retry timeout",# 0x4500F
        282640: "MSMSEC: EAPOL-Start timeout (no response from AP)",     # 0x45010
        282641: "MSMSEC: Too many EAPOL-Start messages sent",            # 0x45011
        282642: "MSMSEC: 802.1X protocol not supported by AP",           # 0x45012
        282643: "MSMSEC: 802.1X module not available for auth",          # 0x45013
    }

    _OUI_TABLE: dict[str, str] = {
        "00:50:F2": "Microsoft",        "00:1A:A2": "Cisco",          "04:BF:6D": "TP-Link",
        "14:CC:20": "TP-Link",          "50:D4:F7": "TP-Link",        "A0:F3:C1": "TP-Link",
        "00:1B:2F": "ASUS",             "10:BF:48": "ASUS",           "2C:FD:A1": "ASUS",
        "00:24:D7": "Netgear",          "9C:3D:CF": "Netgear",        "A0:40:A0": "Netgear",
        "00:17:F2": "Apple",            "00:1C:B3": "Apple",          "04:26:65": "Apple",
        "7C:6D:62": "Apple",            "F8:FF:C2": "Apple",          "AC:BC:32": "Apple",
        "00:23:14": "Intel",            "40:25:C2": "Intel",          "5C:51:4F": "Intel",
        "7C:76:35": "Intel",            "8C:8D:28": "Intel",          "A4:C3:F0": "Qualcomm",
        "00:90:4C": "Broadcom",         "00:15:6D": "Ubiquiti",       "04:18:D6": "Ubiquiti",
        "F4:F5:D8": "Google",           "AC:63:BE": "Amazon",         "FC:A6:67": "Amazon",
        "00:12:47": "Samsung",          "84:C9:B2": "Samsung",        "00:E0:4C": "Realtek",
        "00:0B:86": "Aruba",            "20:4C:03": "Aruba",          "00:26:CB": "Cisco",
        "00:40:96": "Cisco",            "70:70:8B": "Cisco",          "00:1A:30": "Cisco",
        "00:1F:CA": "Cisco",            "00:22:90": "Cisco",          "E8:40:F2": "Cisco",
        "00:26:99": "Cisco",            "18:33:9D": "Cisco",          "B4:DE:31": "Cisco",
        "00:17:DF": "Ruckus",           "D4:68:4D": "Ruckus",         "00:24:39": "Motorola",
        "00:60:B3": "Motorola",         "00:1B:77": "Dell",           "F8:B1:56": "Dell",
        "00:21:9B": "Belkin",           "94:44:52": "Belkin",         "00:13:10": "Linksys",
        "00:18:F8": "Linksys",          "00:14:BF": "Linksys",        "00:26:B9": "D-Link",
        "C8:BE:19": "D-Link",           "1C:7E:E5": "D-Link",         "90:F6:52": "D-Link",
        "00:E0:4B": "D-Link",           "14:D6:4D": "D-Link",         "28:10:7B": "D-Link",
        "00:A0:C5": "ZyXEL",            "00:13:49": "ZyXEL",          "FC:F5:28": "ZyXEL",
        "5C:63:BF": "Xiaomi",           "F4:8B:32": "Xiaomi",         "8C:BE:BE": "Xiaomi",
        "10:2A:B3": "Huawei",           "54:89:98": "Huawei",         "04:F9:38": "Huawei",
        "28:31:52": "Huawei",           "68:CC:6E": "Huawei",         "A0:08:6F": "Huawei",
        "00:9A:CD": "Huawei",           "00:E0:FC": "Huawei",         "00:22:A1": "Motorola",
        "00:24:E8": "Motorola",         "84:10:0D": "Motorola",       "00:1C:10": "Meru Networks",
        "34:BD:C8": "HP",               "3C:D9:2B": "HP",             "9C:B6:54": "HP",
        "00:26:55": "HP",               "1C:98:EC": "HP",             "18:A9:05": "Juniper",
        "28:C0:DA": "Juniper",          "44:F4:77": "Juniper",        "00:05:85": "Juniper",
        "2C:21:72": "Juniper",          "00:80:C8": "D-Link",         "00:0C:E6": "Meru Networks",
    }

    _SECURITY_GRADE_MAP: dict[str, str] = {
        "sae":    "WPA3",
        "owe":    "WPA3",
        "wpa3":   "WPA3",
        "rsna":   "WPA2",
        "wpa2":   "WPA2",
        "ccmp":   "WPA2",
        "802.1x": "WPA2-ENT",
        "wpa":    "WPA",
        "tkip":   "WPA",
        "wep":    "WEP",
        "open":   "OPEN",
    }

    _HEADERS = [
        "SSID", "BSSID", "Vendor", "Adapter",
        "Connected", "Disconnected", "Duration",
        "Security", "Band/Channel", "PHY",
        "Disconnect Reason", "Flags",
    ]

    def __init__(self, events: list[dict], truncated: bool = False, parent=None):
        super().__init__(parent)
        self._all_sessions:   list[dict] = self._build_sessions(events)
        self._shown_sessions: list[dict] = list(self._all_sessions)
        # Carry provenance so summary and export can reflect incomplete datasets.
        self._truncated: bool = truncated
        self._build_ui()
        self._apply_display_filters()

    # ── Session building ───────────────────────────────────────────────────

    @staticmethod
    def _extract_ed(event: dict) -> dict[str, str]:
        """Extract EventData fields — handles flat dict, list-of-Data, and #text shapes."""
        ed_raw = event.get("event_data") or {}
        if not isinstance(ed_raw, dict):
            return {}
        result: dict[str, str] = {}
        # Shape A: flat key→value dict (already expanded)
        if any(k not in ("Data", "#text") for k in ed_raw):
            for k, v in ed_raw.items():
                if not k.startswith("#") and not k.startswith("@"):
                    result[k] = str(v or "")
            return result
        data = ed_raw.get("Data")
        if data is None:
            # Shape C fallback: top-level #text with "Key=Value\n" lines
            raw_text = str(ed_raw.get("#text", ""))
            for line in raw_text.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    result[k.strip()] = v.strip()
            return result
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    name = item.get("@Name", "")
                    val  = item.get("#text", "")
                    if name:
                        result[str(name)] = str(val or "")
            return result
        if isinstance(data, dict):
            name = data.get("@Name", "")
            val  = data.get("#text", "")
            if name:
                result[str(name)] = str(val or "")
            return result
        if isinstance(data, str):
            for line in data.splitlines():
                if "=" in line:
                    k, _, v = line.partition("=")
                    result[k.strip()] = v.strip()
        return result

    @staticmethod
    def _norm_iface(raw: str) -> str:
        return raw.strip("{}").lower().strip()

    @staticmethod
    def _norm_bssid(raw: str) -> str:
        return raw.upper().replace("-", ":").strip()

    @staticmethod
    def _lookup_oui(bssid: str) -> str:
        parts = bssid.split(":")
        if len(parts) < 3:
            return "Unknown"
        oui = ":".join(parts[:3]).upper()
        return _WifiHistoryDialog._OUI_TABLE.get(oui, "Unknown")

    @staticmethod
    def _derive_security(auth: str, cipher: str) -> str:
        a = (auth + " " + cipher).lower().replace("-", "").replace("_", "")
        for key, grade in _WifiHistoryDialog._SECURITY_GRADE_MAP.items():
            if key in a:
                return grade
        if not auth and not cipher:
            return "Unknown"
        return "Unknown"

    @staticmethod
    def _derive_band(channel: int) -> str:
        if channel == 0:
            return "Unknown"
        if 1 <= channel <= 14:
            return "2.4 GHz"
        if channel in {
            36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120,
            124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177,
        }:
            return "5 GHz"
        return "5/6 GHz"

    @staticmethod
    def _phy_label(phy_raw: str) -> str:
        _MAP = {
            "1": "FHSS",          "2": "DSSS (802.11b)",   "3": "IR",
            "4": "OFDM (802.11a)", "5": "HR-DSSS (802.11b+)", "6": "ERP (802.11g)",
            "7": "802.11n (HT)",  "8": "802.11ac (VHT)",   "9": "DMG (802.11ad)",
            "10": "802.11ax (HE/WiFi 6)", "11": "802.11be (EHT/WiFi 7)",
            "dsss": "DSSS (802.11b)", "ofdm": "OFDM (802.11a)", "hrdsss": "HR-DSSS (802.11b+)",
            "erp": "ERP (802.11g)", "ht": "802.11n (HT)", "vht": "802.11ac (VHT)",
            "he": "802.11ax (HE/WiFi 6)", "eht": "802.11be (EHT/WiFi 7)",
        }
        return _MAP.get(str(phy_raw).lower(), str(phy_raw)) if phy_raw else ""

    @staticmethod
    def _calc_duration(ts_start: str, ts_end: str) -> tuple[str, float]:
        """Returns (display_str, total_seconds). total_seconds=-1 on parse error.

        Medium fix: negative durations are no longer silently flipped with abs().
        A negative result means disconnect < connect (mis-pairing or clock skew);
        the display label surfaces this as '⚠ Out-of-order' so it is visible in
        the table and anomaly-flag logic instead of being hidden as a short session.
        """
        try:
            fmt = "%Y-%m-%d %H:%M:%S"
            def _norm(ts: str) -> str:
                return ts.rstrip("Z").replace("T", " ").split(".")[0][:19]
            td    = datetime.strptime(_norm(ts_end), fmt) - datetime.strptime(_norm(ts_start), fmt)
            total = td.total_seconds()
            if total < 0:
                return "⚠ Out-of-order", -1.0
            h, rem = divmod(int(total), 3600)
            m, sec = divmod(rem, 60)
            if h > 0:
                return f"{h}h {m:02d}m {sec:02d}s", total
            if m > 0:
                return f"{m}m {sec:02d}s", total
            return f"{sec}s", total
        except Exception:
            return "?", -1.0

    @staticmethod
    def _norm_ts(raw_ts: object) -> str:
        ts = str(raw_ts or "").strip()
        if not ts:
            return ""
        return ts.rstrip("Z").replace("T", " ").split(".")[0][:19]

    @staticmethod
    def _decode_reason(code: int) -> str:
        """Decode a WLAN disconnect/failure reason code to a human-readable string.

        Covers:
          - 802.11 standard codes (0–65535)
          - Windows WLAN API codes (0x41000–0x45xxx)
          - Unknown Windows codes: hex value + range description
        """
        if code == 0:
            return ""
        known = _WifiHistoryDialog._REASON_CODES.get(code)
        if known:
            return known
        # For unknown Windows WLAN API codes, show hex + range label so the
        # raw decimal (e.g. 294932) is at least identifiable at a glance.
        if code > 0xFFFF:
            h = f"0x{code:X}"
            if   0x41000 <= code <= 0x41FFF:  area = "WLAN auto-connect failure"
            elif 0x42000 <= code <= 0x42FFF:  area = "WLAN disconnect"
            elif 0x43000 <= code <= 0x43FFF:  area = "MSMSEC general"
            elif 0x44000 <= code <= 0x44FFF:  area = "MSMSEC profile validation"
            elif 0x45000 <= code <= 0x45FFF:  area = "MSMSEC security runtime"
            elif 0x46000 <= code <= 0x46FFF:  area = "WLAN IHV connect"
            elif 0x47000 <= code <= 0x47FFF:  area = "WLAN IHV security"
            elif 0x48000 <= code <= 0x4FFFF:  area = "WLAN driver/extended"
            elif code == 0xFFFF0000:           return "Unknown WLAN reason"
            else:                              area = "Windows WLAN API"
            return f"{area} ({h})"
        return f"Code {code}"

    @staticmethod
    def _build_sessions(events: list[dict]) -> list[dict]:
        """
        Single-pass WLAN event filter → sort → pair 8001↔8003 by InterfaceGuid.
        Orphan 8001s (still connected) are included with disconnect_ts="".
        Channel/PHY backfilled from nearest 11001 within 30 s.
        """
        WLAN_CH = _WifiHistoryDialog._WLAN_CHANNEL
        REL     = _WifiHistoryDialog._RELEVANT_EIDS
        _ex     = _WifiHistoryDialog._extract_ed
        _ni     = _WifiHistoryDialog._norm_iface
        _nb     = _WifiHistoryDialog._norm_bssid
        _nts    = _WifiHistoryDialog._norm_ts

        # Collect and categorise WLAN events
        connect_ev:   list[dict] = []
        disco_ev:     list[dict] = []
        assoc_ev:     list[dict] = []   # EID 11001 — channel / PHY
        auth_fail_ev: list[dict] = []   # EID 11006

        for ev in events:
            ch = str(ev.get("channel") or ev.get("Channel") or "")
            # Low/Medium fix: use exact equality instead of substring containment.
            # The old "ch not in WLAN_CH" let any short prefix like "Microsoft"
            # slip through because it IS a substring of the full channel name.
            # Exact match (case-insensitive) is both safer and faster.
            if ch.lower() != WLAN_CH.lower():
                continue
            try:
                eid = int(ev.get("event_id") or ev.get("EventID") or 0)
            except (ValueError, TypeError):
                eid = 0
            if eid not in REL:
                continue
            ed = _ex(ev)
            ts = _nts(ev.get("timestamp") or ev.get("Timestamp") or ev.get("TimeCreated") or "")
            # Medium/High fix: use source_file as fallback when computer is blank
            # so events from different EVTX files are still separated even if the
            # Computer field is absent.  When both are empty we accept the residual
            # limitation — events genuinely share the ("", iface) namespace.
            computer = str(
                ev.get("computer") or ev.get("Computer") or
                ev.get("source_file") or ev.get("SourceFile") or ""
            ).lower()
            entry = {"eid": eid, "ts": ts, "ed": ed, "computer": computer}

            if eid in (8001, 8004):
                connect_ev.append(entry)
            elif eid in (8002, 8003):
                disco_ev.append(entry)
            elif eid == 11001:
                assoc_ev.append(entry)
            elif eid == 11006:
                auth_fail_ev.append(entry)

        if not connect_ev and not disco_ev:
            return []

        # Pair connects with disconnects in chronological order per interface.
        # Key: (computer, iface) so events from different hosts in merged datasets
        # are never paired together, even if they share the same InterfaceGuid.
        all_conn_disco = sorted(connect_ev + disco_ev, key=lambda x: x["ts"])

        # pending: (computer, iface) → list[open session dict] (FIFO)
        pending: dict[tuple, list[dict]] = {}
        sessions: list[dict] = []
        _missing_ctr = 0   # synthetic key counter for events with no InterfaceGuid

        for w in all_conn_disco:
            eid      = w["eid"]
            ed       = w["ed"]
            ts       = w["ts"]
            computer = w["computer"]

            iface_raw = ed.get("InterfaceGuid", "") or ed.get("InterfaceGUID", "")
            iface     = _ni(iface_raw)
            # High fix: empty InterfaceGuid must not share a bucket — events
            # with no GUID cannot be reliably paired, so give each a unique
            # synthetic key so they don't accidentally collide.
            if not iface:
                _missing_ctr += 1
                iface = f"__no_guid_{_missing_ctr}__"
            pkey = (computer, iface)

            if eid in (8001, 8004):
                ssid    = (ed.get("ProfileName") or ed.get("SSIDString")
                           or ed.get("SSID") or "(hidden)")
                bssid   = _nb(ed.get("BSSID") or ed.get("bssid") or "")
                auth    = ed.get("AuthenticationAlgorithm", "") or ed.get("Authentication", "")
                cipher  = ed.get("CipherAlgorithm", "") or ed.get("Cipher", "")
                adapter = ed.get("InterfaceDescription", "") or ed.get("Interface", "")
                sess = {
                    "ssid":              ssid,
                    "bssid":             bssid,
                    "oui_vendor":        _WifiHistoryDialog._lookup_oui(bssid) if bssid else "Unknown",
                    "adapter":           adapter,
                    "interface_guid":    iface,
                    # Low fix: carry computer into session so 11001/11006
                    # enrichment can constrain by host in merged datasets.
                    "computer":          computer,
                    "connect_ts":        ts,
                    "disconnect_ts":     "",
                    "duration":          "Active",
                    "duration_secs":     -1.0,
                    "auth":              auth,
                    "cipher":            cipher,
                    "security_grade":    _WifiHistoryDialog._derive_security(auth, cipher),
                    "channel":           0,
                    "frequency_band":    "Unknown",
                    "phy_label":         "",
                    "disconnect_reason": "",
                    "auth_failures":     0,
                    "connect_eid":       eid,
                    "anomaly_flags":     [],
                }
                pending.setdefault(pkey, []).append(sess)

            elif eid in (8002, 8003):
                open_list = pending.get(pkey, [])
                if open_list:
                    sess = open_list.pop(0)
                    if not open_list:
                        del pending[pkey]
                    reason_raw = ed.get("ReasonCode", "") or ed.get("Reason", "")
                    try:
                        reason_int = int(reason_raw, 0) if reason_raw else 0
                    except (ValueError, TypeError):
                        reason_int = 0
                    reason_str = _WifiHistoryDialog._decode_reason(reason_int)
                    dur_label, dur_secs    = _WifiHistoryDialog._calc_duration(sess["connect_ts"], ts)
                    sess["disconnect_ts"]  = ts
                    sess["duration"]       = dur_label
                    sess["duration_secs"]  = dur_secs
                    sess["disconnect_reason"] = reason_str
                    sessions.append(sess)
                # Orphaned disconnect (no matching connect) — skip

        # Remaining pending sessions = still connected (no disconnect recorded).
        # Medium fix: EID 8004 events are connection *attempts* that failed —
        # they never produced a real connection, so if no disconnect paired them
        # they must not appear as "Active".  Mark them "Failed (no close)" so
        # they are visually distinct from genuinely active sessions.
        for iface_list in pending.values():
            for s in iface_list:
                if s["connect_eid"] == 8004 and not s["disconnect_ts"]:
                    s["duration"] = "Failed (no close)"
            sessions.extend(iface_list)

        # Backfill channel / PHY from nearest EID 11001 on same interface (within 30 s).
        # High fix: also constrain by computer so enrichment never leaks across
        # hosts in a merged dataset.  BSSID guard prevents roam-neighbour bleed.
        for sess in sessions:
            iface    = sess["interface_guid"]
            computer = sess["computer"]
            conn_ts  = sess["connect_ts"]
            best:       dict | None = None
            best_delta: float       = 1e18
            for a in assoc_ev:
                # Host-scope guard: skip if both sides have a computer name and they differ
                if computer and a["computer"] and a["computer"] != computer:
                    continue
                a_iface = _ni(a["ed"].get("InterfaceGuid", "") or a["ed"].get("InterfaceGUID", ""))
                if a_iface != iface:
                    continue
                # Medium fix: skip if BSSIDs are both known but differ
                a_bssid = _nb(a["ed"].get("BSSID") or "")
                if a_bssid and sess["bssid"] and a_bssid != sess["bssid"]:
                    continue
                try:
                    fmt    = "%Y-%m-%d %H:%M:%S"
                    a_dt   = datetime.strptime(a["ts"], fmt)
                    c_dt   = datetime.strptime(conn_ts, fmt)
                    delta  = abs((a_dt - c_dt).total_seconds())
                    if delta < best_delta:
                        best_delta = delta
                        best = a
                except Exception:
                    pass
            if best and best_delta < 30:
                aed = best["ed"]
                try:
                    ch = int(aed.get("Channel", 0) or 0)
                except (ValueError, TypeError):
                    ch = 0
                phy_raw = str(aed.get("PHYType", "") or aed.get("PhyType", ""))
                sess["channel"]        = ch
                sess["frequency_band"] = _WifiHistoryDialog._derive_band(ch)
                sess["phy_label"]      = _WifiHistoryDialog._phy_label(phy_raw)
                if not sess["bssid"] and aed.get("BSSID"):
                    bssid              = _nb(aed["BSSID"])
                    sess["bssid"]      = bssid
                    sess["oui_vendor"] = _WifiHistoryDialog._lookup_oui(bssid)

        # Attach EID 11006 auth-failure counts per session window.
        # High fix: constrain by computer to prevent cross-host leakage.
        # Medium fix: also constrain by ProfileName/SSID when both sides have it
        # so failures from a neighbouring network on the same adapter are excluded.
        for sess in sessions:
            iface    = sess["interface_guid"]
            computer = sess["computer"]
            conn_ts  = sess["connect_ts"]
            disc_ts  = sess["disconnect_ts"] or "9999-12-31 23:59:59"
            count    = 0
            for af in auth_fail_ev:
                # Host-scope guard
                if computer and af["computer"] and af["computer"] != computer:
                    continue
                af_iface = _ni(af["ed"].get("InterfaceGuid", "") or af["ed"].get("InterfaceGUID", ""))
                if af_iface != iface or not (conn_ts <= af["ts"] <= disc_ts):
                    continue
                af_ssid = af["ed"].get("ProfileName") or af["ed"].get("SSID") or ""
                if af_ssid and sess["ssid"] and af_ssid.lower() != sess["ssid"].lower():
                    continue
                count += 1
            sess["auth_failures"] = count

        # Compute anomaly flags
        for sess in sessions:
            flags: list[str] = []
            if sess["connect_eid"] == 8004:
                flags.append("FAILED_ATTEMPT")  # Medium fix: surface 8004 as anomaly
            if sess["security_grade"] == "OPEN":
                flags.append("OPEN")
            elif sess["security_grade"] == "WEP":
                flags.append("WEP")
            if sess["duration_secs"] >= 0 and sess["duration_secs"] < 60 and sess["disconnect_ts"]:
                flags.append("SHORT_SESSION")
            if sess["auth_failures"] > 0:
                flags.append("AUTH_FAILURES")
            if sess["connect_ts"]:
                try:
                    if int(sess["connect_ts"][11:13]) in {1, 2, 3, 4, 5}:
                        flags.append("UNUSUAL_HOURS")
                except Exception:
                    pass
            sess["anomaly_flags"] = flags

        # Deduplicate — Windows occasionally logs EID 8001 twice for the same
        # connection (adapter + profile manager), producing two identical pending
        # entries that both get paired with a disconnect → duplicate rows.
        # Key: (interface_guid, ssid, bssid, connect_ts, disconnect_ts).
        # bssid is included so two legitimate sessions to the same SSID on
        # different APs at the same timestamp are not collapsed.  Synthetic
        # __no_guid_N__ keys are intentionally unique and will never collapse.
        seen:    set[tuple] = set()
        unique:  list[dict] = []
        for s in sessions:
            key = (s["interface_guid"], s["ssid"], s["bssid"],
                   s["connect_ts"], s["disconnect_ts"])
            if key not in seen:
                seen.add(key)
                unique.append(s)
        sessions = unique

        # Sort: most recent connect first
        sessions.sort(key=lambda s: s["connect_ts"], reverse=True)
        return sessions

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("WiFi History Browser")
        self.setMinimumSize(1200, 540)
        self.resize(1400, 640)
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

        # ── Summary label (filled by _apply_display_filters on first render) ──
        self._lbl_summary = QLabel()
        self._lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_summary.setStyleSheet("padding:4px 0; font-size:9pt; background:transparent;")
        root.addWidget(self._lbl_summary)

        # ── Search bar + display toggles ──────────────────────────────────
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Filter by SSID, BSSID, adapter, or vendor…")
        self._search_edit.textChanged.connect(self._apply_display_filters)
        search_row.addWidget(self._search_edit, stretch=1)

        self._chk_hide_failed = QCheckBox("Hide failed connections")
        self._chk_hide_failed.setToolTip("Remove EID 8004 (connection failed) rows")
        self._chk_hide_failed.toggled.connect(self._apply_display_filters)
        search_row.addWidget(self._chk_hide_failed)

        # Only show "Hide open networks" when open nets are present
        has_open = any(s["security_grade"] == "OPEN" for s in self._all_sessions)
        self._chk_hide_open = QCheckBox("Hide open networks")
        self._chk_hide_open.setToolTip("Remove unencrypted (OPEN) networks from the table")
        self._chk_hide_open.toggled.connect(self._apply_display_filters)
        self._chk_hide_open.setVisible(has_open)
        search_row.addWidget(self._chk_hide_open)

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
        # SSID, BSSID, Vendor, Adapter, Connected, Disconnected, Duration,
        # Security, Band/Channel, PHY, Disconnect Reason, Flags
        for i, w in enumerate([140, 145, 90, 160, 140, 140, 75, 75, 90, 90, 200, 120]):
            self._tbl.setColumnWidth(i, w)

        self._tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tbl.customContextMenuRequested.connect(self._on_context_menu)
        root.addWidget(self._tbl)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()

        btn_export = QPushButton("Export CSV")
        btn_export.setToolTip("Export currently-filtered sessions to a CSV file")
        btn_export.clicked.connect(self._on_export_csv)
        btn_row.addWidget(btn_export)

        btn_row.addStretch()

        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.close)
        btn_row.addWidget(btn_close)

        root.addLayout(btn_row)

    # ── Table population ──────────────────────────────────────────────────

    def _populate_table(self, sessions: list[dict]) -> None:
        self._tbl.setSortingEnabled(False)
        self._tbl.setRowCount(len(sessions))

        col_failed   = QColor("#fde8e0")   # pale red   — EID 8004 failed
        col_authfail = QColor("#fff8dc")   # pale yellow — auth failures
        col_open     = QColor("#fff3cd")   # amber      — open network
        col_active   = QColor("#edf7ed")   # pale green — still connected

        for row, s in enumerate(sessions):
            if s["connect_eid"] == 8004:
                row_bg = col_failed
            elif s["security_grade"] == "OPEN":
                row_bg = col_open
            elif s["auth_failures"] > 0:
                row_bg = col_authfail
            elif not s["disconnect_ts"]:
                row_bg = col_active
            else:
                row_bg = None

            band_ch = (
                f"{s['frequency_band']} / Ch.{s['channel']}"
                if s["channel"] else s["frequency_band"]
            )

            cells = [
                s["ssid"],
                s["bssid"],
                s["oui_vendor"],
                s["adapter"],
                s["connect_ts"],
                s["disconnect_ts"] if s["disconnect_ts"] else "Active",
                s["duration"],
                s["security_grade"],
                band_ch,
                s["phy_label"],
                s["disconnect_reason"],
                ", ".join(s["anomaly_flags"]),
            ]

            for col, text in enumerate(cells):
                item = _DurationItem(text) if col == 6 else QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
                item.setData(Qt.ItemDataRole.UserRole, row)
                if row_bg is not None:
                    item.setBackground(row_bg)
                self._tbl.setItem(row, col, item)

        self._tbl.setSortingEnabled(True)
        self._shown_sessions = sessions

    # ── Filtering / summary ───────────────────────────────────────────────

    def _apply_display_filters(self, *_) -> None:
        t           = self._search_edit.text().strip().lower()
        hide_failed = self._chk_hide_failed.isChecked()
        hide_open   = self._chk_hide_open.isChecked()
        sessions    = self._all_sessions

        if hide_failed:
            sessions = [s for s in sessions if s["connect_eid"] == 8001]
        if hide_open:
            sessions = [s for s in sessions if s["security_grade"] != "OPEN"]
        if t:
            sessions = [
                s for s in sessions
                if t in s["ssid"].lower()
                or t in s["bssid"].lower()
                or t in s["adapter"].lower()
                or t in s["oui_vendor"].lower()
            ]
        self._populate_table(sessions)
        self._update_summary(sessions)

    def _update_summary(self, sessions: list[dict]) -> None:
        total  = len(sessions)
        ssids  = len({s["ssid"] for s in sessions})
        active = sum(1 for s in sessions if not s["disconnect_ts"])
        open_n = sum(1 for s in sessions if s["security_grade"] == "OPEN")
        parts  = [
            f"<b>{total}</b> session(s)",
            f"<b>{ssids}</b> unique network(s)",
        ]
        if active:
            parts.append(f"<b>{active}</b> active (no disconnect recorded)")
        if open_n:
            parts.append(
                f"<span style='color:#a01800;'>⚠ {open_n} open network(s) (no encryption)</span>"
            )
        # Provenance: surface incomplete-dataset state directly in the summary bar
        # so the user never has to remember the earlier pop-up warning.
        if self._truncated:
            parts.append(
                "<span style='color:#8a4800;'>⚠ Results capped at 200,000 events — "
                "later sessions may be missing</span>"
            )
        self._lbl_summary.setText(" &nbsp;│&nbsp; ".join(parts))

    # ── Context menu ──────────────────────────────────────────────────────

    def _on_context_menu(self, pos) -> None:
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui     import QGuiApplication

        index = self._tbl.indexAt(pos)
        if not index.isValid():
            return
        self._tbl.selectRow(index.row())
        # After column sorting QTableWidget physically reorders items, so the
        # visual row index no longer matches insertion order.  UserRole stores
        # the original index into _shown_sessions at populate time — use that
        # instead of index.row() so we always read the correct session.
        cell = self._tbl.item(index.row(), 0)
        if cell is None:
            return
        orig_row = cell.data(Qt.ItemDataRole.UserRole)
        if orig_row is None or not (0 <= orig_row < len(self._shown_sessions)):
            return
        s = self._shown_sessions[orig_row]

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#2b2b2b; color:#e8e8e8; border:1px solid #555; }"
            "QMenu::item:selected { background:#4a6fa5; color:white; }"
            "QMenu::separator { height:1px; background:#555; margin:4px 8px; }"
        )

        act_ssid = menu.addAction(f"\U0001f4cb  Copy SSID  ({s['ssid']})")
        act_ssid.triggered.connect(lambda: QGuiApplication.clipboard().setText(s["ssid"]))

        if s["bssid"]:
            act_bssid = menu.addAction(f"\U0001f4cb  Copy BSSID  ({s['bssid']})")
            act_bssid.triggered.connect(lambda: QGuiApplication.clipboard().setText(s["bssid"]))

        if s["adapter"]:
            act_adapt = menu.addAction(f"\U0001f4cb  Copy Adapter  ({s['adapter']})")
            act_adapt.triggered.connect(lambda: QGuiApplication.clipboard().setText(s["adapter"]))

        if s["auth_failures"] > 0:
            menu.addSeparator()
            act_af = menu.addAction(f"\u26a0  {s['auth_failures']} auth failure(s) in this session")
            act_af.setEnabled(False)

        menu.exec(self._tbl.viewport().mapToGlobal(pos))

    # ── Export ────────────────────────────────────────────────────────────

    def _on_export_csv(self) -> None:
        import csv
        path, _ = QFileDialog.getSaveFileName(
            self, "Export WiFi History", "wifi_history.csv",
            "CSV files (*.csv);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                # Provenance: note truncation in the file itself so the exported
                # CSV is self-describing even when the dialog is long closed.
                if self._truncated:
                    writer.writerow([
                        "NOTE: Dataset was capped at 200,000 events — "
                        "sessions from later in the time range may be missing."
                    ])
                writer.writerow(self._HEADERS)
                # Low fix: rebuild row order from the table's current visual state
                # so an interactive column sort is reflected in the exported file.
                ordered: list[dict] = []
                for vis_row in range(self._tbl.rowCount()):
                    cell = self._tbl.item(vis_row, 0)
                    if cell is None:
                        continue
                    orig = cell.data(Qt.ItemDataRole.UserRole)
                    if orig is not None and 0 <= orig < len(self._shown_sessions):
                        ordered.append(self._shown_sessions[orig])
                if not ordered:
                    ordered = self._shown_sessions
                for s in ordered:
                    band_ch = (
                        f"{s['frequency_band']} / Ch.{s['channel']}"
                        if s["channel"] else s["frequency_band"]
                    )
                    writer.writerow([
                        s["ssid"], s["bssid"], s["oui_vendor"], s["adapter"],
                        s["connect_ts"], s["disconnect_ts"], s["duration"],
                        s["security_grade"], band_ch, s["phy_label"],
                        s["disconnect_reason"], ", ".join(s["anomaly_flags"]),
                    ])
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", f"Could not write CSV:\n{exc}")
            return
        QMessageBox.information(
            self, "Export Complete",
            f"Saved {len(ordered)} session(s) to:\n{path}"
        )


# ── WiFi JM background fetch worker ──────────────────────────────────────────

class _WifiJMFetchWorker(QThread):
    """Query Parquet shards for WLAN-AutoConfig events on a background thread.

    Prevents the UI from freezing on large shard sets — DuckDB parquet_scan()
    over many files can take several seconds on spinning-disk hardware.

    Emits ``finished(list)`` with the collected event dicts on success,
    or ``fetch_error(str)`` with a human-readable message on failure.
    (Signal is named ``fetch_error`` rather than ``error`` to avoid shadowing
    the built-in QThread.error() that exists on some Qt versions.)
    """

    finished    = Signal(list, bool)  # (list[dict], was_truncated) — may be empty/False
    fetch_error = Signal(str, str)    # (error_kind, detail_message)

    _WLAN_CHANNEL = "Microsoft-Windows-WLAN-AutoConfig/Operational"
    _RELEVANT_EIDS = (8001, 8002, 8003, 8004, 11001, 11006)

    def __init__(self, parquet_dir: str, parent=None) -> None:
        super().__init__(parent)
        self._parquet_dir = parquet_dir

    def run(self) -> None:
        import json as _json
        import os  as _os
        import duckdb as _duckdb

        manifest_path = _os.path.join(self._parquet_dir, "parquet_manifest.json")
        # Structured manifest read — distinguish missing file from corrupt JSON
        # from generic I/O errors so the UI can show a targeted message.
        try:
            with open(manifest_path, "r", encoding="utf-8") as _f:
                _raw_manifest = _f.read()
        except FileNotFoundError:
            logger.error("WiFi JM [manifest_missing]: %s", manifest_path)
            self.fetch_error.emit(
                "manifest_missing",
                f"Parquet manifest not found:\n{manifest_path}\n\n"
                "The dataset may have been moved or the JM session was not fully built.",
            )
            return
        except OSError as exc:
            logger.error("WiFi JM [manifest_read_error]: %s — %s", manifest_path, exc)
            self.fetch_error.emit(
                "manifest_read_error",
                f"Cannot read Parquet manifest:\n{exc}",
            )
            return
        try:
            shards = _json.loads(_raw_manifest)
        except _json.JSONDecodeError as exc:
            logger.error("WiFi JM [manifest_parse_error]: %s — %s", manifest_path, exc)
            self.fetch_error.emit(
                "manifest_parse_error",
                f"Parquet manifest is not valid JSON:\n{exc}",
            )
            return

        if not shards:
            self.finished.emit([], False)
            return

        eids_csv   = ", ".join(str(e) for e in self._RELEVANT_EIDS)
        shard_list = (
            "[" + ", ".join(f"'{p.replace(chr(39), chr(39)*2)}'" for p in shards) + "]"
        )
        try:
            con = _duckdb.connect()
            try:
                # Low fix: fetch one extra row so we can detect truncation without
                # false-positive warnings when the result count exactly equals the cap.
                rows = con.execute(
                    f"SELECT event_id, timestamp_utc, event_data_json "
                    f"FROM parquet_scan({shard_list}) "
                    f"WHERE channel = ? "
                    f"  AND event_id IN ({eids_csv}) "
                    f"ORDER BY timestamp_utc "
                    f"LIMIT 200001",
                    [self._WLAN_CHANNEL],
                ).fetchall()
            finally:
                con.close()   # Low/Medium fix: guaranteed even on query exception
        except Exception as exc:
            logger.error("WiFi JM [duckdb_query_error]: %s", exc)
            self.fetch_error.emit("duckdb_query_error", str(exc))
            return

        truncated = len(rows) > 200_000
        if truncated:
            rows = rows[:200_000]

        events: list[dict] = []
        for ev_id, ts_utc, ed_json in rows:
            try:
                ed = _json.loads(ed_json) if ed_json else {}
            except Exception:
                ed = {}
            events.append({
                "event_id":   ev_id,
                "timestamp":  str(ts_utc or ""),
                "event_data": ed,
                "channel":    self._WLAN_CHANNEL,
            })
        self.finished.emit(events, truncated)


# ── Numeric-sort helper ───────────────────────────────────────────────────────

class _NumericSortItem(QTableWidgetItem):
    """QTableWidgetItem whose sort order is determined by its numeric UserRole.

    Set ``item.setData(Qt.ItemDataRole.UserRole, float_value)`` where the value
    is the natural sort key.  ``None`` / non-numeric UserRole falls back to the
    default string comparison so mixed columns are safe.

    Callers should pass ``float("inf")`` for unknown/sentinel values so that
    "?" or similar display strings sort *last* in ascending order rather than
    first (as a raw ``-1.0`` would do).
    """

    def __lt__(self, other: "QTableWidgetItem") -> bool:
        sv = self.data(Qt.ItemDataRole.UserRole)
        ov = other.data(Qt.ItemDataRole.UserRole)
        try:
            return float(sv) < float(ov)   # type: ignore[arg-type]
        except (TypeError, ValueError):
            return super().__lt__(other)


# ── Remote Assistance Session Browser dialog ──────────────────────────────────

class _RemoteAssistanceDialog(QDialog):
    """
    Non-modal dialog listing Remote Assistance / Remote Help / RDP / Quick Assist
    sessions parsed from multiple Windows event channels.

    Channels covered:
      • Microsoft-Windows-RemoteAssistance/Operational  (Classic RA — EIDs 1/2/3)
      • Microsoft-Windows-RemoteHelp/Operational        (Remote Help)
      • Microsoft-Windows-TerminalServices-*            (RDP — EIDs 21/23/24/25/1149/261)
      • Security                                        (4624/4634 LogonType=10, 4778/4779)
      • Security EID 4688                               (Quick Assist process launch)

    *on_filter_fn* is called with ``(related_keys: frozenset, session_info: dict)``
    when the user chooses "Filter to Session" from the context menu.
    """

    _HEADERS = [
        "Type", "Computer", "Start", "End", "Duration",
        "User", "Remote Host", "Control", "Status", "Events", "Flags",
    ]

    _TYPE_COLORS: dict[str, str] = {
        "Classic RA":  "#1e4d8c",
        "Remote Help": "#2e6820",
        "RDP Session": "#7a5c1e",
        "Quick Assist":"#6b1e6b",
    }

    _BASE_QSS = """
        QDialog { background: #f5f0e8; }
        QLabel  { color: #1e1a14; font-size: 9pt; }
        QLineEdit {
            background: #faf7f2; color: #1e1a14;
            border: 1px solid #c4bba8; border-radius: 3px;
            padding: 2px 6px; font-size: 9pt;
        }
        QLineEdit:focus { border-color: #7a5c1e; }
        QComboBox {
            background: #faf7f2; color: #1e1a14;
            border: 1px solid #c4bba8; border-radius: 3px;
            padding: 2px 6px; font-size: 9pt; min-width: 110px;
        }
        QComboBox QAbstractItemView {
            background: #faf7f2; color: #1e1a14;
            selection-background-color: #7a5c1e;
        }
        QPushButton {
            background: #e4ddd3; color: #1e1a14;
            border: 1px solid #c4bba8; border-radius: 3px;
            padding: 3px 12px; font-size: 9pt;
        }
        QPushButton:hover    { background: #d6cdbf; }
        QPushButton:pressed  { background: #c4bba8; }
        QPushButton#okBtn {
            background: #7a5c1e; color: #ffffff;
            border: 1px solid #5a3e1e;
        }
        QPushButton#okBtn:hover   { background: #8a6c2e; }
        QPushButton#okBtn:pressed { background: #5a3e1e; }
        QTableWidget {
            background: #faf7f2; color: #1e1a14;
            border: 1px solid #c4bba8; gridline-color: #e0d8c4;
            font-size: 9pt; outline: none;
        }
        QTableWidget::item { padding: 1px 4px; }
        QTableWidget::item:selected {
            background: #7a5c1e; color: #ffffff;
        }
        QHeaderView::section {
            background: #e4ddd3; color: #1e1a14;
            border: none; border-right: 1px solid #c4bba8;
            border-bottom: 1px solid #c4bba8;
            padding: 3px 6px; font-size: 9pt; font-weight: bold;
        }
        QScrollBar:vertical { background: #f5f0e8; width: 8px; margin: 0; }
        QScrollBar::handle:vertical {
            background: #5a3e1e; border-radius: 4px; min-height: 20px;
        }
        QScrollBar::handle:vertical:hover { background: #7a5c1e; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QScrollBar:horizontal { background: #f5f0e8; height: 8px; margin: 0; }
        QScrollBar::handle:horizontal {
            background: #5a3e1e; border-radius: 4px; min-width: 20px;
        }
        QScrollBar::handle:horizontal:hover { background: #7a5c1e; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
    """

    def __init__(
        self,
        events: list[dict],
        on_filter_fn=None,
        truncated: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._on_filter_fn = on_filter_fn
        self._truncated    = truncated
        self._all_sessions:   list[dict] = self._build_sessions(events)
        self._shown_sessions: list[dict] = list(self._all_sessions)
        # L6: pre-compute type totals once so _update_summary() never O(n)-scans
        # all_sessions on every filter interaction.
        self._by_type_totals: dict[str, int] = {}
        for _s in self._all_sessions:
            self._by_type_totals[_s["type"]] = (
                self._by_type_totals.get(_s["type"], 0) + 1
            )
        self._build_ui()
        self._apply_display_filters()

    # ── Session building ───────────────────────────────────────────────────

    @staticmethod
    def _build_sessions(events: list[dict]) -> list[dict]:
        """Parse raw events into Remote Assistance session dicts."""
        from datetime import datetime as _dt

        _RA_CHAN    = "remoteassistance"
        _RH_CHAN    = "remotehelp"
        _TS_CHAN    = "terminalservices"
        _SEC_CHAN   = "security"
        _CORR_SECS  = 120.0
        # Explicit-key matching windows.
        _KEY_CORR_SECS      = 14400.0   # 4h: default explicit-key proximity
        # For still-open buckets we keep a much wider window than closed buckets
        # so long-lived sessions with sparse telemetry do not split prematurely.
        _OPEN_KEY_CORR_SECS = 604800.0  # 7 days
        # Only these classic RA event IDs carry the start/control/end semantics used below.
        _RA_EIDS = frozenset({1, 2, 3})
        # TerminalServices IDs that are session-semantic (exclude diagnostics noise).
        _TS_EIDS = frozenset({
            21,   # LocalSessionManager: session logon
            22,   # shell start
            23,   # session logoff
            24,   # session disconnect
            25,   # session reconnect
            39,   # session disconnect (alt)
            40,   # session logoff (alt)
            41,   # session connect (alt)
            261,  # RemoteConnectionManager: listener got connection
            1149, # RemoteConnectionManager: auth succeeded
        })

        def _parse_ts(ts: str):
            ts = str(ts or "").strip().rstrip("Z")
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S",
            ):
                try:
                    return _dt.strptime(ts[:26], fmt)
                except Exception:
                    pass
            return None

        def _fmt_ts(d) -> str:
            return d.strftime("%Y-%m-%d %H:%M:%S") if d else ""

        def _extract_ed(event: dict) -> dict:
            ed_raw = event.get("event_data") or {}
            if not isinstance(ed_raw, dict):
                return {}
            result: dict = {}
            # M2 fix: Shape A gate must fire only when there is at least one
            # *real* field key — not "Data", not "#text", and not an XML-attribute
            # / metadata prefix ("@..." or "#...").
            # Old guard: `any(k not in ("Data","#text") for k in ed_raw)` was
            # triggered by "@Version" (a metadata key), causing the function to
            # take the Shape A branch, skip all keys (stripped by the "@"/"#"
            # filter), return {}, and lose all Data entries.
            # New guard: only enters Shape A when a genuine payload key exists.
            if any(
                k not in ("Data", "#text")
                and not k.startswith("#")
                and not k.startswith("@")
                for k in ed_raw
            ):
                # L1: skip "Data" key itself; its contents are handled by
                # Shape B/C below.  Including it here would inject the raw
                # list/dict repr as a string field value.
                for k, v in ed_raw.items():
                    if not k.startswith("#") and not k.startswith("@") and k != "Data":
                        result[k] = str(v or "")
                return result
            data = ed_raw.get("Data")
            if data is None:
                for line in str(ed_raw.get("#text", "")).splitlines():
                    if "=" in line:
                        k, _, v = line.partition("=")
                        result[k.strip()] = v.strip()
                return result
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        name = item.get("@Name", "")
                        val  = item.get("#text", "")
                        if name:
                            result[str(name)] = str(val or "")
                return result
            if isinstance(data, dict):
                name = data.get("@Name", "")
                val  = data.get("#text", "")
                if name:
                    result[str(name)] = str(val or "")
            return result

        def _classify(ev: dict, ed: dict) -> tuple | None:
            """Return (type_label, explicit_grouping_key) or None to skip."""
            try:
                eid = int(ev.get("event_id") or 0)
            except (TypeError, ValueError):
                eid = 0
            chan = str(ev.get("channel") or "").lower()
            if _RA_CHAN in chan:
                if eid not in _RA_EIDS:
                    return None
                # Use (LocalFQDNName | UserName) as explicit key when available
                # so distinct concurrent Classic RA sessions on the same host get
                # separate buckets rather than collapsing into one time cluster.
                fqdn = ed.get("LocalFQDNName", "").strip().lower()
                user = ed.get("UserName",      "").strip().lower()
                key  = f"{fqdn}|{user}" if (fqdn or user) else ""
                return "Classic RA", key
            if _RH_CHAN in chan:
                # SessionId / ConnectionId disambiguates concurrent Remote Help
                # sessions.  Require an explicit session key to avoid turning
                # generic channel noise into synthetic sessions.
                sid = (
                    ed.get("SessionId")
                    or ed.get("SessionID")
                    or ed.get("ConnectionId")
                    or ed.get("ConnectionID")
                    or ""
                ).strip()
                if not sid:
                    return None
                return "Remote Help", sid
            if _TS_CHAN in chan:
                # Gate on EIDs that are meaningful for session reconstruction;
                # other TerminalServices operational events (diagnostics, licensing,
                # etc.) create false sessions without this guard.
                if eid not in _TS_EIDS:
                    return None   # skip unrelated TS operational events
                sess_id = (ed.get("SessionID") or ed.get("Session") or "").strip()
                return "RDP Session", sess_id
            if _SEC_CHAN in chan:
                if eid in (4624, 4634):
                    if str(ed.get("LogonType", "")) != "10":
                        return None   # not remote-interactive
                    lid = (ed.get("TargetLogonId") or "").strip()
                    return "RDP Session", lid
                if eid in (4778, 4779):
                    lid = (ed.get("TargetLogonId") or "").strip()
                    return "RDP Session", lid
                if eid == 4688:
                    # Broaden: check NewProcessName AND CommandLine AND Application
                    # so renamed paths and alternate field names are also caught.
                    _proc_fields = (
                        str(ed.get("NewProcessName", "")).lower(),
                        str(ed.get("CommandLine",    "")).lower(),
                        str(ed.get("Application",    "")).lower(),
                    )
                    if any("quickassist" in _f for _f in _proc_fields):
                        # Use a composite key to reduce PID-reuse collisions.
                        _qa_pid = str(ed.get("NewProcessId") or "").strip()
                        _qa_img = str(
                            ed.get("NewProcessName") or ed.get("Application") or ""
                        ).strip().lower()
                        _qa_ts  = str(ev.get("timestamp") or "").strip()[:19]
                        _qa_key = "|".join([x for x in (_qa_pid, _qa_img, _qa_ts) if x])
                        return "Quick Assist", _qa_key
                return None
            return None

        events_sorted: list[dict] = sorted(
            events,
            key=lambda e: (
                str(e.get("computer") or e.get("source_file") or "").lower(),
                str(e.get("timestamp") or ""),
            ),
        )

        # Explicit-key buckets are stored as lists so the same key value reused
        # later can create a new bucket instead of collapsing into an old one.
        # Still-open buckets are allowed a larger match window to avoid splitting
        # long-running sessions that emit sparse events.
        open_by_key:  dict = {}   # (computer, type, explicit_key) → list[(last_dt, bucket)]
        open_by_time: dict = {}   # (computer, type) → list[(last_dt, bucket)]
        all_buckets:  list = []
        syn_ctr = [0]
        # L3: define once outside the event loop (frozenset is constant).
        _USER_BLOCK = frozenset({
            "-", "system", "local service", "network service",
            "anonymous logon", "window manager", "dcom launch",
            "font driver host", "umfd-0", "umfd-1",
        })

        def _norm_user_for_match(raw: str) -> str:
            user = str(raw or "").strip()
            if not user:
                return ""
            local = user.rpartition("\\")[2].lower() if "\\" in user else user.lower()
            if local in _USER_BLOCK or local.endswith("$"):
                return ""
            return local

        def _norm_remote_for_match(raw: str) -> str:
            r = str(raw or "").strip().lower()
            if r in ("", "-", "::1", "127.0.0.1"):
                return ""
            return r

        def _next_syn() -> str:
            syn_ctr[0] += 1
            return f"__syn_{syn_ctr[0]:04d}__"

        def _new_bucket(
            type_label: str, computer_key: str, key: str,
            computer_display: str = "",
        ) -> dict:
            # Classic RA starts at "No" — EID 2 is the only explicit grant.
            # All other types start at "Unknown" — no explicit grant event exists
            # in Windows logs for RDP/Quick Assist/Remote Help.
            ctrl_default = "No" if type_label == "Classic RA" else "Unknown"
            b: dict = {
                "_type": type_label, "_computer": computer_key,
                # Preserve original casing for UI/export; grouping/lookup uses
                # the lowercase _computer key, not _computer_display.
                "_computer_display": computer_display or computer_key,
                "_key": key,
                "_events": [], "_start_dt": None, "_end_dt": None,
                "_has_start": False, "_has_end": False,
                "_control": ctrl_default, "_user": "", "_remote_host": "",
                "_user_norm": "", "_remote_norm": "",
            }
            all_buckets.append(b)
            return b

        for ev in events_sorted:
            ed  = _extract_ed(ev)
            cls = _classify(ev, ed)
            if cls is None:
                continue
            type_label, explicit_key = cls
            try:
                eid = int(ev.get("event_id") or 0)
            except (TypeError, ValueError):
                eid = 0
            # L2 + H fix: separate display value (basename) from grouping key.
            # Display: basename for readability ("Security.evtx").
            # Grouping key: FULL source_file path (lowercased) so two files
            # that share the same filename but live in different directories
            # (e.g. Security.evtx from two different host captures) are never
            # merged into the same bucket.
            _comp_val = str(ev.get("computer") or "").strip()
            _src_val  = str(ev.get("source_file") or "").strip()
            if _comp_val:
                computer_raw = _comp_val
                computer     = _comp_val.lower()
            elif _src_val:
                import os as _os_inner
                computer_raw = _os_inner.path.basename(_src_val) or "(unknown)"
                computer     = _src_val.lower()   # full path → unique per capture
            else:
                computer_raw = "(unknown)"
                computer     = "(unknown)"
            dt           = _parse_ts(str(ev.get("timestamp") or ""))
            _ev_user_norm = _norm_user_for_match(
                ed.get("User")
                or ed.get("TargetUserName")
                or ed.get("SubjectUserName")
                or str(ev.get("user_id") or "")
            )
            _ev_remote_norm = _norm_remote_for_match(
                ed.get("IpAddress") or ed.get("Source") or ""
            )

            # ── Bucket selection ──────────────────────────────────────────
            if explicit_key and explicit_key not in ("0x0", "0", "-1", ""):
                # H1 fix: maintain a list per explicit key so the same key
                # value recycled weeks later (RDP SessionID, FQDN|user reuse)
                # creates a new bucket instead of collapsing into the old one.
                bk       = (computer, type_label, explicit_key)
                key_list = open_by_key.setdefault(bk, [])
                best_bkt:   "dict | None" = None
                best_delta: "float | None" = None
                best_idx = -1
                if dt is not None:
                    for _i, (_ldt, _bkt) in enumerate(key_list):
                        if _ldt is None:
                            continue
                        _delta = (dt - _ldt).total_seconds()
                        _max_corr = (
                            _OPEN_KEY_CORR_SECS
                            if not _bkt.get("_has_end")
                            else _KEY_CORR_SECS
                        )
                        if 0 <= _delta <= _max_corr:
                            # Long-gap explicit-key matches are high-risk for
                            # recycled IDs. Require corroborating identity.
                            if _delta > _KEY_CORR_SECS:
                                _user_match = bool(
                                    _bkt.get("_user_norm")
                                    and _ev_user_norm
                                    and _bkt["_user_norm"] == _ev_user_norm
                                )
                                _remote_match = bool(
                                    _bkt.get("_remote_norm")
                                    and _ev_remote_norm
                                    and _bkt["_remote_norm"] == _ev_remote_norm
                                )
                                if not (_user_match or _remote_match):
                                    continue
                            if best_delta is None or _delta < best_delta:
                                best_bkt, best_delta, best_idx = _bkt, _delta, _i
                if best_bkt is not None:
                    bucket = best_bkt
                    key_list[best_idx] = (dt, best_bkt)   # advance last_dt
                elif dt is None and key_list:
                    # No timestamp — attach to most recent bucket with this key.
                    bucket = key_list[-1][1]
                else:
                    bucket = _new_bucket(type_label, computer, explicit_key,
                                         computer_raw)
                    key_list.append((dt, bucket))
            else:
                # Time-based clustering: maintain a LIST of open buckets per
                # (computer, type) so concurrent same-type sessions on the same
                # host are not erroneously merged into one bucket.
                # Pick the open bucket whose last_dt is closest within _CORR_SECS.
                #
                # M3 fix: if no time-cluster match exists, also scan explicit-key
                # buckets for the same (computer, type) — this handles Classic RA
                # events that carry no LocalFQDNName/UserName (empty key) but
                # temporally belong to an already-open keyed session on that host.
                tk        = (computer, type_label)
                open_list = open_by_time.setdefault(tk, [])
                bucket:   "dict | None" = None
                if dt is not None:
                    best_delta2: "float | None" = None
                    best_idx2 = -1
                    for _i, (_ldt, _bkt) in enumerate(open_list):
                        if _ldt is None:
                            continue
                        _delta = (dt - _ldt).total_seconds()
                        if 0 <= _delta <= _CORR_SECS:
                            if best_delta2 is None or _delta < best_delta2:
                                best_delta2, best_idx2 = _delta, _i
                    if best_idx2 >= 0:
                        bucket = open_list[best_idx2][1]
                        open_list[best_idx2] = (dt, bucket)   # advance last_dt
                    else:
                        # Spill: check explicit-key buckets (M3)
                        best_spill: "float | None" = None
                        for _bk_tuple, _kl in open_by_key.items():
                            if _bk_tuple[0] != computer or _bk_tuple[1] != type_label:
                                continue
                            for _ldt, _bkt in _kl:
                                if _ldt is None:
                                    continue
                                _delta = (dt - _ldt).total_seconds()
                                if 0 <= _delta <= _CORR_SECS:
                                    if best_spill is None or _delta < best_spill:
                                        bucket, best_spill = _bkt, _delta
                if bucket is None:
                    syn_key = _next_syn()
                    bucket  = _new_bucket(type_label, computer, syn_key,
                                          computer_raw)
                    open_list.append((dt, bucket))

            bucket["_events"].append(ev)

            # Timestamps
            if dt is not None:
                if bucket["_start_dt"] is None or dt < bucket["_start_dt"]:
                    bucket["_start_dt"] = dt
                if bucket["_end_dt"] is None or dt > bucket["_end_dt"]:
                    bucket["_end_dt"] = dt

            # User / remote host (first non-trivial value wins)
            # L3: _USER_BLOCK defined once above the loop.
            user = (
                ed.get("User") or ed.get("TargetUserName") or
                ed.get("SubjectUserName") or str(ev.get("user_id") or "")
            ).strip()
            # Machine-account ("WORKSTATION01$") and domain-prefix strip:
            # "NT AUTHORITY\SYSTEM".lower() == "nt authority\\system" ≠ "system",
            # so strip any "DOMAIN\" prefix before blocklist matching (M3 fix).
            _user_local = (
                user.rpartition("\\")[2].lower() if "\\" in user else user.lower()
            )
            if (user and _user_local not in _USER_BLOCK
                    and not user.endswith("$") and not bucket["_user"]):
                bucket["_user"] = user
                bucket["_user_norm"] = _user_local
            remote = (ed.get("IpAddress") or ed.get("Source") or "").strip()
            if remote and remote not in ("-", "::1", "127.0.0.1") and not bucket["_remote_host"]:
                bucket["_remote_host"] = remote
                bucket["_remote_norm"] = _ev_remote_norm

            # EID semantics
            if type_label == "Classic RA":
                if eid == 1:
                    bucket["_has_start"] = True
                elif eid == 2:
                    bucket["_control"] = "Yes"   # explicit control grant
                elif eid == 3:
                    bucket["_has_end"] = True
            elif type_label == "RDP Session":
                if eid in (21, 1149, 4624, 4778):
                    bucket["_has_start"] = True
                if eid in (23, 24, 4634, 4779):
                    bucket["_has_end"] = True
                # No control assignment — Windows logs carry no explicit RDP
                # "control granted" event; value stays "Unknown" (set in _new_bucket).

        # ── M2: merge TS-channel and Security-channel RDP buckets ────────────
        # TerminalServices events use a small integer SessionID as their explicit
        # key; Security 4624/4634/4778/4779 events use a hex TargetLogonId.  The
        # two identifiers are never equal, so the same physical RDP connection
        # produces two separate buckets.  Post-processing: if one bucket contains
        # exclusively TS-channel events and another on the same computer contains
        # exclusively Security-channel events AND their time windows overlap within
        # a 5-minute tolerance, absorb the Security bucket into the TS bucket so
        # the session row has both the remote-host (from Security) and the
        # start/end flags (from TS events).
        def _merge_rdp_buckets(buckets: list) -> None:
            from datetime import timedelta as _td
            _MERGE_TOL  = _td(seconds=300)
            _TS_STR     = "terminalservices"
            _SEC_STR    = "security"

            def _kind(bkt: dict) -> str:
                has_ts  = any(_TS_STR  in str(e.get("channel", "")).lower()
                              for e in bkt["_events"])
                has_sec = any(_SEC_STR in str(e.get("channel", "")).lower()
                              for e in bkt["_events"])
                if has_ts and not has_sec:
                    return "ts"
                if has_sec and not has_ts:
                    return "sec"
                return "mixed"   # already contains both — no merge needed

            def _overlaps(a: dict, b: dict) -> bool:
                as_ = a["_start_dt"];  ae = a["_end_dt"] or a["_start_dt"]
                bs_ = b["_start_dt"];  be = b["_end_dt"] or b["_start_dt"]
                if as_ is None or bs_ is None:
                    return False
                # M1 fix: expand each window outward by tolerance (not inward).
                # Correct overlap: window A ends within MERGE_TOL of B's start,
                # or vice versa.
                return (ae + _MERGE_TOL >= bs_) and (be + _MERGE_TOL >= as_)

            by_comp: dict = {}
            for bkt in buckets:
                if bkt["_type"] == "RDP Session" and not bkt.get("_absorbed"):
                    by_comp.setdefault(bkt["_computer"], []).append(bkt)

            for comp_bkts in by_comp.values():
                ts_list  = [b for b in comp_bkts if _kind(b) == "ts"]
                sec_list = [b for b in comp_bkts if _kind(b) == "sec"]
                for sec_b in sec_list:
                    if sec_b.get("_absorbed"):
                        continue
                    candidates: list[tuple[bool, float, dict]] = []
                    sec_ref = sec_b["_start_dt"] or sec_b["_end_dt"]
                    for ts_b in ts_list:
                        if ts_b.get("_absorbed"):
                            continue
                        # User compatibility: skip if both are known and differ.
                        u_ts  = ts_b["_user"].lower().strip()
                        u_sec = sec_b["_user"].lower().strip()
                        if u_ts and u_sec and u_ts != u_sec:
                            continue
                        # Remote-host guard: different origin IPs → different
                        # connections.  Only fires when both sides are populated
                        # so blank entries (common in TS events) stay neutral.
                        rh_ts  = ts_b["_remote_host"].strip()
                        rh_sec = sec_b["_remote_host"].strip()
                        if rh_ts and rh_sec and rh_ts != rh_sec:
                            continue
                        if not _overlaps(ts_b, sec_b):
                            continue
                        corroborated = bool(
                            (u_ts and u_sec and u_ts == u_sec)
                            or (rh_ts and rh_sec and rh_ts == rh_sec)
                        )
                        ts_ref = ts_b["_start_dt"] or ts_b["_end_dt"]
                        if sec_ref is not None and ts_ref is not None:
                            dist = abs((sec_ref - ts_ref).total_seconds())
                        else:
                            dist = float("inf")
                        candidates.append((corroborated, dist, ts_b))
                    if not candidates:
                        continue
                    corroborated = [c for c in candidates if c[0]]
                    if corroborated:
                        _ts_pick = min(corroborated, key=lambda t: t[1])[2]
                    else:
                        # Require at least one strong positive join key (user or
                        # remote-host match).  Overlap-only merges are too risky.
                        continue
                    ts_b = _ts_pick
                    # Absorb sec_b into ts_b
                    ts_b["_events"].extend(sec_b["_events"])
                    for _v in (sec_b["_start_dt"], sec_b["_end_dt"]):
                        if _v is None:
                            continue
                        if ts_b["_start_dt"] is None or _v < ts_b["_start_dt"]:
                            ts_b["_start_dt"] = _v
                        if ts_b["_end_dt"]   is None or _v > ts_b["_end_dt"]:
                            ts_b["_end_dt"]   = _v
                    if not ts_b["_user"]        and sec_b["_user"]:
                        ts_b["_user"]        = sec_b["_user"]
                    if not ts_b["_remote_host"] and sec_b["_remote_host"]:
                        ts_b["_remote_host"] = sec_b["_remote_host"]
                    if sec_b["_has_start"]:
                        ts_b["_has_start"] = True
                    if sec_b["_has_end"]:
                        ts_b["_has_end"]   = True
                    sec_b["_absorbed"] = True

        _merge_rdp_buckets(all_buckets)

        # ── Build final session dicts ─────────────────────────────────────
        sessions: list[dict] = []
        for bkt in all_buckets:
            if bkt.get("_absorbed"):
                continue   # M2: this bucket was merged into another
            evs = bkt["_events"]
            if not evs:
                continue
            type_label = bkt["_type"]
            start_dt   = bkt["_start_dt"]
            end_dt     = bkt["_end_dt"]
            start_ts   = _fmt_ts(start_dt)
            end_ts     = _fmt_ts(end_dt)

            # Duration
            if start_dt and end_dt:
                secs = (end_dt - start_dt).total_seconds()
                if secs < 0:
                    dur_str, dur_secs = "⚠ Out-of-order", -1.0
                else:
                    h, rem  = divmod(int(secs), 3600)
                    m, sec  = divmod(rem, 60)
                    dur_str = (f"{h}h {m:02d}m {sec:02d}s" if h else
                               f"{m}m {sec:02d}s"          if m else f"{sec}s")
                    dur_secs = secs
            else:
                dur_str, dur_secs = "?", -1.0
            if len(evs) == 1 and not (bkt["_has_start"] and bkt["_has_end"]):
                # Single-point evidence cannot prove elapsed session duration.
                dur_str, dur_secs = "?", -1.0

            # Status
            if type_label == "Classic RA":
                if bkt["_has_start"] and bkt["_has_end"]:
                    status = "Completed"
                elif bkt["_has_start"]:
                    status = "Active / Ongoing"
                elif bkt["_has_end"]:
                    status = "Partial (no start)"
                else:
                    status = "Unknown"
            elif type_label == "RDP Session":
                if bkt["_has_start"] and bkt["_has_end"]:
                    status = "Completed"
                elif bkt["_has_start"]:
                    status = "Active / Ongoing"
                elif bkt["_has_end"]:
                    status = "Disconnected (no auth logged)"
                else:
                    status = "Unknown"
            elif type_label == "Remote Help":
                # L5: Remote Help EID semantics are not publicly documented.
                # For now status is always "Detected"; future work can wire
                # specific EIDs to _has_start / _has_end once confirmed.
                status = "Detected"
            else:
                # Quick Assist and any future types
                status = "Detected"

            # Flags
            flags: list[str] = []
            if type_label == "Classic RA" and bkt["_control"] == "Yes":
                flags.append("CONTROL_GRANTED")
            if dur_secs < 0 and start_dt and end_dt:
                flags.append("OUT_OF_ORDER")
            if len(evs) == 1:
                flags.append("SINGLE_EVENT")

            # related_keys: (source_file, record_id) composite — used for filter-to-session.
            # Only include events that have a real record_id; the -1 fallback is
            # omitted because multiple events from the same source_file could all
            # map to (source_file, -1) and collide when the filter is applied.
            # M2 fix: guard int() cast — a non-integer record_id (malformed parse
            # output) would otherwise raise ValueError and abort all session building.
            def _safe_rid(v):
                try:
                    return int(v)
                except (TypeError, ValueError):
                    return None

            _pairs: set[tuple[str, int]] = set()
            _unfilterable_count = 0
            for e in evs:
                _rid_raw = e.get("record_id")
                if _rid_raw is None:
                    _unfilterable_count += 1
                    continue
                _rid = _safe_rid(_rid_raw)
                if _rid is None:
                    _unfilterable_count += 1
                    continue
                _pairs.add((str(e.get("source_file") or ""), _rid))
            related_keys: frozenset = frozenset(_pairs)
            if _unfilterable_count > 0:
                flags.append(f"UNFILTERABLE_EVENTS:{_unfilterable_count}")

            sessions.append({
                "type":          type_label,
                "session_key":   bkt["_key"],
                "computer":      bkt.get("_computer_display") or bkt["_computer"],
                "start_ts":      start_ts,
                "end_ts":        end_ts,
                "duration":      dur_str,
                "duration_secs": dur_secs,
                "user":          bkt["_user"],
                "remote_host":   bkt["_remote_host"],
                "control":       bkt["_control"],
                "status":        status,
                "event_count":   len(evs),
                "filterable_event_count": len(related_keys),
                "unfilterable_event_count": _unfilterable_count,
                "flags":         flags,
                "related_keys":  related_keys,
            })

        sessions.sort(key=lambda s: s["start_ts"] or "")
        return sessions

    # ── UI building ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("Remote Assistance Sessions")
        self.resize(1150, 650)
        self.setStyleSheet(self._BASE_QSS)
        self.setAttribute(Qt.WA_DeleteOnClose)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        # ── Filter row ─────────────────────────────────────────────────────
        frow = QHBoxLayout()
        frow.setSpacing(6)

        frow.addWidget(QLabel("Type:"))
        self._cmb_type = QComboBox()
        self._cmb_type.addItems(
            ["All Types", "Classic RA", "Remote Help", "RDP Session", "Quick Assist"]
        )
        frow.addWidget(self._cmb_type)

        frow.addWidget(QLabel("Status:"))
        self._cmb_status = QComboBox()
        self._cmb_status.addItems([
            "All Statuses", "Completed", "Active / Ongoing",
            "Partial (no start)", "Disconnected (no auth logged)",
            "Detected", "Unknown",
        ])
        frow.addWidget(self._cmb_status)

        frow.addWidget(QLabel("Search:"))
        self._txt_search = QLineEdit()
        self._txt_search.setPlaceholderText("computer / user / remote host…")
        self._txt_search.setFixedWidth(200)
        self._txt_search.returnPressed.connect(self._apply_display_filters)
        frow.addWidget(self._txt_search)

        btn_apply = QPushButton("Apply")
        btn_apply.setFixedWidth(60)
        btn_apply.clicked.connect(self._apply_display_filters)
        frow.addWidget(btn_apply)

        btn_clr = QPushButton("Clear")
        btn_clr.setFixedWidth(60)
        btn_clr.clicked.connect(self._clear_filters)
        frow.addWidget(btn_clr)

        frow.addStretch()
        root.addLayout(frow)

        # ── Table ──────────────────────────────────────────────────────────
        self._tbl = QTableWidget(0, len(self._HEADERS))
        self._tbl.setHorizontalHeaderLabels(self._HEADERS)
        self._tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tbl.setAlternatingRowColors(False)
        self._tbl.setSortingEnabled(True)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.verticalHeader().setDefaultSectionSize(22)
        hdr = self._tbl.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tbl.customContextMenuRequested.connect(self._on_context_menu)
        root.addWidget(self._tbl, 1)

        # ── Summary bar ────────────────────────────────────────────────────
        self._lbl_summary = QLabel("")
        self._lbl_summary.setWordWrap(True)
        self._lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_summary.setStyleSheet(
            "background:#faf7f2; border:1px solid #c4bba8;"
            " border-radius:3px; padding:4px 8px; color:#1e1a14;"
        )
        root.addWidget(self._lbl_summary)

        # ── Button row ─────────────────────────────────────────────────────
        brow = QHBoxLayout()
        brow.setSpacing(8)

        btn_export = QPushButton("Export CSV…")
        btn_export.clicked.connect(self._on_export_csv)
        brow.addWidget(btn_export)

        brow.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setObjectName("okBtn")
        btn_close.setFixedWidth(80)
        btn_close.clicked.connect(self.close)
        brow.addWidget(btn_close)

        root.addLayout(brow)

    # ── Display logic ──────────────────────────────────────────────────────

    def _apply_display_filters(self) -> None:
        type_flt   = self._cmb_type.currentText()   if hasattr(self, "_cmb_type")   else "All Types"
        status_flt = self._cmb_status.currentText() if hasattr(self, "_cmb_status") else "All Statuses"
        needle     = (self._txt_search.text().strip().lower()
                      if hasattr(self, "_txt_search") else "")

        shown: list[dict] = []
        for s in self._all_sessions:
            if type_flt   != "All Types"    and s["type"]   != type_flt:
                continue
            if status_flt != "All Statuses" and s["status"] != status_flt:
                continue
            if needle:
                haystack = " ".join([
                    s["computer"], s["user"], s["remote_host"],
                    s["session_key"], s["status"], ", ".join(s["flags"]),
                ]).lower()
                if needle not in haystack:
                    continue
            shown.append(s)

        self._shown_sessions = shown
        self._populate_table()
        self._update_summary()

    def _clear_filters(self) -> None:
        if hasattr(self, "_cmb_type"):
            self._cmb_type.setCurrentIndex(0)
        if hasattr(self, "_cmb_status"):
            self._cmb_status.setCurrentIndex(0)
        if hasattr(self, "_txt_search"):
            self._txt_search.clear()
        self._apply_display_filters()

    def _populate_table(self) -> None:
        tbl = self._tbl
        tbl.setSortingEnabled(False)
        tbl.setRowCount(0)
        for orig_row, s in enumerate(self._shown_sessions):
            r = tbl.rowCount()
            tbl.insertRow(r)
            cells = [
                s["type"],
                s["computer"],
                s["start_ts"],
                s["end_ts"],
                s["duration"],
                s["user"],
                s["remote_host"],
                s["control"],
                s["status"],
                str(s["event_count"]),
                ", ".join(s["flags"]),
            ]
            _COL_TYPE     = 0
            _COL_DURATION = 4
            _COL_EVENTS   = 9
            for c, text in enumerate(cells):
                if c == _COL_DURATION:
                    # Numeric sort: unknown/out-of-order durations (duration_secs < 0)
                    # map to inf so "?" rows sort last in ascending order, not first.
                    _dsecs = s["duration_secs"]
                    _sort_key = float("inf") if _dsecs < 0 else _dsecs
                    item = _NumericSortItem(text)
                    item.setData(Qt.ItemDataRole.UserRole, _sort_key)
                elif c == _COL_EVENTS:
                    # Numeric sort: UserRole = integer event count
                    item = _NumericSortItem(text)
                    item.setData(Qt.ItemDataRole.UserRole, s["event_count"])
                else:
                    item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if c == _COL_TYPE:
                    # Store the shown_sessions index for context-menu lookup.
                    item.setData(Qt.ItemDataRole.UserRole, orig_row)
                    color = self._TYPE_COLORS.get(s["type"], "#1e1a14")
                    item.setForeground(QColor(color))
                tbl.setItem(r, c, item)
        tbl.setSortingEnabled(True)

    def _update_summary(self) -> None:
        total   = len(self._all_sessions)
        shown   = len(self._shown_sessions)
        # L6: use the totals cached at construction time (avoid O(n) per filter)
        by_type = getattr(self, "_by_type_totals", {})

        type_parts = " | ".join(
            f"<b>{t}</b>: {n}" for t, n in sorted(by_type.items())
        )
        html = (
            f"<span style='color:#1e1a14;'>"
            f"Showing <b>{shown}</b> of <b>{total}</b> session(s)"
            f"</span>"
        )
        if type_parts:
            html += f"&ensp;—&ensp;<span style='color:#5a4030;'>{type_parts}</span>"
        if self._truncated:
            html += (
                "&ensp;<span style='color:#8a4800;'>⚠ Results capped at 200,000 events — "
                "later sessions may be missing</span>"
            )
        if hasattr(self, "_lbl_summary"):
            self._lbl_summary.setText(html)

    # ── Context menu ───────────────────────────────────────────────────────

    def _on_context_menu(self, pos) -> None:
        from PySide6.QtWidgets import QMenu
        from PySide6.QtGui     import QGuiApplication

        index = self._tbl.indexAt(pos)
        if not index.isValid():
            return
        self._tbl.selectRow(index.row())
        cell = self._tbl.item(index.row(), 0)
        if cell is None:
            return
        orig_row = cell.data(Qt.ItemDataRole.UserRole)
        if orig_row is None or not (0 <= orig_row < len(self._shown_sessions)):
            return
        s = self._shown_sessions[orig_row]

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#2b2b2b; color:#e8e8e8; border:1px solid #555; }"
            "QMenu::item:selected { background:#4a6fa5; color:white; }"
            "QMenu::separator { height:1px; background:#555; margin:4px 8px; }"
        )

        act_type = menu.addAction(f"\U0001f4cb  Copy Type  ({s['type']})")
        act_type.triggered.connect(
            lambda: QGuiApplication.clipboard().setText(s["type"])
        )
        if s["computer"]:
            _comp = s["computer"]
            act_comp = menu.addAction(f"\U0001f4cb  Copy Computer  ({_comp})")
            act_comp.triggered.connect(lambda: QGuiApplication.clipboard().setText(_comp))
        if s["user"]:
            _usr = s["user"]
            act_usr = menu.addAction(f"\U0001f4cb  Copy User  ({_usr})")
            act_usr.triggered.connect(lambda: QGuiApplication.clipboard().setText(_usr))
        if s["remote_host"]:
            _rh = s["remote_host"]
            act_rh = menu.addAction(f"\U0001f4cb  Copy Remote Host  ({_rh})")
            act_rh.triggered.connect(lambda: QGuiApplication.clipboard().setText(_rh))

        if self._on_filter_fn and s["related_keys"]:
            menu.addSeparator()
            _rk = s["related_keys"]
            _si = dict(s)   # snapshot — avoid closure-over-loop-variable issues
            act_flt = menu.addAction("\U0001f50d  Filter to Session Events")
            act_flt.triggered.connect(lambda: self._on_filter_fn(_rk, _si))

        menu.exec(self._tbl.viewport().mapToGlobal(pos))

    # ── Export ─────────────────────────────────────────────────────────────

    def _on_export_csv(self) -> None:
        import csv
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Remote Assistance Sessions",
            "ra_sessions.csv", "CSV files (*.csv);;All files (*)"
        )
        if not path:
            return
        try:
            # Respect the user's current column-sort order when exporting.
            ordered: list[dict] = []
            for vis_row in range(self._tbl.rowCount()):
                cell = self._tbl.item(vis_row, 0)
                if cell is None:
                    continue
                orig = cell.data(Qt.ItemDataRole.UserRole)
                if orig is not None and 0 <= orig < len(self._shown_sessions):
                    ordered.append(self._shown_sessions[orig])
            if not ordered:
                ordered = list(self._shown_sessions)

            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                if self._truncated:
                    writer.writerow([
                        "NOTE: Dataset was capped at 200,000 events — "
                        "sessions from later in the time range may be missing."
                    ])
                # L2 fix: extractors are ordered to match _HEADERS exactly.
                # Adding a new column to _HEADERS must be accompanied by a
                # corresponding entry here; the assertion below catches the mismatch
                # at runtime so a future maintainer cannot silently break the export.
                _EXTRACTORS = [
                    lambda s: s["type"],
                    lambda s: s["computer"],
                    lambda s: s["start_ts"],
                    lambda s: s["end_ts"],
                    lambda s: s["duration"],
                    lambda s: s["user"],
                    lambda s: s["remote_host"],
                    lambda s: s["control"],
                    lambda s: s["status"],
                    lambda s: s["event_count"],
                    lambda s: ", ".join(s["flags"]),
                ]
                assert len(_EXTRACTORS) == len(self._HEADERS), (
                    f"CSV extractors ({len(_EXTRACTORS)}) out of sync with "
                    f"_HEADERS ({len(self._HEADERS)})"
                )
                writer.writerow(self._HEADERS)
                for s in ordered:
                    writer.writerow([fn(s) for fn in _EXTRACTORS])
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", f"Could not write CSV:\n{exc}")
            return
        # L4: echo the truncation caveat in the success dialog so users
        # are not surprised by missing sessions in the exported CSV.
        _trunc_note = (
            "\n\n⚠ Note: the source dataset was capped at 200,000 events;\n"
            "sessions from later in the time range may be incomplete."
            if self._truncated else ""
        )
        QMessageBox.information(
            self, "Export Complete",
            f"Saved {len(ordered)} session(s) to:\n{path}{_trunc_note}"
        )


# ── Remote Assistance JM background fetch worker ──────────────────────────────

class _RemoteAssistJMFetchWorker(QThread):
    """Fetch Remote Assistance-related events from Parquet shards (Juggernaut mode).

    Queries five Windows event channels relevant to remote access:
      • Microsoft-Windows-RemoteAssistance/Operational
      • Microsoft-Windows-RemoteHelp/Operational
      • Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
      • Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational
      • Security  (EIDs 4624/4634 with LogonType=10, 4778/4779, 4688 QuickAssist)

    Signal naming matches _WifiJMFetchWorker conventions:
      finished(list, bool)   — (events, was_truncated)
      fetch_error(str, str)  — (error_kind, detail_message)
    """

    finished    = Signal(list, bool)   # (list[dict], truncated)
    fetch_error = Signal(str, str)     # (error_kind, detail_message)

    _RA_CHANNELS = (
        "Microsoft-Windows-RemoteAssistance/Operational",
        "Microsoft-Windows-RemoteHelp/Operational",
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    )
    # Security legs are handled inline in run() with per-leg SQL predicates
    # (LogonType=10 for 4624/4634, LIKE filter for 4688) rather than a simple
    # EID IN list — so no class-level _SECURITY_EIDS constant is needed.

    def __init__(self, parquet_dir: str, parent=None) -> None:
        super().__init__(parent)
        self._parquet_dir = parquet_dir

    def run(self) -> None:
        import json  as _json
        import os    as _os
        import duckdb as _duckdb

        manifest_path = _os.path.join(self._parquet_dir, "parquet_manifest.json")
        try:
            with open(manifest_path, "r", encoding="utf-8") as _f:
                _raw = _f.read()
        except FileNotFoundError:
            logger.error("RA JM [manifest_missing]: %s", manifest_path)
            self.fetch_error.emit(
                "manifest_missing",
                f"Parquet manifest not found:\n{manifest_path}\n\n"
                "The dataset may have been moved or the JM session was not fully built.",
            )
            return
        except OSError as exc:
            logger.error("RA JM [manifest_read_error]: %s — %s", manifest_path, exc)
            self.fetch_error.emit(
                "manifest_read_error",
                f"Cannot read Parquet manifest:\n{exc}",
            )
            return

        try:
            shards = _json.loads(_raw)
        except _json.JSONDecodeError as exc:
            logger.error("RA JM [manifest_parse_error]: %s — %s", manifest_path, exc)
            self.fetch_error.emit(
                "manifest_parse_error",
                f"Parquet manifest is not valid JSON:\n{exc}",
            )
            return

        if not shards:
            self.finished.emit([], False)
            return

        shard_list = (
            "[" + ", ".join(f"'{p.replace(chr(39), chr(39)*2)}'" for p in shards) + "]"
        )
        chan_placeholders = ", ".join("?" * len(self._RA_CHANNELS))

        # Four-leg Security filter — each leg as narrow as possible.
        #
        #   Leg 1: RA/RH/TS channels — all EIDs (already narrow channels)
        #   Leg 2: 4778/4779 — always remote; no extra predicate needed
        #   Leg 3: 4624/4634 — detect LogonType=10 in both flat-dict and list-of-Data
        #           event_data shapes.
        #   Leg 4: 4688 — Quick Assist process detection with normal-mode parity:
        #           NewProcessName OR CommandLine OR Application (plus list-of-Data fallback).
        sql = (
            f"SELECT event_id, timestamp_utc, event_data_json, channel, "
            f"       computer, record_id, source_file "
            f"FROM parquet_scan({shard_list}) "
            f"WHERE ("
            f"    channel IN ({chan_placeholders})"
            f"    OR (channel = 'Security' AND event_id IN (4778, 4779))"
            f"    OR (channel = 'Security' AND event_id IN (4624, 4634)"
            f"        AND ("
            f"            json_extract_string(event_data_json, '$.LogonType') = '10'"
            f"            OR event_data_json LIKE '%\"LogonType\": \"10\"%'"
            f"            OR event_data_json LIKE '%\"LogonType\":\"10\"%'"
            f"            OR ("
            f"                ("
            f"                    lower(event_data_json) LIKE '%\"@name\":\"logontype\"%'"
            f"                    OR lower(event_data_json) LIKE '%\"@name\": \"logontype\"%'"
            f"                )"
            f"                AND ("
                    f"                    lower(event_data_json) LIKE '%\"#text\":\"10\"%'"
                    f"                    OR lower(event_data_json) LIKE '%\"#text\": \"10\"%'"
                f"                )"
            f"            )"
            f"        ))"
            f"    OR (channel = 'Security' AND event_id = 4688"
            f"        AND ("
            f"            lower(coalesce(json_extract_string(event_data_json, '$.NewProcessName'), '')) LIKE '%quickassist%'"
            f"            OR lower(coalesce(json_extract_string(event_data_json, '$.CommandLine'), '')) LIKE '%quickassist%'"
            f"            OR lower(coalesce(json_extract_string(event_data_json, '$.Application'), '')) LIKE '%quickassist%'"
            f"            OR ("
            f"                ("
            f"                    lower(event_data_json) LIKE '%\"@name\":\"newprocessname\"%'"
            f"                    OR lower(event_data_json) LIKE '%\"@name\": \"newprocessname\"%'"
            f"                )"
            f"                AND ("
            f"                    lower(event_data_json) LIKE '%\"#text\":\"%quickassist%'"
            f"                    OR lower(event_data_json) LIKE '%\"#text\": \"%quickassist%'"
            f"                )"
            f"            )"
            f"            OR ("
            f"                ("
            f"                    lower(event_data_json) LIKE '%\"@name\":\"commandline\"%'"
            f"                    OR lower(event_data_json) LIKE '%\"@name\": \"commandline\"%'"
            f"                )"
            f"                AND ("
            f"                    lower(event_data_json) LIKE '%\"#text\":\"%quickassist%'"
            f"                    OR lower(event_data_json) LIKE '%\"#text\": \"%quickassist%'"
            f"                )"
            f"            )"
            f"            OR ("
            f"                ("
            f"                    lower(event_data_json) LIKE '%\"@name\":\"application\"%'"
            f"                    OR lower(event_data_json) LIKE '%\"@name\": \"application\"%'"
            f"                )"
            f"                AND ("
            f"                    lower(event_data_json) LIKE '%\"#text\":\"%quickassist%'"
            f"                    OR lower(event_data_json) LIKE '%\"#text\": \"%quickassist%'"
            f"                )"
            f"            )"
            f"        ))"
            f") "
            f"ORDER BY timestamp_utc "
            f"LIMIT 200001"
        )
        params = list(self._RA_CHANNELS)

        try:
            con = _duckdb.connect()
            try:
                rows = con.execute(sql, params).fetchall()
            finally:
                con.close()
        except Exception as exc:
            logger.error("RA JM [duckdb_query_error]: %s", exc)
            self.fetch_error.emit("duckdb_query_error", str(exc))
            return

        truncated = len(rows) > 200_000
        if truncated:
            rows = rows[:200_000]

        events: list[dict] = []
        for eid, ts_utc, ed_json, channel, computer, record_id, source_file in rows:
            try:
                ed = _json.loads(ed_json) if ed_json else {}
            except Exception:
                ed = {}
            events.append({
                "event_id":    eid,
                "timestamp":   str(ts_utc or ""),
                "event_data":  ed,
                "channel":     str(channel or ""),
                "computer":    str(computer or ""),
                "record_id":   record_id,
                "source_file": str(source_file or ""),
            })
        self.finished.emit(events, truncated)


# ── Computer Normalisation helpers ────────────────────────────────────────────

def _norm_computer_key(raw: str) -> str:
    """Collapse a Computer field to a canonical short-hostname key.

    Rules (applied in order):
      • strip whitespace and any trailing dot (FQDN trailing-dot form)
      • lowercase
      • take the first label before "." so FQDN and short name collapse:
            "WORK01.contoso.local"  → "work01"
            "Work01"                 → "work01"
            "WORK01 "                → "work01"
      • blank input → "(unknown)" so empty Computer fields cluster together
    """
    s = str(raw or "").strip().rstrip(".").lower()
    if not s:
        return "(unknown)"
    # Short hostname before first dot
    return s.split(".", 1)[0]


def _is_forwarded_source(source_file: str) -> bool:
    """True if the source EVTX file is a Windows Event Forwarding collector log.

    ForwardedEvents.evtx (the default WEF target) contains events from MANY
    remote source computers — each event preserves the source machine's
    Computer field, so a single forwarded log can inflate distinct-computer
    counts dramatically.  We flag rows from such files so the UI can show
    "Forwarded? Yes" and the analyst can decide whether to filter them out.
    """
    import os as _os
    base = _os.path.basename(str(source_file or "")).lower()
    # Default name + custom-channel variants seen in the wild
    return "forwardedevents" in base or base.endswith("_forwarded.evtx")


# ── Computer Normalisation JM worker ──────────────────────────────────────────

class _ComputerNormJMWorker(QThread):
    """Aggregate distinct (computer, source_file, count) tuples in JM mode.

    Single DuckDB GROUP BY against the full parquet shard set — much cheaper
    than the WiFi / Remote Assistance fetchers because we never read
    event_data_json, only the small columnar fields.  No LIMIT needed: even
    on a 50 M-event dataset the GROUP BY produces at most a few thousand rows.

    Signal naming mirrors _RemoteAssistJMFetchWorker:
      finished(list)       — list[dict] with keys: computer, source_file, n
      fetch_error(str,str) — (error_kind, detail_message)
    """

    finished    = Signal(list)
    fetch_error = Signal(str, str)

    def __init__(self, parquet_dir: str, parent=None) -> None:
        super().__init__(parent)
        self._parquet_dir = parquet_dir

    def run(self) -> None:
        import json   as _json
        import os     as _os
        import duckdb as _duckdb

        manifest_path = _os.path.join(self._parquet_dir, "parquet_manifest.json")
        try:
            with open(manifest_path, "r", encoding="utf-8") as _f:
                _raw = _f.read()
        except FileNotFoundError:
            logger.error("ComputerNorm JM [manifest_missing]: %s", manifest_path)
            self.fetch_error.emit(
                "manifest_missing",
                f"Parquet manifest not found:\n{manifest_path}",
            )
            return
        except OSError as exc:
            logger.error("ComputerNorm JM [manifest_read_error]: %s — %s",
                         manifest_path, exc)
            self.fetch_error.emit("manifest_read_error",
                                  f"Cannot read Parquet manifest:\n{exc}")
            return

        try:
            shards = _json.loads(_raw)
        except _json.JSONDecodeError as exc:
            logger.error("ComputerNorm JM [manifest_parse_error]: %s", exc)
            self.fetch_error.emit("manifest_parse_error",
                                  f"Parquet manifest is not valid JSON:\n{exc}")
            return

        if not shards:
            self.finished.emit([])
            return

        shard_list = (
            "[" + ", ".join(f"'{p.replace(chr(39), chr(39)*2)}'" for p in shards) + "]"
        )
        sql = (
            f"SELECT COALESCE(computer, '') AS computer, "
            f"       COALESCE(source_file, '') AS source_file, "
            f"       COUNT(*) AS n "
            f"FROM parquet_scan({shard_list}) "
            f"GROUP BY computer, source_file"
        )

        try:
            con = _duckdb.connect()
            try:
                rows = con.execute(sql).fetchall()
            finally:
                con.close()
        except Exception as exc:
            logger.error("ComputerNorm JM [duckdb_query_error]: %s", exc)
            self.fetch_error.emit("duckdb_query_error", str(exc))
            return

        out: list[dict] = []
        for computer, source_file, n in rows:
            out.append({
                "computer":    str(computer or ""),
                "source_file": str(source_file or ""),
                "n":           int(n or 0),
            })
        self.finished.emit(out)


# ── Computer Normalisation dialog ─────────────────────────────────────────────

class _ComputerNormalisationDialog(QDialog):
    """Browse all Computer-field values collapsed to canonical hostnames.

    Each row represents one normalised key (lowercased short hostname).  The
    Variants column shows how many distinct raw strings collapsed into that
    key; the Variant Details column lists them comma-separated (truncated).
    The Forwarded column flags rows that include events from a
    ForwardedEvents.evtx collector log — a single such file can inflate the
    distinct-Computer count by dozens because WEF preserves the original
    source machine in each forwarded event.

    *rows* is the raw aggregation: list[dict] with keys
        ``computer``, ``source_file``, ``n``.
    *on_filter_fn* is invoked with ``(variants: list[str])`` when the user
    chooses "Filter Events to This Computer" from the context menu.
    """

    _HEADERS = [
        "Normalised Name", "Variants", "Events", "Source Files",
        "Forwarded?", "Variant Details",
    ]

    _BASE_QSS = """
        QDialog { background: #f5f0e8; }
        QLabel  { color: #1e1a14; font-size: 9pt; }
        QLineEdit {
            background: #faf7f2; color: #1e1a14;
            border: 1px solid #c4bba8; border-radius: 3px;
            padding: 2px 6px; font-size: 9pt;
        }
        QLineEdit:focus { border-color: #7a5c1e; }
        QComboBox {
            background: #faf7f2; color: #1e1a14;
            border: 1px solid #c4bba8; border-radius: 3px;
            padding: 2px 6px; font-size: 9pt; min-width: 130px;
        }
        QComboBox QAbstractItemView {
            background: #faf7f2; color: #1e1a14;
            selection-background-color: #7a5c1e;
        }
        QPushButton {
            background: #e4ddd3; color: #1e1a14;
            border: 1px solid #c4bba8; border-radius: 3px;
            padding: 3px 12px; font-size: 9pt;
        }
        QPushButton:hover    { background: #d6cdbf; }
        QPushButton:pressed  { background: #c4bba8; }
        QPushButton#okBtn {
            background: #7a5c1e; color: #ffffff;
            border: 1px solid #5a3e1e;
        }
        QPushButton#okBtn:hover   { background: #8a6c2e; }
        QPushButton#okBtn:pressed { background: #5a3e1e; }
        QTableWidget {
            background: #faf7f2; color: #1e1a14;
            border: 1px solid #c4bba8; gridline-color: #e0d8c4;
            font-size: 9pt; outline: none;
        }
        QTableWidget::item { padding: 1px 4px; }
        QTableWidget::item:selected {
            background: #7a5c1e; color: #ffffff;
        }
        QHeaderView::section {
            background: #e4ddd3; color: #1e1a14;
            border: none; border-right: 1px solid #c4bba8;
            border-bottom: 1px solid #c4bba8;
            padding: 3px 6px; font-size: 9pt; font-weight: bold;
        }
        QScrollBar:vertical { background: #f5f0e8; width: 8px; margin: 0; }
        QScrollBar::handle:vertical {
            background: #5a3e1e; border-radius: 4px; min-height: 20px;
        }
        QScrollBar::handle:vertical:hover { background: #7a5c1e; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
        QScrollBar:horizontal { background: #f5f0e8; height: 8px; margin: 0; }
        QScrollBar::handle:horizontal {
            background: #5a3e1e; border-radius: 4px; min-width: 20px;
        }
        QScrollBar::handle:horizontal:hover { background: #7a5c1e; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
    """

    def __init__(self, rows: list[dict], on_filter_fn=None, parent=None) -> None:
        super().__init__(parent)
        self._on_filter_fn = on_filter_fn
        self._all_rows:    list[dict] = self._build_rows(rows)
        self._shown_rows:  list[dict] = list(self._all_rows)
        self._build_ui()
        self._apply_display_filters()

    # ── Aggregation ────────────────────────────────────────────────────────

    @staticmethod
    def _build_rows(raw_rows: list[dict]) -> list[dict]:
        """Group (computer, source_file, n) tuples by normalised key.

        Each output row carries:
          norm_name        — canonical hostname used for grouping
          variants         — list[str] of raw Computer strings (originals)
          variant_counts   — dict[variant → event_count]
          source_files     — list[str] of basenames the variants appear in
          source_files_full— list[str] of FULL source paths (for filtering)
          forwarded        — True if any source_file is a ForwardedEvents log
          event_count      — sum of n across all (variant, source_file) entries
        """
        import os as _os
        agg: dict[str, dict] = {}
        for r in raw_rows:
            comp = str(r.get("computer") or "")
            sf   = str(r.get("source_file") or "")
            n    = int(r.get("n") or 0)
            key  = _norm_computer_key(comp)
            slot = agg.setdefault(key, {
                "norm_name":         key,
                "variants_set":      set(),
                "variant_counts":    {},
                "source_files_set":  set(),
                "source_files_full": set(),
                "forwarded":         False,
                "event_count":       0,
            })
            slot["variants_set"].add(comp)
            slot["variant_counts"][comp] = slot["variant_counts"].get(comp, 0) + n
            slot["source_files_full"].add(sf)
            if sf:
                slot["source_files_set"].add(_os.path.basename(sf))
            if _is_forwarded_source(sf):
                slot["forwarded"] = True
            slot["event_count"] += n

        out: list[dict] = []
        for slot in agg.values():
            variants_sorted = sorted(slot["variants_set"], key=lambda x: x.lower())
            out.append({
                "norm_name":         slot["norm_name"],
                "variants":          variants_sorted,
                "variant_count":     len(variants_sorted),
                "variant_counts":    slot["variant_counts"],
                "source_files":      sorted(slot["source_files_set"]),
                "source_files_full": sorted(slot["source_files_full"]),
                "source_file_count": len(slot["source_files_set"]),
                "forwarded":         slot["forwarded"],
                "event_count":       slot["event_count"],
            })
        # Sort: most variants first (so ambiguous / FQDN-vs-short rises to top)
        out.sort(key=lambda d: (-d["variant_count"], -d["event_count"],
                                 d["norm_name"]))
        return out

    # ── UI building ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.setWindowTitle("Computer Normalisation")
        self.resize(1100, 600)
        self.setStyleSheet(self._BASE_QSS)
        self.setAttribute(Qt.WA_DeleteOnClose)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        # ── Filter row ─────────────────────────────────────────────────────
        frow = QHBoxLayout()
        frow.setSpacing(6)

        frow.addWidget(QLabel("Show:"))
        self._cmb_show = QComboBox()
        self._cmb_show.addItems([
            "All hosts",
            "Only hosts with multiple variants",
            "Only hosts in Forwarded logs",
            "Hide Forwarded-only hosts",
        ])
        self._cmb_show.currentIndexChanged.connect(self._apply_display_filters)
        frow.addWidget(self._cmb_show)

        frow.addWidget(QLabel("Search:"))
        self._txt_search = QLineEdit()
        self._txt_search.setPlaceholderText("hostname / variant / source file…")
        self._txt_search.setFixedWidth(220)
        self._txt_search.returnPressed.connect(self._apply_display_filters)
        frow.addWidget(self._txt_search)

        btn_apply = QPushButton("Apply")
        btn_apply.setFixedWidth(60)
        btn_apply.clicked.connect(self._apply_display_filters)
        frow.addWidget(btn_apply)

        btn_clear = QPushButton("Clear")
        btn_clear.setFixedWidth(60)
        btn_clear.clicked.connect(self._clear_filters)
        frow.addWidget(btn_clear)

        frow.addStretch()
        root.addLayout(frow)

        # ── Table ──────────────────────────────────────────────────────────
        self._tbl = QTableWidget(0, len(self._HEADERS))
        self._tbl.setHorizontalHeaderLabels(self._HEADERS)
        self._tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._tbl.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self._tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._tbl.setAlternatingRowColors(False)
        self._tbl.setSortingEnabled(True)
        self._tbl.verticalHeader().setVisible(False)
        self._tbl.verticalHeader().setDefaultSectionSize(22)
        hdr = self._tbl.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._tbl.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tbl.customContextMenuRequested.connect(self._on_context_menu)
        root.addWidget(self._tbl, 1)

        # ── Summary bar ────────────────────────────────────────────────────
        self._lbl_summary = QLabel("")
        self._lbl_summary.setWordWrap(True)
        self._lbl_summary.setTextFormat(Qt.TextFormat.RichText)
        self._lbl_summary.setStyleSheet(
            "background:#faf7f2; border:1px solid #c4bba8;"
            " border-radius:3px; padding:4px 8px; color:#1e1a14;"
        )
        root.addWidget(self._lbl_summary)

        # ── Button row ─────────────────────────────────────────────────────
        brow = QHBoxLayout()
        brow.setSpacing(8)

        btn_export = QPushButton("Export CSV…")
        btn_export.clicked.connect(self._on_export_csv)
        brow.addWidget(btn_export)

        brow.addStretch()

        btn_close = QPushButton("Close")
        btn_close.setObjectName("okBtn")
        btn_close.setFixedWidth(80)
        btn_close.clicked.connect(self.close)
        brow.addWidget(btn_close)

        root.addLayout(brow)

    # ── Display logic ──────────────────────────────────────────────────────

    def _apply_display_filters(self) -> None:
        mode   = self._cmb_show.currentText() if hasattr(self, "_cmb_show") else "All hosts"
        needle = (self._txt_search.text().strip().lower()
                  if hasattr(self, "_txt_search") else "")
        shown: list[dict] = []
        for r in self._all_rows:
            if mode == "Only hosts with multiple variants" and r["variant_count"] < 2:
                continue
            if mode == "Only hosts in Forwarded logs" and not r["forwarded"]:
                continue
            if mode == "Hide Forwarded-only hosts":
                # Drop rows where EVERY source file is a ForwardedEvents log —
                # these are the most likely "extra" hosts inflating the count.
                _all_fwd = all(
                    _is_forwarded_source(sf) for sf in r["source_files_full"]
                ) if r["source_files_full"] else False
                if _all_fwd:
                    continue
            if needle:
                hay = " ".join([
                    r["norm_name"],
                    " ".join(r["variants"]),
                    " ".join(r["source_files"]),
                ]).lower()
                if needle not in hay:
                    continue
            shown.append(r)
        self._shown_rows = shown
        self._populate_table()
        self._update_summary()

    def _clear_filters(self) -> None:
        if hasattr(self, "_cmb_show"):
            self._cmb_show.setCurrentIndex(0)
        if hasattr(self, "_txt_search"):
            self._txt_search.clear()
        self._apply_display_filters()

    def _populate_table(self) -> None:
        tbl = self._tbl
        tbl.setSortingEnabled(False)
        tbl.setRowCount(0)
        for orig_row, r in enumerate(self._shown_rows):
            # Compact variant detail string (truncated)
            _vd_full = ", ".join(r["variants"])
            _vd_show = _vd_full if len(_vd_full) <= 100 else _vd_full[:97] + "…"
            cells = [
                r["norm_name"],
                str(r["variant_count"]),
                f"{r['event_count']:,}",
                str(r["source_file_count"]),
                "Yes" if r["forwarded"] else "No",
                _vd_show,
            ]
            row = tbl.rowCount()
            tbl.insertRow(row)
            for c, text in enumerate(cells):
                if c in (1, 3):       # Variants / Source Files (int sort)
                    item = _NumericSortItem(text)
                    item.setData(Qt.ItemDataRole.UserRole,
                                 r["variant_count"] if c == 1 else r["source_file_count"])
                elif c == 2:          # Events (int sort, comma-formatted)
                    item = _NumericSortItem(text)
                    item.setData(Qt.ItemDataRole.UserRole, r["event_count"])
                else:
                    item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if c == 0:
                    # Stash orig_row index for context-menu lookup.
                    item.setData(Qt.ItemDataRole.UserRole, orig_row)
                    if r["variant_count"] > 1:
                        item.setForeground(QColor("#7a5c1e"))   # highlight
                if c == 4 and r["forwarded"]:
                    item.setForeground(QColor("#8a4800"))       # amber
                if c == 5:
                    # Full variant list as tooltip so truncation is non-lossy
                    item.setToolTip(_vd_full)
                tbl.setItem(row, c, item)
        tbl.setSortingEnabled(True)

    def _update_summary(self) -> None:
        total = len(self._all_rows)
        shown = len(self._shown_rows)
        multi = sum(1 for r in self._all_rows if r["variant_count"] > 1)
        fwd   = sum(1 for r in self._all_rows if r["forwarded"])
        total_events  = sum(r["event_count"] for r in self._all_rows)
        total_raw_vars = sum(r["variant_count"] for r in self._all_rows)
        html = (
            f"<span style='color:#1e1a14;'>"
            f"Showing <b>{shown}</b> of <b>{total}</b> normalised host(s)"
            f"</span>"
            f"&ensp;—&ensp;<span style='color:#5a4030;'>"
            f"<b>{total_raw_vars}</b> raw Computer string(s) collapsed&ensp;|"
            f"&ensp;<b>{multi}</b> with multiple variants&ensp;|"
            f"&ensp;<b>{fwd}</b> seen in Forwarded logs&ensp;|"
            f"&ensp;<b>{total_events:,}</b> event(s)"
            f"</span>"
        )
        if hasattr(self, "_lbl_summary"):
            self._lbl_summary.setText(html)

    # ── Context menu ───────────────────────────────────────────────────────

    def _on_context_menu(self, pos) -> None:
        from PySide6.QtWidgets import QMenu, QMessageBox
        from PySide6.QtGui     import QGuiApplication
        index = self._tbl.indexAt(pos)
        if not index.isValid():
            return
        self._tbl.selectRow(index.row())
        cell = self._tbl.item(index.row(), 0)
        if cell is None:
            return
        orig = cell.data(Qt.ItemDataRole.UserRole)
        if orig is None or not (0 <= orig < len(self._shown_rows)):
            return
        r = self._shown_rows[orig]

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#2b2b2b; color:#e8e8e8; border:1px solid #555; }"
            "QMenu::item:selected { background:#4a6fa5; color:white; }"
            "QMenu::separator { height:1px; background:#555; margin:4px 8px; }"
        )

        act_n = menu.addAction(f"\U0001f4cb  Copy Normalised Name  ({r['norm_name']})")
        act_n.triggered.connect(lambda: QGuiApplication.clipboard().setText(r["norm_name"]))

        if r["variants"]:
            act_v = menu.addAction(f"\U0001f4cb  Copy All Variants  ({r['variant_count']})")
            act_v.triggered.connect(
                lambda: QGuiApplication.clipboard().setText("\n".join(r["variants"]))
            )

        if r["source_files"]:
            act_s = menu.addAction(
                f"\U0001f4cb  Copy Source Files  ({r['source_file_count']})"
            )
            act_s.triggered.connect(
                lambda: QGuiApplication.clipboard().setText("\n".join(r["source_files"]))
            )

        # Show variant breakdown popup with per-variant event counts.
        act_d = menu.addAction("\U0001f4cb  Show Variant Breakdown…")
        act_d.triggered.connect(lambda: self._show_variant_breakdown(r))

        if self._on_filter_fn and r["variants"]:
            menu.addSeparator()
            _vars = list(r["variants"])
            act_f = menu.addAction(
                f"\U0001f50d  Filter Events to This Computer  "
                f"({r['variant_count']} variant{'s' if r['variant_count'] != 1 else ''})"
            )
            act_f.triggered.connect(lambda: self._on_filter_fn(_vars))

        menu.exec(self._tbl.viewport().mapToGlobal(pos))

    def _show_variant_breakdown(self, r: dict) -> None:
        from PySide6.QtWidgets import QMessageBox
        lines = [f"Normalised:  {r['norm_name']}",
                 f"Total events: {r['event_count']:,}", ""]
        lines.append("Variants (raw Computer values):")
        for v in r["variants"]:
            n = r["variant_counts"].get(v, 0)
            disp = v if v else "(empty)"
            lines.append(f"  • {disp}  —  {n:,} event(s)")
        lines.append("")
        lines.append("Source files:")
        for sf in r["source_files"]:
            mark = "  (FORWARDED)" if _is_forwarded_source(sf) else ""
            lines.append(f"  • {sf}{mark}")
        QMessageBox.information(self, f"Variant Breakdown — {r['norm_name']}",
                                "\n".join(lines))

    # ── Export ─────────────────────────────────────────────────────────────

    def _on_export_csv(self) -> None:
        import csv
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Computer Normalisation",
            "computer_normalisation.csv", "CSV files (*.csv);;All files (*)"
        )
        if not path:
            return
        try:
            # Respect current sort order
            ordered: list[dict] = []
            for vis in range(self._tbl.rowCount()):
                cell = self._tbl.item(vis, 0)
                if cell is None:
                    continue
                orig = cell.data(Qt.ItemDataRole.UserRole)
                if orig is not None and 0 <= orig < len(self._shown_rows):
                    ordered.append(self._shown_rows[orig])
            if not ordered:
                ordered = list(self._shown_rows)

            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Normalised Name", "Variants", "Events",
                    "Source Files", "Forwarded?", "Variant Details",
                    "Source File Details",
                ])
                for r in ordered:
                    writer.writerow([
                        r["norm_name"],
                        r["variant_count"],
                        r["event_count"],
                        r["source_file_count"],
                        "Yes" if r["forwarded"] else "No",
                        " | ".join(r["variants"]),
                        " | ".join(r["source_files"]),
                    ])
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed",
                                 f"Could not write CSV:\n{exc}")
            return
        QMessageBox.information(self, "Export Complete",
                                f"Saved {len(ordered)} row(s) to:\n{path}")


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
        self.setWindowTitle("EventHawk  v1.3")
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
        # RA session filter tracking — L1 fix: explicit init so the attribute
        # is always present and _clear_ra_filter_if_active() can safely reference
        # it without relying on getattr's default-value fallback.
        self._ra_filter_active: bool = False
        self._ra_dlg = None
        # Computer Normalisation dialog tracking (single instance, JM async).
        self._computer_norm_dlg = None
        self._computer_norm_jm_req_id: int = 0
        self._computer_norm_jm_workers: list = []
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
        # col_idx → (mode, values) where mode in {"include", "exclude"}.
        # "include" means "keep only rows whose value is in values".
        # "exclude" means "drop rows whose value is in values".
        # An entry exists only while a non-trivial filter is active on the column.
        self._col_filters: dict[int, tuple[str, list[str]]] = {}

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

        a = tm.addAction("WiFi History\u2026")
        a.setToolTip("Browse WiFi connection/disconnection history from WLAN-AutoConfig events")
        a.triggered.connect(self._on_show_wifi_history)

        a = tm.addAction("Remote Assistance Sessions\u2026")
        a.setToolTip(
            "Browse Remote Assistance, Remote Help, RDP, and Quick Assist sessions "
            "reconstructed from Windows event logs"
        )
        a.triggered.connect(self._on_show_remote_assist)

        a = tm.addAction("Computer Normalisation\u2026")
        a.setToolTip(
            "Collapse FQDN/short-name/case variants of the Computer field to canonical "
            "hostnames; flag computers introduced by ForwardedEvents.evtx (Windows "
            "Event Forwarding) so they can be excluded from host counts"
        )
        a.triggered.connect(self._on_show_computer_norm)

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

        # Explicit apply — profiles do NOT auto-apply on toggle.  The user ticks
        # the profiles they want, then clicks Apply so a single filter pass runs.
        # Works in BOTH Juggernaut and normal mode WITHOUT re-parsing the logs.
        self._btn_apply_profiles = QPushButton("✓ Apply Profiles")
        self._btn_apply_profiles.setToolTip(
            "Apply the ticked profiles to the already-parsed events.\n"
            "Filters in place — does NOT re-parse the logs.\n"
            "Tick several profiles first, then click once."
        )
        self._btn_apply_profiles.clicked.connect(self._on_apply_profiles_clicked)
        layout.addWidget(self._btn_apply_profiles)

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

    def _create_configured_table(self, proxy: EventFilterProxyModel) -> _EventTableView:
        """Create and configure a QTableView with standard settings."""
        table = _EventTableView()
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

        # Inherit active session filter so a newly opened per-file tab is
        # already filtered to the same session as the merged view.
        _active_keys = getattr(self, "_active_jm_session_keys", frozenset())
        if _active_keys:
            file_model.apply_bookmark_filter(_active_keys)

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

        # Invalidate the logon-session browser cache when the active tab changes
        # in normal mode.  Close the existing dialog so it can no longer apply
        # stale session filters against the newly active dataset.
        if self._hw_model is None:
            self._close_logon_sessions_dlg()
            self._close_ra_dlg()
            self._close_computer_norm_dlg()

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

        # ── Parse-integrity check: unparsed records must be visible ──────────
        # A skipped-record count is a forensic finding (possible corruption,
        # tampering, or tool limitation) — surface it, never bury it in logs.
        try:
            _stats = getattr(self._hw_worker, "parse_stats", {}) or {}

            def _file_problem(v: dict) -> str:
                """Return a short problem description for one file's stats, or ''."""
                bits = []
                _sk = v.get("json_errors", 0) + v.get("extract_errors", 0)
                if _sk:
                    bits.append(f"{_sk:,} unparsed record(s)")
                if v.get("stream_error"):
                    _sal = v.get("salvaged", 0)
                    _unrec = v.get("salvage_unrecoverable", 0)
                    if _sal or _unrec:
                        # Salvage ran — report recovery, not a bare abort.
                        _txt = (f"parse aborted mid-file but RECOVERED "
                                f"{_sal:,} record(s) via chunk salvage")
                        if _unrec:
                            _txt += f"; {_unrec} chunk(s) unrecoverable"
                        bits.append(_txt)
                    else:
                        bits.append(f"parse ABORTED mid-file ({v['stream_error']})")
                if v.get("open_error"):
                    bits.append("file could not be opened")
                if v.get("rows_lost_to_write_failure"):
                    bits.append(
                        f"{v['rows_lost_to_write_failure']:,} row(s) lost to shard-write failure"
                    )
                if v.get("missing_vs_expected"):
                    bits.append(
                        f"{v['missing_vs_expected']:,} record(s) declared in chunk headers "
                        f"not parsed (see Missing Record IDs)"
                    )
                if v.get("truncation"):
                    bits.append(v["truncation"])
                return "; ".join(bits)

            _problems = []
            for k, v in _stats.items():
                desc = _file_problem(v)
                if desc:
                    _name = ("[storage]" if k == "__shard_write_loss__"
                             else os.path.basename(k))
                    _problems.append(f"{_name}: {desc}")

            if _problems:
                QMessageBox.warning(
                    self, "Parse Integrity Warning",
                    "Some evidence did NOT fully load — results may be "
                    "incomplete:\n\n"
                    + "\n".join(_problems[:15])
                    + ("\n…" if len(_problems) > 15 else "")
                    + "\n\nA parse ABORT means all records after the failure "
                    "point are missing from this session.\n"
                    "Details: parse_stats.json in the session directory.",
                )
        except Exception:
            logger.warning("Parse-integrity stats check failed", exc_info=True)

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

        # ── Profiles are applied MANUALLY via the "Apply Profiles" button ──
        # Deliberately NOT auto-applied on toggle: ticking several profiles used
        # to fire a filter pass per checkbox (and, on systems that fall back to
        # normal mode, a full re-parse each time).  The explicit button runs a
        # single filter pass over the already-loaded data in either mode.
        # _hw_profile_signal_connected stays False so the cleanup disconnect is
        # a no-op.  (Left here intentionally — see _on_apply_profiles_clicked.)
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
                        f"SELECT {col}, COUNT(*) FROM events "
                        f"WHERE {col} IS NOT NULL AND {col} != '' "
                        f"GROUP BY {col} "
                        f"ORDER BY COUNT(*) DESC LIMIT 500"
                    ).fetchall()
                    meta[key] = {r[0]: r[1] for r in rows}
                eid_rows = _con.execute(
                    "SELECT event_id, COUNT(*) FROM events "
                    "GROUP BY event_id ORDER BY COUNT(*) DESC LIMIT 2000"
                ).fetchall()
                meta["event_id"] = {str(r[0]): r[1] for r in eid_rows}
                # Level names for the filter dialog level checkboxes
                lvl_rows = _con.execute(
                    "SELECT level_name, COUNT(*) FROM events "
                    "WHERE level_name IS NOT NULL AND level_name != '' "
                    "GROUP BY level_name ORDER BY COUNT(*) DESC"
                ).fetchall()
                meta["level"] = {r[0]: r[1] for r in lvl_rows}
            except Exception as exc:
                _logger.warning("_load_jm_metadata background worker failed: %s", exc)
            finally:
                try:
                    _con.close()
                except Exception:
                    pass

            # Post result back to main thread — QTimer.singleShot is thread-safe.
            QTimer.singleShot(0, lambda m=meta: self._on_jm_metadata_loaded(m))

        threading.Thread(target=_worker, daemon=True, name="jm-metadata").start()

    def _on_jm_metadata_loaded(self, meta: dict) -> None:
        """Receive FilterDialog metadata loaded by the background worker thread."""
        self._metadata = meta

    def _query_jm_metadata_sync(self) -> dict:
        """Query JM metadata synchronously from the Arrow table (main-thread fallback).

        Called when the user opens the Advanced Filter dialog and the background
        metadata loader hasn't completed (or silently failed).  Typically finishes
        in < 200 ms even on multi-million-row tables thanks to DuckDB's vectorised
        GROUP BY on dict-encoded Arrow columns.
        """
        import logging as _log
        _logger = _log.getLogger(__name__)
        meta: dict = {}
        if self._hw_model is None:
            return meta
        try:
            import duckdb
            arrow_table = self._hw_model._full_table
            _con = duckdb.connect()
            _con.register("events", arrow_table)
            for col, key in (
                ("provider", "source"),
                ("channel",  "category"),
                ("user_id",  "user"),
                ("computer", "computer"),
            ):
                rows = _con.execute(
                    f"SELECT {col}, COUNT(*) FROM events "
                    f"WHERE {col} IS NOT NULL AND {col} != '' "
                    f"GROUP BY {col} "
                    f"ORDER BY COUNT(*) DESC LIMIT 500"
                ).fetchall()
                meta[key] = {r[0]: r[1] for r in rows}
            eid_rows = _con.execute(
                "SELECT event_id, COUNT(*) FROM events "
                "GROUP BY event_id ORDER BY COUNT(*) DESC LIMIT 2000"
            ).fetchall()
            meta["event_id"] = {str(r[0]): r[1] for r in eid_rows}
            lvl_rows = _con.execute(
                "SELECT level_name, COUNT(*) FROM events "
                "WHERE level_name IS NOT NULL AND level_name != '' "
                "GROUP BY level_name ORDER BY COUNT(*) DESC"
            ).fetchall()
            meta["level"] = {r[0]: r[1] for r in lvl_rows}
            _con.close()
            _logger.info("_query_jm_metadata_sync: loaded %d sources, %d categories, %d users, %d computers",
                         len(meta.get("source", {})), len(meta.get("category", {})),
                         len(meta.get("user", {})), len(meta.get("computer", {})))
        except Exception as exc:
            _logger.warning("_query_jm_metadata_sync failed: %s", exc)
        return meta

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
        # Reset session-filter state so stale keys are not reapplied to tabs
        # opened in a subsequent JM load.
        self._active_jm_session_keys = frozenset()
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

    def _on_apply_profiles_clicked(self) -> None:
        """Apply the currently-ticked profiles to the loaded events, IN PLACE.

        Fully manual: profiles do NOT auto-apply on toggle.  The user ticks the
        profiles they want and clicks Apply once — so selecting several profiles
        no longer fires a filter pass per tick.  Works in BOTH modes WITHOUT
        re-parsing:
          • Juggernaut: apply_filter() on the in-memory Arrow model.
          • Normal:     set_advanced_filter() on the view proxy.
        This is the fix for "some systems re-parse on every profile" — those
        systems run normal mode, which previously applied profiles only at parse
        time (so changing a profile meant a full re-parse).  Profiles are stacked
        ON TOP of any active Advanced Filter cfg (same slot), so applying a
        profile never wipes the advanced filter and vice-versa.
        """
        fc = self._build_filter_config(base=getattr(self, "_adv_filter_cfg", None))

        if self._hw_model is not None:
            # Juggernaut — filter the in-memory Arrow table (no re-parse).
            self._show_hw_loading_dialog(
                heading="Please Wait — Applying Profiles",
                detail="Filtering events…",
            )
            self._hw_model.apply_filter(fc)
            for _fp, _st in self._file_tabs.items():
                if _fp.startswith("__chain__"):
                    continue
                try:
                    _st.model.apply_filter(fc)
                except Exception:
                    # Log, don't swallow: a per-file-tab that fails to filter is
                    # a real problem the user should see, not hidden.
                    logger.warning(
                        "Apply Profiles: failed to filter JM tab %r", _fp, exc_info=True
                    )
        else:
            # Normal mode — apply live to the view proxy (no re-parse).
            _proxy = getattr(self, "_active_proxy", None) or getattr(self, "_proxy_model", None)
            if _proxy is None:
                QMessageBox.information(
                    self, "No Events",
                    "Parse some logs first, then click Apply Profiles.",
                )
                return
            _proxy.set_advanced_filter(fc)
            for _fp, _st in self._file_tabs.items():
                if _fp.startswith("__chain__"):
                    continue
                try:
                    _st.proxy.set_advanced_filter(fc)
                except Exception:
                    logger.warning(
                        "Apply Profiles: failed to filter normal-mode tab %r", _fp, exc_info=True
                    )

        self._update_adv_filter_badge()
        self._update_count_label()

    def _on_hw_profile_filter_changed(self) -> None:
        """Re-apply the profile selection as a SQL filter in Juggernaut mode.

        Called whenever the user checks/unchecks a profile while Juggernaut
        Mode is active.  Builds the *combined* filter (active profiles stacked
        ON TOP of any Advanced Filter cfg already applied) and pushes it to
        the live model.

        Why stack rather than replace: profile and Advanced Filter share the
        same ``apply_filter()`` slot on ArrowTableModel — replacing it with a
        profile-only cfg would silently wipe whatever the user typed in the
        Advanced Filter dialog (and vice-versa in ``_on_advanced_filter_clicked``).
        """
        if self._hw_model is None:
            return
        # Stack profiles on top of the last-applied Advanced Filter cfg.
        # When neither is active, _build_filter_config returns empty_filter().
        fc = self._build_filter_config(base=getattr(self, "_adv_filter_cfg", None))
        # Show the "Please Wait" blocker immediately on a profile toggle —
        # bypassing the 150 ms busy-timer threshold used by other filter ops.
        # Profile toggles are explicit user actions and the user expects
        # immediate visual feedback (same UX as the parse-time blocker).
        # busy_finished from the model will close the dialog automatically.
        self._show_hw_loading_dialog(
            heading="Please Wait — Applying Profile",
            detail="Filtering events…",
        )
        self._hw_model.apply_filter(fc)
        # Mirror to per-file JM tabs so they stay in sync with the live filter.
        for _fp, _st in self._file_tabs.items():
            if _fp.startswith("__chain__"):
                continue
            try:
                _st.model.apply_filter(fc)
            except Exception:
                pass
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
        # Collect the events visible through ALL active filters (advanced, text,
        # session, quick) while temporarily suspending the current column's own
        # quick filter so the popup still shows all of that column's values.
        # This is strictly more correct than the old cascade_filters approach,
        # which only considered quick filters and missed advanced/text/session.
        from evtx_tool.gui.jm_col_worker import NormalColValueWorker
        visible_events = self._active_proxy.collect_source_events_for_popup(col_key)
        if not visible_events:
            return
        worker = NormalColValueWorker(visible_events, col_key, parent=self)
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

    def _build_col_cascade_where(self, col_key: str):
        """Build the (where_sql, where_params) that scopes a JM column popup to
        the current view: active file tab + cascading quick filters (excluding
        this column) + advanced/session base filter.

        Shared by the initial popup worker and the full-dataset search worker so
        both count values against exactly the same visible slice.
        """
        from evtx_tool.gui.jm_col_worker import build_cascade_where
        from evtx_tool.gui.heavyweight_model import ArrowTableModel as _ATM
        # If a per-file tab is active, scope GROUP BY to that file only.
        active_fp = getattr(self, "_active_file_tab", None)
        file_state = self._file_tabs.get(active_fp) if active_fp else None
        if file_state and active_fp:
            where_sql, where_params = "source_file = ?", [active_fp]
        else:
            where_sql, where_params = None, None
        _am      = self._active_table.model()
        _jm_src  = _am if isinstance(_am, _ATM) else self._hw_model
        cascade_sql, cascade_params = build_cascade_where(
            col_key, _jm_src.get_quick_filters()
        )
        if cascade_sql and where_sql:
            where_sql    = f"({where_sql}) AND ({cascade_sql})"
            where_params = list(where_params or []) + cascade_params
        elif cascade_sql:
            where_sql, where_params = cascade_sql, cascade_params
        # Also fold in the advanced-filter and session-filter WHERE so the
        # popup counts reflect the full active view, not just quick filters.
        base_sql, base_params = _jm_src.get_cascade_base_where()
        if base_sql:
            where_sql    = f"({where_sql}) AND ({base_sql})" if where_sql else base_sql
            where_params = list(where_params or []) + base_params
        return where_sql, where_params

    def _track_col_worker(self, worker) -> None:
        """Keep a reference so the worker isn't GC'd before it finishes,
        pruning already-finished workers to prevent unbounded accumulation."""
        if not hasattr(self, "_col_value_workers"):
            self._col_value_workers = []
        self._col_value_workers = [w for w in self._col_value_workers if w.isRunning()]
        self._col_value_workers.append(worker)

    def _make_col_search_provider(self, col_key: str):
        """Return a ``search_provider(term, callback)`` for the popup that queries
        the FULL dataset for values matching *term*, scoped to the current view.

        JM mode reuses ``ColValueWorker`` (DuckDB LIKE over the Arrow table);
        normal mode reuses ``NormalColValueWorker`` over the popup's visible
        events.  Both cap at the top-1000 *matching* values, so a rare value
        outside the default top-1000 becomes reachable via search.
        """
        def provider(term: str, callback) -> None:
            try:
                if self._hw_model is not None:
                    from evtx_tool.gui.jm_col_worker import ColValueWorker
                    where_sql, where_params = self._build_col_cascade_where(col_key)
                    worker = ColValueWorker(
                        self._hw_model._full_table, col_key,
                        where_sql=where_sql, where_params=where_params,
                        search_term=term, parent=self,
                    )
                else:
                    from evtx_tool.gui.jm_col_worker import NormalColValueWorker
                    visible_events = self._active_proxy.collect_source_events_for_popup(col_key)
                    if not visible_events:
                        return
                    worker = NormalColValueWorker(
                        visible_events, col_key, search_term=term, parent=self,
                    )
                worker.finished.connect(lambda vals: callback(vals))
                worker.start()
                self._track_col_worker(worker)
            except Exception:
                logger.exception("column-filter search provider failed (col=%s)", col_key)
        return provider

    def _start_col_value_worker(self, logical_index: int, col_key: str) -> None:
        """Start async ColValueWorker for Juggernaut Mode column filter popup."""
        from evtx_tool.gui.jm_col_worker import ColValueWorker
        if self._hw_model is None:
            return
        where_sql, where_params = self._build_col_cascade_where(col_key)

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
        self._track_col_worker(worker)

    def _show_col_filter_popup(self, logical_index: int, values: dict) -> None:
        """Create and show the column filter popup with the given value counts."""
        if not values:
            return

        # Position popup below the header section
        hdr = self._active_table.horizontalHeader()
        section_x = hdr.sectionPosition(logical_index) - hdr.offset()
        global_pos = hdr.mapToGlobal(QPoint(section_x, hdr.height()))

        # Give the popup a full-dataset search hook so typing in its search box
        # can surface values outside the initial top-1000 (e.g. a rare
        # correlation_id) and let the user select them.
        _popup_col_key0 = ColumnFilterPopup.FILTERABLE.get(logical_index, "")
        _search_provider = (
            self._make_col_search_provider(_popup_col_key0)
            if _popup_col_key0 else None
        )
        popup = ColumnFilterPopup(
            logical_index, values, parent=self, search_provider=_search_provider
        )

        # Bug 7 fix: derive pre-uncheck state from the active tab's actual quick filters
        # rather than the global _col_filters (which is shared across tabs).
        #
        # Both filter modes need to be reflected back into the popup's checkbox
        # state so the user sees what's already filtering:
        #   • EXCLUDE filters → uncheck those specific values
        #   • INCLUDE filters → uncheck EVERYTHING except those values
        # The previous code only handled the exclude case, leaving include-mode
        # filters silently invisible after a re-open of the popup.
        _popup_col_key = ColumnFilterPopup.FILTERABLE.get(logical_index, "")
        if _popup_col_key:
            if self._hw_model is not None:
                from evtx_tool.gui.heavyweight_model import ArrowTableModel as _ATM
                _am = self._active_table.model()
                _qf_src = _am if isinstance(_am, _ATM) else self._hw_model
                _active_qf = _qf_src.get_quick_filters()
            else:
                _active_qf = self._active_proxy.get_quick_filters()

            _col_qfs = [qf for qf in _active_qf if qf.get("key") == _popup_col_key]
            _excluded_vals = {
                qf["value"] for qf in _col_qfs if not qf.get("include", True)
            }
            _included_vals = {
                qf["value"] for qf in _col_qfs if qf.get("include", True)
            }

            if _included_vals:
                # Include-mode: only checked values are the included ones.
                for chk in popup._checkboxes:
                    val = chk.property("filter_value")
                    chk.setChecked(val in _included_vals)
            elif _excluded_vals:
                # Exclude-mode: uncheck the excluded values, leave others checked.
                for chk in popup._checkboxes:
                    if chk.property("filter_value") in _excluded_vals:
                        chk.setChecked(False)

        popup.filterApplied.connect(self._on_col_filter_applied)
        popup.sortRequested.connect(
            lambda col, order, tbl=self._active_table:
                self._on_sort_by_column(col, tbl, force_order=order)
        )
        # ── Screen-edge clamping ──────────────────────────────────────────────
        # For the rightmost columns the popup extends off the right edge of the
        # screen.  Force Qt to compute the popup's real size first, then shift
        # its x so the right edge stays within the available screen area.
        # Also guard against clipping off the bottom (e.g. table near taskbar).
        popup.adjustSize()
        p = QPoint(global_pos)
        screen = QApplication.screenAt(p) or QApplication.primaryScreen()
        if screen is not None:
            avail = screen.availableGeometry()
            pw    = popup.width()
            ph    = popup.height()
            # Right-edge clip: align popup's right edge to column's right edge
            if p.x() + pw > avail.right() + 1:
                sect_right = (hdr.sectionPosition(logical_index)
                              + hdr.sectionSize(logical_index)
                              - hdr.offset())
                global_right = hdr.mapToGlobal(QPoint(sect_right, 0)).x()
                p.setX(max(avail.left(), global_right - pw))
            # Bottom-edge clip: flip popup above the header row
            if p.y() + ph > avail.bottom() + 1:
                p.setY(max(avail.top(), global_pos.y() - hdr.height() - ph))
        popup.move(p)
        popup.show()

    def _on_col_filter_applied(self, col_index: int, mode: str, values: list) -> None:
        """Apply column filter selections by setting Quick Filters.

        *mode* is "include", "exclude", or "clear" — see ColumnFilterPopup.
        Picking the right mode at the popup means events with values outside
        the popup's top-1000 cap are handled correctly (see bug RCA in
        ColumnFilterPopup._apply).
        """
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

        # Commit column filter state now that we know we're applying.
        # "clear" with non-empty values is a programmer error from the popup,
        # but we treat it the same as clear for robustness.
        if mode == "clear" or (mode == "exclude" and not values):
            # No filtering needed on this column
            self._col_filters.pop(col_index, None)
        else:
            self._col_filters[col_index] = (mode, list(values))

        # Build the full quick-filter list from all current column filters.
        # Each column contributes 0..N quick-filter entries, all sharing
        # the column's mode (include or exclude).
        #
        # Note: the popup never emits ("include", []) — the "everything
        # unchecked" case is emitted as ("exclude", all_visible_values) so we
        # never need a sentinel here.  See ColumnFilterPopup._apply.
        new_qf: list[dict] = []
        for ci, (col_mode, col_values) in self._col_filters.items():
            ck = ColumnFilterPopup.FILTERABLE.get(ci, "")
            if not ck:
                continue
            include_flag = (col_mode == "include")
            for val in col_values:
                new_qf.append({"key": ck, "value": val, "include": include_flag})

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
        # resolve_col_expr handles timestamp_date dynamically (display-TZ
        # aware) so this sync fallback shows the same date format the user
        # sees in the event table.
        from evtx_tool.gui.jm_col_worker import resolve_col_expr
        expr = resolve_col_expr(col_key)
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
        # _col_filters entries are (mode, values) tuples — the column is filtered
        # iff the values list is non-empty.  An "include" with empty values is
        # technically a "match nothing" filter and still counts as active.
        def _is_active(entry) -> bool:
            if not entry:
                return False
            mode, values = entry
            return mode in ("include", "exclude")  # "clear" entries are popped above

        if self._hw_model is not None:
            # Juggernaut mode: update HW model's _header_overrides dict
            if not hasattr(self._hw_model, "_header_overrides"):
                self._hw_model._header_overrides = {}
            self._hw_model._header_overrides.clear()
            for col, entry in self._col_filters.items():
                if _is_active(entry) and col < len(COLUMNS):
                    self._hw_model._header_overrides[col] = f"▼ {COLUMNS[col]}"
            self._hw_model.headerDataChanged.emit(
                Qt.Orientation.Horizontal, 0, self._hw_model.columnCount() - 1
            )
            return
        model = self._active_model
        model._header_overrides.clear()
        for col, entry in self._col_filters.items():
            if _is_active(entry) and col < len(COLUMNS):
                model._header_overrides[col] = f"▼ {COLUMNS[col]}"
        model.headerDataChanged.emit(
            Qt.Orientation.Horizontal, 0, model.columnCount() - 1
        )


    # =========================================================================
    # BUILD FILTER
    # =========================================================================

    def _build_filter_config(self, base: dict | None = None) -> dict:
        """Build a filter config, optionally stacking on top of a *base* cfg.

        With ``base=None`` (the default) this returns just the profile-derived
        config — used at parse time, when nothing else is active yet.

        With ``base=<dialog cfg>`` it stacks the active profiles ON TOP of
        the dialog cfg.  This is what JM-mode live filtering must use so that
        applying the Advanced Filter does not silently wipe an active profile
        selection (and vice-versa).
        """
        from evtx_tool.core.filters import empty_filter
        fc = dict(base) if base else empty_filter()

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

        # ── Parse-integrity check (normal mode) — same standard as Juggernaut ─
        # engine.state.warnings carries per-file "N record(s) could not be
        # parsed" messages; unparsed evidence must be visible to the examiner.
        try:
            _pw = [w for w in getattr(self._worker, "parse_warnings", [])
                   if ("could not be parsed" in w or "ABORTED" in w
                       or "TRUNCATED" in w)]
            if _pw:
                QMessageBox.warning(
                    self, "Parse Integrity Warning",
                    "Some evidence did NOT fully load — results may be "
                    "incomplete:\n\n"
                    + "\n".join(_pw[:15])
                    + ("\n…" if len(_pw) > 15 else ""),
                )
        except Exception:
            logger.warning("Parse-integrity warning check failed", exc_info=True)

        self._events         = events
        self._close_logon_sessions_dlg()   # close + invalidate session browser cache
        self._close_ra_dlg(clear_filter=True)  # M1: close + clear RA filter + kill worker
        self._close_computer_norm_dlg()    # invalidate cached aggregation
        self._attack_summary = attack_summary
        self._iocs           = None
        self._chains         = []
        self._metadata       = {}

        # Clear stale filter state
        self._active_tactic_filter = None
        self._active_technique_filter = None
        self._tactic_filter_widget.setVisible(False)
        self._col_filters.clear()
        # Clear session LogonId filter so an old filter from a previous load
        # does not silently carry into the new dataset and suppress results.
        self._set_session_filter(None, None)

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
        # In Juggernaut Mode the analysis subprocess runs with events=[] so
        # build_metadata() returns all-empty dicts.  _load_jm_metadata() has
        # already populated self._metadata from DuckDB — don't overwrite it.
        if self._hw_model is None:
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
        logger.error("Analysis worker failed:\n%s", msg)
        err_dlg = QMessageBox(self)
        err_dlg.setWindowTitle("Analysis Failed")
        err_dlg.setIcon(QMessageBox.Icon.Warning)
        err_dlg.setText(
            "An analysis step failed (IOC extraction / Correlation / Metadata).\n\n"
            "Event table is still populated — parse results are unaffected."
        )
        err_dlg.setDetailedText(msg)
        err_dlg.exec()


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
        # In Juggernaut Mode, guarantee metadata is populated before opening
        # the dialog.  The background thread loader (_load_jm_metadata) may
        # not have completed yet, or may have silently failed.  This fallback
        # queries the Arrow table synchronously — typically < 200ms.
        if self._hw_model is not None and not self._metadata.get("source"):
            self._metadata = self._query_jm_metadata_sync()

        dlg = FilterDialog(
            metadata=self._metadata,
            current_filter=self._adv_filter_cfg,
            parent=self,
            juggernaut_mode=(self._hw_model is not None),
        )
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        cfg = dlg.get_filter_config()

        # ── Stack the dialog cfg ON TOP of any active profile selection ──
        # Both the profile filter and the dialog filter are applied via the same
        # slot (apply_filter in JM, set_advanced_filter in normal).  Stacking
        # them means opening the Advanced Filter never wipes a live-applied
        # profile (and vice-versa) — in EITHER mode, now that profiles are
        # applied live (see _on_apply_profiles_clicked).  ``_adv_filter_cfg``
        # still stores only the raw dialog cfg so a later profile Apply can
        # re-stack cleanly.
        cfg_effective = self._build_filter_config(base=cfg)

        # In separate-tabs mode ask which files to target before committing cfg
        if self._view_mode == "separate":
            target_tabs = self._filter_target_tabs()
            if target_tabs:
                scope_dlg = _FilterTargetDialog(target_tabs, self)
                if scope_dlg.exec() != QDialog.DialogCode.Accepted:
                    return  # cancelled — _adv_filter_cfg stays unchanged
                # Store the raw dialog cfg (not the merged one) so subsequent
                # profile toggles can re-build the combined filter cleanly.
                self._adv_filter_cfg = cfg
                is_jm = self._hw_model is not None
                for fp in scope_dlg.selected():
                    if fp == "__all_events__":
                        if is_jm:
                            self._hw_model.apply_filter(cfg_effective)
                        else:
                            self._proxy_model.set_advanced_filter(cfg_effective)
                        continue
                    state = self._file_tabs.get(fp)
                    if state is None:
                        continue
                    if is_jm:
                        state.model.apply_filter(cfg_effective)
                    else:
                        state.proxy.set_advanced_filter(cfg_effective)
                self._update_adv_filter_badge()
                self._update_count_label()
                return

        # Merged mode (or no file tabs yet) — apply to active model as before
        self._adv_filter_cfg = cfg
        if self._hw_model is not None:
            self._hw_model.apply_filter(cfg_effective)
            self._update_adv_filter_badge()
            self._update_count_label()
            return
        self._active_proxy.set_advanced_filter(cfg_effective)
        self._update_adv_filter_badge()
        self._update_count_label()

    def _clear_advanced_filter(self) -> None:
        """Remove the advanced filter and hide the badge.

        In Juggernaut Mode the profile filter and the Advanced Filter share the
        same ``apply_filter`` slot.  Calling ``clear_filter()`` blindly would
        also wipe an active profile selection.  Instead, re-build the filter
        from the active profile state alone (with ``base=None`` so the dialog
        cfg is gone) so the profile filter survives the clear.
        """
        self._adv_filter_cfg = None
        # Bug 3 fix: in Juggernaut Mode clear via hw_model — but keep profiles.
        if self._hw_model is not None:
            # Rebuild filter from profiles only (no dialog cfg).
            # _build_filter_config with base=None == profile-only cfg.
            # When no profiles are checked this returns empty_filter(), which
            # apply_filter() treats as "no filter".
            profile_only_fc = self._build_filter_config(base=None)
            checked = self._get_checked_profiles()
            if checked:
                self._hw_model.apply_filter(profile_only_fc)
                for _fp, _st in self._file_tabs.items():
                    if not _fp.startswith("__chain__"):
                        try:
                            _st.model.apply_filter(profile_only_fc)
                        except Exception:
                            pass
            else:
                # No profile active either — same as a full clear.
                self._hw_model.clear_filter()
                for _fp, _st in self._file_tabs.items():
                    if not _fp.startswith("__chain__"):
                        _st.model.clear_filter()
            self._update_adv_filter_badge()
            self._update_count_label()
            return
        self._active_proxy.clear_advanced_filter()
        # Also clear per-file tab proxies (separate-tabs mode)
        for _st in self._file_tabs.values():
            _st.proxy.clear_advanced_filter()
        self._update_adv_filter_badge()
        self._update_count_label()

    def _clear_all_filters(self) -> None:
        """Reset every active filter layer and return to the full unfiltered view.

        Covers: text search bar, advanced filter, quick column filters,
        session LogonId filter, ATT&CK tactic filter, bookmark/IOC pivot
        (record-ID filter).  Safe to call even when no filters are active.

        **Profile selection is NOT cleared** — the profile combo's checkboxes
        stay as they were and the profile-derived filter is re-applied at
        the end so the user's "what kind of events am I investigating"
        choice survives a Clear All.  Without this, JM mode would visibly
        wipe the profile filter even though the checkboxes still showed
        checked (the underlying model state was reset, leaving the UI and
        the live filter inconsistent).
        """
        # RA session filters are implemented on top of the bookmark/record-id
        # filter layer.  Clear the ownership flag up front so a later dataset
        # change cannot accidentally re-clear a different bookmark filter.
        self._ra_filter_active = False

        # 1. Advanced filter
        self._adv_filter_cfg = None

        # 2. Record-ID filter (IOC pivot, missing-record-ID) + bookmark filter
        #    + quick filters + text search — batch ALL resets then _invalidate() once.
        if self._hw_model is not None:
            self._hw_model._base_where_sql       = "1=1"
            self._hw_model._base_params          = []
            self._hw_model._has_advanced_filter  = False
            self._hw_model._conditions_cfg       = {}
            self._hw_model._text_search_cfg      = {}
            self._hw_model._text_where_sql       = ""
            self._hw_model._text_params          = []
            self._hw_model._record_id_where_sql  = ""
            self._hw_model._record_id_params     = []
            # Quick filters — clear in the same batch to avoid double _invalidate()
            self._hw_model._quick_filters.clear()
            self._hw_model._quick_where_sql = ""
            self._hw_model._quick_params    = []
            # Single dispatch for all resets
            self._hw_model._invalidate()
            # Also clear record-id/bookmark filters on open per-file JM tab models.
            for _fm in getattr(self, "_jm_file_models", []):
                _fm.clear_record_id_filter()
            self._active_jm_session_keys = frozenset()
            # Also clear filters on any open per-file JM tab models.
            # Use clear_all_filters() to reset everything in one _invalidate()
            # call instead of calling clear_filter() + clear_quick_filters()
            # separately (which would dispatch two redundant round-trips each).
            for _fp, _st in self._file_tabs.items():
                if not _fp.startswith("__chain__"):
                    _st.model.clear_all_filters()

            # ── Re-apply the profile-only filter ─────────────────────────────
            # We just wiped self._hw_model's filter state.  If the user has
            # any profile checked, restore that filter so the profile combo
            # selection stays consistent with the live data view.  When no
            # profile is checked, _build_filter_config(base=None) returns
            # empty_filter() which apply_filter() treats as "no filter" — so
            # the model stays unfiltered, matching what the user sees.
            try:
                if self._get_checked_profiles():
                    _profile_fc = self._build_filter_config(base=None)
                    self._hw_model.apply_filter(_profile_fc)
                    for _fp, _st in self._file_tabs.items():
                        if _fp.startswith("__chain__"):
                            continue
                        try:
                            _st.model.apply_filter(_profile_fc)
                        except Exception:
                            pass
            except Exception:
                pass
        else:
            # Batch: clear all filter layers in one invalidateFilter() call.
            self._active_proxy.clear_all_filters()
            # Also clear per-file tab proxies in one pass each.
            for state in self._file_tabs.values():
                state.proxy.clear_all_filters()
            # Normal mode: profile is applied at PARSE TIME (events are pre-
            # filtered before they reach the proxy), so the proxy needs no
            # restore step — clearing proxy filters returns to the pre-
            # filtered event set the user originally loaded.

        # 5. Session filter — JM: cleared above (step 3 resets _hw_model + per-file models
        #    + _active_jm_session_keys).  Normal mode: cleared by clear_all_filters() above.

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
        # Sync the open session browser's internal badge if it is still showing.
        _dlg = getattr(self, "_logon_sessions_dlg", None)
        if _dlg is not None:
            try:
                _dlg.notify_filter_cleared()
            except RuntimeError:
                pass

    def _update_adv_filter_badge(self) -> None:
        """Show/hide the 'Filter Active' badge and surface inverted/exclude modes.

        The badge represents the **Advanced Filter dialog** state, not any
        active *profile* filter.  In JM mode profiles and the Advanced Filter
        share ``ArrowTableModel.has_filter()`` — using that directly would
        keep the badge (and its X clear button) visible after the user clears
        the Advanced Filter, making the X look broken when only a profile is
        actually filtering.  Read ``_adv_filter_cfg`` directly instead so the
        badge tracks the dialog cfg exclusively.

        When any *exclude* checkbox in the FilterDialog is on, the corresponding
        clause is wrapped in ``NOT (...)`` at SQL level (or inverted at Python
        level in normal mode).  If the inverted criterion matches *no* rows
        (e.g. searching ``Exclude: 1=1`` where no event contains "1=1"), the
        result is the entire dataset — which is visually indistinguishable from
        "no filter applied".

        Fix: when any exclude mode is active, the badge text and tooltip
        explicitly name the inverted layers so the user can never confuse
        "filter not applied" with "filter is inverted on a no-match term".
        """
        # Use _adv_filter_cfg (dialog state) as the source of truth — NOT
        # hw_model.has_filter(), which is also True for profile-only filters
        # in JM mode.
        active = getattr(self, "_adv_filter_cfg", None) is not None
        # In normal mode also honour the proxy's view in case some other path
        # set an advanced filter without going through _adv_filter_cfg.
        if not active and self._hw_model is None:
            try:
                active = self._active_proxy.has_advanced_filter()
            except Exception:
                pass
        self._lbl_adv_filter_badge.setVisible(active)
        self._btn_clear_adv.setVisible(active)

        if not active:
            # Reset to the default appearance — important when the user clears
            # an inverted filter and applies a non-inverted one in sequence.
            self._lbl_adv_filter_badge.setText("⚡ Filter Active")
            self._lbl_adv_filter_badge.setToolTip("")
            return

        # Identify every active exclude/inverted mode from the stored cfg.
        # Use the last-applied cfg (works for both merged and separate modes —
        # in separate mode the per-file proxies all share the same cfg shape).
        cfg = getattr(self, "_adv_filter_cfg", None) or {}
        excludes: list[str] = []
        # Map cfg key → human-readable label.  Only listed when the
        # corresponding *filter clause is actually applied* — an unused
        # exclude checkbox combined with an empty value field carries no
        # behavioural risk and would just produce a false positive.
        _EXCLUDE_LAYERS = [
            # Simple list/string layers — gated on the value field having content
            ("event_id_exclude",  "event_id_expr",  "Event ID(s)"),
            ("text_exclude",      "text_search",    "Text in description"),
            ("source_exclude",    "sources",        "Source"),
            ("category_exclude",  "categories",     "Category"),
            ("user_exclude",      "users",          "User"),
            ("computer_exclude",  "computers",      "Computer"),
        ]
        for excl_key, value_key, label in _EXCLUDE_LAYERS:
            if not cfg.get(excl_key):
                continue
            val = cfg.get(value_key)
            if val:  # non-empty string or non-empty list
                excludes.append(label)

        # Date / time exclude — only surface when the date filter is actually
        # applied (filter_sql.py line 246 gates the date clause on date_from
        # or date_to being non-empty; without either, date_exclude is dead).
        if cfg.get("date_exclude") and (cfg.get("date_from") or cfg.get("date_to")):
            excludes.append("Date / Time")

        # Relative time exclude — only surface when the relative filter is
        # actually applied (filter_sql.py line 379 gates on days OR hours > 0).
        _rel_days  = cfg.get("relative_days", 0)  or 0
        _rel_hours = cfg.get("relative_hours", 0) or 0
        try:
            _rel_active = (int(_rel_days) > 0 or int(_rel_hours) > 0)
        except (TypeError, ValueError):
            _rel_active = False
        if cfg.get("relative_exclude") and _rel_active:
            excludes.append("Relative time")

        if excludes:
            self._lbl_adv_filter_badge.setText(
                f"⚡ Filter Active  ⚠ Exclude×{len(excludes)}"
            )
            tip_lines = ["Filter is INVERTED on the following layer(s):"]
            tip_lines.extend(f"  • {label}" for label in excludes)
            tip_lines.append("")
            tip_lines.append(
                "Exclude inverts the match: rows that DO match the criterion "
                "are HIDDEN, and rows that do NOT match are shown.  If the "
                "search term doesn't appear in any event, exclude shows ALL "
                "rows — which can look identical to 'no filter applied'."
            )
            self._lbl_adv_filter_badge.setToolTip("\n".join(tip_lines))
        else:
            self._lbl_adv_filter_badge.setText("⚡ Filter Active")
            self._lbl_adv_filter_badge.setToolTip("")

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
            0:  None,                  # Row # — can't filter
            1:  'event_id',
            2:  'level_name',
            3:  'timestamp_date',  # date-only quick filter (YYYY-MM-DD)
            4:  'computer',
            5:  'channel',
            6:  'user_id',
            7:  None,                  # ATT&CK — handled separately
            8:  'source_file',
            # ── Extended columns ──────────────────────────────────────────
            9:  'keywords',
            10: 'opcode',
            11: 'log',
            12: 'process_id',
            13: 'thread_id',
            14: 'processor_id',
            15: 'session_id',
            19: 'correlation_id',
            20: 'record_id',
            21: 'provider',
        }
        col_key = col_key_map.get(col)
        cell_val = index.data() or ""

        # Timestamp quick filter uses date portion only (YYYY-MM-DD) so the
        # popup groups by day and the filter is easy to read / match.
        if col_key == "timestamp_date":
            cell_val = cell_val[:10]

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

    def _close_logon_sessions_dlg(self) -> None:
        """Close an open session browser dialog and clear the cached reference.

        Closing (not just nulling the pointer) prevents a stale dialog from
        applying old session filters against a new or different dataset.
        """
        dlg = getattr(self, "_logon_sessions_dlg", None)
        if dlg is not None:
            try:
                dlg.close()
            except RuntimeError:
                pass  # underlying C++ object already destroyed
        self._logon_sessions_dlg = None

    def _clear_ra_filter_if_active(self) -> None:
        """M1: Remove the RA session bookmark filter from all proxy/model layers.

        Only acts when _ra_filter_active is True — avoids clobbering unrelated
        filters (user bookmarks, logon-session filter) that happen to use the
        same underlying set_bookmark_filter() mechanism.
        """
        if not getattr(self, "_ra_filter_active", False):
            return
        if self._hw_model is not None:
            self._hw_model.clear_record_id_filter()
            for _fm in getattr(self, "_jm_file_models", []):
                _fm.clear_record_id_filter()
            self._active_jm_session_keys = frozenset()
        else:
            self._proxy_model.clear_bookmark_filter()
            for _state in self._file_tabs.values():
                _state.proxy.clear_bookmark_filter()
        self._ra_filter_active = False
        self._update_count_label()

    def _close_ra_dlg(self, clear_filter: bool = False) -> None:
        """Close any open Remote Assistance dialog and invalidate in-flight workers.

        Bumping ``_ra_jm_req_id`` ensures that a long-running JM fetch started
        against the *previous* dataset cannot open a stale dialog after the
        dataset has been replaced (parse, clear, tab-change, or JM teardown).

        M1: pass ``clear_filter=True`` at dataset-change call sites (parse /
        clear) so any active RA session filter is removed and does not persist
        into the new dataset.  Tab-change calls keep the default (False) because
        the underlying data did not change.
        """
        dlg = getattr(self, "_ra_dlg", None)
        if dlg is not None:
            try:
                dlg.close()
            except RuntimeError:
                pass
        self._ra_dlg = None
        # Invalidate any in-flight fetch worker — the closure checks this token.
        self._ra_jm_req_id = getattr(self, "_ra_jm_req_id", 0) + 1
        if clear_filter:
            self._clear_ra_filter_if_active()

    def _on_show_logon_sessions(self) -> None:
        """Open the Logon Session Browser dialog (non-modal)."""
        if self._hw_model is not None:
            self._on_show_logon_sessions_jm()
            return
        events = self._active_events
        if not events:
            QMessageBox.information(self, "Logon Sessions", "No events loaded.")
            return
        # Reuse the existing dialog if it is still alive — avoids rebuilding
        # sessions (O(n) scan) every time the user reopens the browser.
        # The cache is invalidated whenever new events are loaded or cleared.
        existing = getattr(self, "_logon_sessions_dlg", None)
        if existing is not None:
            try:
                existing.show()
                existing.raise_()
                existing.activateWindow()
                return
            except RuntimeError:
                pass  # underlying C++ object was destroyed
        dlg = _LogonSessionDialog(
            events=events,
            on_filter_fn=self._set_session_filter,
            parent=self,
        )
        self._logon_sessions_dlg = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _on_show_wifi_history(self) -> None:
        """Open the WiFi History Browser dialog (non-modal).

        High-1 fix: the dialog is NEVER reused across calls — always close any
        existing instance and build a fresh one so stale sessions are impossible
        after a re-parse, file clear, or tab-context change.
        """
        # Always invalidate the previous dialog (don't serve stale sessions).
        existing = getattr(self, "_wifi_history_dlg", None)
        if existing is not None:
            try:
                existing.close()
            except RuntimeError:
                pass
            self._wifi_history_dlg = None

        if self._hw_model is not None:
            # JM mode: run DuckDB parquet_scan on a background thread so the
            # UI never freezes on large shard sets (Medium-4 fix).
            parquet_dir = getattr(self, "_hw_db_path", None)
            if not parquet_dir:
                QMessageBox.information(self, "WiFi History",
                                        "No Juggernaut dataset loaded.")
                return
            self._set_status("Fetching WiFi events…")
            # Medium fix: monotonic request token.  If the user triggers multiple
            # quick fetches, results from older workers are silently dropped so
            # they cannot open a stale dialog after a newer request has finished.
            self._wifi_jm_req_id = getattr(self, "_wifi_jm_req_id", 0) + 1
            _req = self._wifi_jm_req_id

            worker = _WifiJMFetchWorker(parquet_dir, parent=self)

            def _on_ready(events, truncated, _r=_req):
                if getattr(self, "_wifi_jm_req_id", None) != _r:
                    return   # stale — a newer request already owns the slot
                self._on_wifi_jm_events_ready(events, truncated)

            def _on_err(kind, msg, _r=_req):
                if getattr(self, "_wifi_jm_req_id", None) != _r:
                    return
                self._on_wifi_jm_fetch_error(kind, msg)

            worker.finished.connect(_on_ready)
            worker.fetch_error.connect(_on_err)
            worker.start()
            # Keep a reference so the worker is not GC'd before it finishes.
            if not hasattr(self, "_wifi_jm_workers"):
                self._wifi_jm_workers = []
            self._wifi_jm_workers = [w for w in self._wifi_jm_workers
                                     if w.isRunning()]
            self._wifi_jm_workers.append(worker)
            return

        # Normal mode — events are already in memory, no cap applied.
        events = self._active_events
        if not events:
            QMessageBox.information(self, "WiFi History", "No events loaded.")
            return
        self._open_wifi_history_dialog(events, truncated=False)

    def _on_wifi_jm_events_ready(self, events: list, truncated: bool) -> None:
        """Called (via closure) when _WifiJMFetchWorker finishes for the current request."""
        self._set_status("")
        if not events:
            QMessageBox.information(self, "WiFi History",
                                    "No WLAN-AutoConfig events found in the dataset.")
            return
        # Medium fix: warn only when the worker confirmed truncation (fetched > 200 000
        # rows), not merely when the result count equals the cap exactly.
        if truncated:
            QMessageBox.warning(
                self, "WiFi History — Results Truncated",
                "The dataset contains more than 200,000 WLAN-AutoConfig events.\n"
                "Results are limited to the first 200,000 (chronological order).\n"
                "Some sessions near the end of the time range may be missing.",
            )
        self._open_wifi_history_dialog(events, truncated=truncated)

    def _on_wifi_jm_fetch_error(self, kind: str, msg: str) -> None:
        """Called (via closure) when _WifiJMFetchWorker encounters a classified error.

        *kind* is a machine-readable tag emitted by the worker:
          ``manifest_missing``    — parquet_manifest.json not found
          ``manifest_read_error`` — I/O error reading the manifest
          ``manifest_parse_error``— manifest is not valid JSON
          ``duckdb_query_error``  — DuckDB parquet_scan / execute failure
        """
        self._set_status("")
        _TITLES = {
            "manifest_missing":     "Parquet Manifest Not Found",
            "manifest_read_error":  "Cannot Read Parquet Manifest",
            "manifest_parse_error": "Parquet Manifest Corrupt",
            "duckdb_query_error":   "WiFi History Query Failed",
        }
        title = _TITLES.get(kind, "WiFi History Error")
        QMessageBox.warning(self, title, msg)

    def _open_wifi_history_dialog(self, events: list, truncated: bool = False) -> None:
        """Create and show a fresh _WifiHistoryDialog from *events*.

        *truncated* is forwarded into the dialog so the summary bar and CSV
        export can carry provenance even after the one-shot warning is dismissed.
        """
        dlg = _WifiHistoryDialog(events=events, truncated=truncated, parent=self)
        self._wifi_history_dlg = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    # ── Remote Assistance session browser ─────────────────────────────────────

    def _on_show_remote_assist(self) -> None:
        """Open the Remote Assistance Session Browser dialog (non-modal).

        Always discards any previous dialog instance so the session list is
        rebuilt fresh — prevents serving stale data after a re-parse or file
        change.  Mirrors the pattern used by _on_show_wifi_history.
        """
        existing = getattr(self, "_ra_dlg", None)
        if existing is not None:
            try:
                existing.close()
            except RuntimeError:
                pass
            self._ra_dlg = None

        if self._hw_model is not None:
            # Juggernaut mode: query Parquet shards on a background thread.
            parquet_dir = getattr(self, "_hw_db_path", None)
            if not parquet_dir:
                QMessageBox.information(
                    self, "Remote Assistance", "No Juggernaut dataset loaded."
                )
                return
            self._set_status("Fetching Remote Assistance events…")
            # Monotonic request token — stale results from aborted requests are
            # silently dropped so they cannot open a dialog after a newer fetch.
            self._ra_jm_req_id = getattr(self, "_ra_jm_req_id", 0) + 1
            _req = self._ra_jm_req_id

            worker = _RemoteAssistJMFetchWorker(parquet_dir, parent=self)

            def _on_ready(events, truncated, _r=_req):
                if getattr(self, "_ra_jm_req_id", None) != _r:
                    return   # stale — newer request already owns the slot
                self._on_remote_assist_jm_ready(events, truncated)

            def _on_err(kind, msg, _r=_req):
                if getattr(self, "_ra_jm_req_id", None) != _r:
                    return
                self._on_remote_assist_jm_error(kind, msg)

            worker.finished.connect(_on_ready)
            worker.fetch_error.connect(_on_err)
            worker.start()
            # Keep a strong reference so the worker is not GC'd before it finishes.
            if not hasattr(self, "_ra_jm_workers"):
                self._ra_jm_workers = []
            self._ra_jm_workers = [w for w in self._ra_jm_workers if w.isRunning()]
            self._ra_jm_workers.append(worker)
            return

        # Normal mode — events are already in memory.
        events = self._active_events
        if not events:
            QMessageBox.information(self, "Remote Assistance", "No events loaded.")
            return
        self._open_remote_assist_dialog(events, truncated=False)

    def _on_remote_assist_jm_ready(self, events: list, truncated: bool) -> None:
        """Called (via closure) when _RemoteAssistJMFetchWorker succeeds."""
        self._set_status("")
        if not events:
            QMessageBox.information(
                self, "Remote Assistance",
                "No Remote Assistance / RDP / Quick Assist events found in the dataset.\n\n"
                "Channels checked:\n"
                "  • Microsoft-Windows-RemoteAssistance/Operational\n"
                "  • Microsoft-Windows-RemoteHelp/Operational\n"
                "  • Microsoft-Windows-TerminalServices-LocalSessionManager/Operational\n"
                "  • Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational\n"
                "  • Security (EIDs 4624/4634/4688/4778/4779)",
            )
            return
        if truncated:
            QMessageBox.warning(
                self, "Remote Assistance — Results Truncated",
                "The dataset contains more than 200,000 relevant events.\n"
                "Results are limited to the first 200,000 (chronological order).\n"
                "Some sessions near the end of the time range may be missing.",
            )
        self._open_remote_assist_dialog(events, truncated=truncated)

    def _on_remote_assist_jm_error(self, kind: str, msg: str) -> None:
        """Show a targeted error dialog based on the classified error kind."""
        self._set_status("")
        _TITLES = {
            "manifest_missing":     "Parquet Manifest Not Found",
            "manifest_read_error":  "Cannot Read Parquet Manifest",
            "manifest_parse_error": "Parquet Manifest Corrupt",
            "duckdb_query_error":   "Remote Assistance Query Failed",
        }
        title = _TITLES.get(kind, "Remote Assistance Error")
        QMessageBox.warning(self, title, msg)

    def _open_remote_assist_dialog(
        self, events: list, truncated: bool = False
    ) -> None:
        """Instantiate and show a fresh _RemoteAssistanceDialog from *events*."""
        dlg = _RemoteAssistanceDialog(
            events=events,
            on_filter_fn=self._set_ra_session_filter,
            truncated=truncated,
            parent=self,
        )
        self._ra_dlg = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _set_ra_session_filter(
        self, related_keys: frozenset, session_info: dict
    ) -> None:
        """Apply a bookmark filter for the chosen Remote Assistance session.

        Works identically to _filter_to_bookmarks but targets the RA session's
        composite (source_file, record_id) key set rather than user bookmarks.

        Normal mode:  proxy.set_bookmark_filter(related_keys)
        JM mode:      hw_model.apply_bookmark_filter(related_keys) + all file models

        M1: sets _ra_filter_active = True so _close_ra_dlg(clear_filter=True)
        can clean up the filter on dataset change without touching unrelated filters.
        """
        if not related_keys:
            self._set_status("No events associated with this Remote Assistance session.")
            return
        if self._hw_model is not None:
            self._hw_model.apply_bookmark_filter(related_keys)
            for _fm in self._jm_file_models:
                _fm.apply_bookmark_filter(related_keys)
            # Remember active keys so tabs opened later inherit this filter.
            self._active_jm_session_keys = related_keys
        else:
            # Apply to the merged main proxy AND every file-tab proxy.
            # Use _proxy_model (not _active_proxy) as the merged-proxy target:
            # when a file tab is active, _active_proxy IS a file-tab proxy, so
            # calling it here AND in the loop below would double-invalidate that proxy.
            self._proxy_model.set_bookmark_filter(related_keys)
            for _state in self._file_tabs.values():
                _state.proxy.set_bookmark_filter(related_keys)
        self._ra_filter_active = True   # M1: track that RA applied a filter
        self._update_count_label()
        n   = len(related_keys)
        typ = session_info.get("type", "RA")
        ts  = session_info.get("start_ts", "")
        self._set_status(
            f"Filtered to {n} event{'s' if n != 1 else ''} "
            f"for {typ} session"
            + (f" starting {ts}" if ts else "")
        )

    # ── Computer Normalisation browser ─────────────────────────────────────────

    def _close_computer_norm_dlg(self) -> None:
        """Close the Computer Normalisation dialog and invalidate in-flight workers.

        Bumping ``_computer_norm_jm_req_id`` ensures that any pending JM fetch
        from the previous dataset cannot open a stale dialog after the dataset
        has been replaced (parse-complete, clear-results, tab-change).
        """
        dlg = getattr(self, "_computer_norm_dlg", None)
        if dlg is not None:
            try:
                dlg.close()
            except RuntimeError:
                pass
        self._computer_norm_dlg = None
        self._computer_norm_jm_req_id = (
            getattr(self, "_computer_norm_jm_req_id", 0) + 1
        )

    def _on_show_computer_norm(self) -> None:
        """Open the Computer Normalisation dialog (non-modal).

        Always discards any previous dialog instance so the aggregation is
        rebuilt fresh — prevents serving stale data after a re-parse.
        Normal mode: scan in-memory events.  JM mode: background DuckDB query.
        """
        existing = getattr(self, "_computer_norm_dlg", None)
        if existing is not None:
            try:
                existing.close()
            except RuntimeError:
                pass
            self._computer_norm_dlg = None

        if self._hw_model is not None:
            parquet_dir = getattr(self, "_hw_db_path", None)
            if not parquet_dir:
                QMessageBox.information(self, "Computer Normalisation",
                                        "No Juggernaut dataset loaded.")
                return
            self._set_status("Aggregating computer field…")
            self._computer_norm_jm_req_id = (
                getattr(self, "_computer_norm_jm_req_id", 0) + 1
            )
            _req = self._computer_norm_jm_req_id

            worker = _ComputerNormJMWorker(parquet_dir, parent=self)

            def _on_ready(rows, _r=_req):
                if getattr(self, "_computer_norm_jm_req_id", None) != _r:
                    return   # stale — newer request owns the slot
                self._on_computer_norm_jm_ready(rows)

            def _on_err(kind, msg, _r=_req):
                if getattr(self, "_computer_norm_jm_req_id", None) != _r:
                    return
                self._on_computer_norm_jm_error(kind, msg)

            worker.finished.connect(_on_ready)
            worker.fetch_error.connect(_on_err)
            worker.start()
            # Keep a strong reference so the worker is not GC'd mid-flight.
            self._computer_norm_jm_workers = [
                w for w in self._computer_norm_jm_workers if w.isRunning()
            ]
            self._computer_norm_jm_workers.append(worker)
            return

        # Normal mode — aggregate in-memory events.
        events = self._active_events
        if not events:
            QMessageBox.information(self, "Computer Normalisation",
                                    "No events loaded.")
            return
        rows: list[dict] = []
        agg: dict[tuple[str, str], int] = {}
        for ev in events:
            key = (str(ev.get("computer") or ""),
                   str(ev.get("source_file") or ""))
            agg[key] = agg.get(key, 0) + 1
        for (comp, sf), n in agg.items():
            rows.append({"computer": comp, "source_file": sf, "n": n})
        self._open_computer_norm_dialog(rows)

    def _on_computer_norm_jm_ready(self, rows: list) -> None:
        self._set_status("")
        if not rows:
            QMessageBox.information(self, "Computer Normalisation",
                                    "No events found in the dataset.")
            return
        self._open_computer_norm_dialog(rows)

    def _on_computer_norm_jm_error(self, kind: str, msg: str) -> None:
        self._set_status("")
        _TITLES = {
            "manifest_missing":     "Parquet Manifest Not Found",
            "manifest_read_error":  "Cannot Read Parquet Manifest",
            "manifest_parse_error": "Parquet Manifest Corrupt",
            "duckdb_query_error":   "Computer Normalisation Query Failed",
        }
        title = _TITLES.get(kind, "Computer Normalisation Error")
        QMessageBox.warning(self, title, msg)

    def _open_computer_norm_dialog(self, rows: list) -> None:
        """Instantiate and show a fresh _ComputerNormalisationDialog from *rows*."""
        dlg = _ComputerNormalisationDialog(
            rows=rows,
            on_filter_fn=self._apply_computer_norm_filter,
            parent=self,
        )
        self._computer_norm_dlg = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _apply_computer_norm_filter(self, variants: list[str]) -> None:
        """Apply an OR-of-variants quick filter on the computer column.

        Uses ``set_quick_filters([...])`` directly (rather than repeated
        ``add_quick_filter`` calls) because add_quick_filter dedupes by key
        — the same-key replacement logic would collapse all variants down
        to the last one.  ``set_quick_filters`` preserves the full list and
        ``_rebuild_quick_where`` groups them into a single ``IN (?, ?, …)``
        clause that ORs the values together.
        """
        if not variants:
            return
        filters = [{"key": "computer", "value": v, "include": True}
                   for v in variants if v]
        if not filters:
            self._set_status("Selected host has only empty Computer values; "
                             "no filter applied.")
            return
        if self._hw_model is not None:
            self._hw_model.set_quick_filters(filters)
            # Also push to per-file JM models so the per-file tab views match.
            for _st in self._file_tabs.values():
                _st.model.set_quick_filters(filters)
        else:
            self._proxy_model.set_quick_filters(filters)
            for _st in self._file_tabs.values():
                _st.proxy.set_quick_filters(filters)
        self._update_quick_filter_badge()
        self._update_count_label()
        n = len(filters)
        self._set_status(
            f"Filtered to events where Computer matches "
            f"{n} variant{'s' if n != 1 else ''}."
        )

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

        # Query only the 4 logon-related event types (fast — column-pruned Parquet scan).
        # source_file is selected so we can build composite (source_file, record_id) keys
        # that are unique across multi-file loads (record_id alone is not unique per file).
        try:
            _con = _duckdb.connect()
            _rows = _con.execute(
                f"SELECT source_file, record_id, event_id, computer, timestamp_utc, event_data_json "
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
        # Also accumulate logon_id → set[(source_file, record_id)] composite keys for
        # fast filter pre-seeding.  Composite keys prevent false matches when different
        # files happen to share the same record_id value.
        _LOGON_ID_SKIP = _LogonSessionDialog._SKIP_IDS
        events: list[dict] = []
        _lid_to_keys: dict[tuple[str, str], set] = {}   # (computer, lid) → set of (source_file, record_id)

        for src_file, rec_id, ev_id, computer, ts_utc, ed_json in _rows:
            try:
                ed = _json.loads(ed_json) if ed_json else {}
            except Exception:
                ed = {}
            events.append({
                "event_id":    ev_id,
                "computer":    computer or "",
                "timestamp":   str(ts_utc or ""),
                "event_data":  ed,
                "_record_id":  rec_id,
                "_source_file": src_file or "",
            })
            # Collect logon_id → composite key mapping
            if ev_id in (4624, 4634):
                lid = str(ed.get("TargetLogonId", "")).strip()
            else:
                lid = str(ed.get("SubjectLogonId", "")).strip()
            if lid and lid not in _LOGON_ID_SKIP:
                _lid_to_keys.setdefault((computer or "", lid), set()).add((src_file or "", rec_id))

        # Capture for closure
        _shard_list_captured = shard_list
        _hw_model = self._hw_model

        def _jm_session_filter(logon_id: str | None, session_info: dict | None):
            import logging as _log
            try:
                return _jm_session_filter_impl(logon_id, session_info)
            except Exception:
                _log.getLogger("eventhawk.session").exception(
                    "JM session filter raised an unhandled exception for LogonId=%s", logon_id
                )
                raise  # propagate so _on_filter_clicked can show the error dialog

        def _jm_session_filter_impl(logon_id: str | None, session_info: dict | None) -> None:
            if logon_id is None:
                _hw_model.clear_record_id_filter()
                for _fm in self._jm_file_models:
                    _fm.clear_record_id_filter()
                self._active_jm_session_keys = frozenset()
                self._update_session_filter_badge(None, None)
                self._update_count_label()
                return

            # Query ALL events from Parquet whose event_data references this
            # concrete session instance. Scope by host + time window so later
            # same-host LogonId reuse does not leak into the selected session.
            _computer = (session_info or {}).get("computer", "")
            _start_ts = (session_info or {}).get("scope_start_ts", "")
            _end_ts = (session_info or {}).get("scope_end_ts", "")
            _end_inclusive = bool((session_info or {}).get("scope_end_inclusive"))
            _linked_lid = (session_info or {}).get("linked_lid", "") or ""
            if _linked_lid:
                # Widen to union of both sibling windows.
                _ls = (session_info or {}).get("linked_scope_start_ts") or ""
                _le = (session_info or {}).get("linked_scope_end_ts") or ""
                _lei = bool((session_info or {}).get("linked_scope_end_inclusive"))
                if _ls and (not _start_ts or _ls < _start_ts):
                    _start_ts = _ls
                if _le:
                    if not _end_ts or _le > _end_ts:
                        _end_ts = _le
                        _end_inclusive = _lei
                    elif _le == _end_ts:
                        _end_inclusive = _end_inclusive or _lei
            # ── Build WHERE clause ────────────────────────────────────────
            _JM_SESSION_ROW_WARN  = 100_000   # warn before continuing
            _JM_SESSION_ROW_LIMIT = 500_000   # hard cap

            if _linked_lid:
                _where_parts: list[str] = [
                    "("
                    "json_extract_string(event_data_json, '$.TargetLogonId') IN (?, ?) "
                    "OR json_extract_string(event_data_json, '$.SubjectLogonId') IN (?, ?)"
                    ")"
                ]
                _params: list[object] = [logon_id, _linked_lid, logon_id, _linked_lid]
            else:
                _where_parts = [
                    "("
                    "json_extract_string(event_data_json, '$.TargetLogonId') = ? "
                    "OR json_extract_string(event_data_json, '$.SubjectLogonId') = ?"
                    ")"
                ]
                _params = [logon_id, logon_id]
            if _computer:
                _where_parts.append("computer = ?")
                _params.append(_computer)
            if _start_ts:
                _where_parts.append("timestamp_utc >= CAST(? AS TIMESTAMP)")
                _params.append(_start_ts)
            if _end_ts:
                _where_parts.append(
                    f"timestamp_utc {'<=' if _end_inclusive else '<'} CAST(? AS TIMESTAMP)"
                )
                _params.append(_end_ts)
            _where_sql = " AND ".join(_where_parts)
            _scan_sql  = f"parquet_scan({_shard_list_captured})"

            # ── Both phases run on the worker thread — main thread never blocks ──
            # Phase 1 (COUNT) emits count_ready; main thread slot decides whether
            # to proceed.  Phase 2 (row fetch) runs after proceed(True) is called.
            # A single QEventLoop drives both phases so the Qt event loop stays
            # alive (and the UI stays responsive) throughout.
            from PySide6.QtWidgets import QApplication as _QApp, QProgressDialog as _QPD
            from PySide6.QtCore import Qt as _Qt2, QEventLoop as _QEL

            _query_result: list = [None, None]   # [frozenset | None, error_str | None]
            _query_loop   = _QEL()
            _canceled     = [False]

            _worker = _JMSessionFetchWorker(
                _duckdb, _scan_sql, _where_sql, _params, _JM_SESSION_ROW_LIMIT,
            )

            _progress = _QPD("Counting session events\u2026", "", 0, 0, self)
            _progress.setWindowTitle("Session Filter")
            _progress.setWindowModality(_Qt2.WindowModality.WindowModal)
            _progress.setMinimumDuration(0)
            _progress.setValue(0)
            _progress.setCancelButton(None)   # hide cancel — we manage this ourselves

            def _on_count(n: int) -> None:
                if n > _JM_SESSION_ROW_WARN:
                    _progress.hide()
                    _ans = QMessageBox.question(
                        self,
                        "Large Session",
                        f"This session matches {n:,} events.\n"
                        "Applying the filter may take several seconds.\n\n"
                        "Continue?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                        QMessageBox.StandardButton.No,
                    )
                    if _ans != QMessageBox.StandardButton.Yes:
                        _canceled[0] = True
                        _worker.proceed(False)
                        _query_loop.quit()
                        return
                    _progress.setLabelText("Retrieving session events\u2026")
                    _progress.show()
                else:
                    _progress.setLabelText("Retrieving session events\u2026")
                _worker.proceed(True)

            def _on_rows(keys) -> None:
                _query_result[0] = keys
                _progress.close()
                _query_loop.quit()

            def _on_failed(msg: str) -> None:
                _query_result[1] = msg
                _progress.close()
                _query_loop.quit()

            _worker.count_ready.connect(_on_count)
            _worker.rows_ready.connect(_on_rows)
            _worker.query_failed.connect(_on_failed)
            # Show progress BEFORE starting the worker so the dialog is
            # visible by the time count_ready arrives on the main thread.
            _progress.show()
            _worker.start()
            _query_loop.exec()    # nested event loop — UI stays alive
            _worker.wait()        # ensure thread fully joined before touching results

            if _canceled[0]:
                return False      # user clicked No on large-session dialog

            if _query_result[1]:
                # Worker raised — fall back to precomputed keys
                import logging as _log
                _log.getLogger("eventhawk.session").error(
                    "JM session filter query failed for LogonId=%s (%s); "
                    "falling back to precomputed keys.", logon_id, _query_result[1],
                )
                composite_keys = frozenset(
                    (session_info or {}).get("linked_related_keys")
                    or (session_info or {}).get("related_keys", ())
                )
            else:
                composite_keys = _query_result[0] or frozenset()
                if len(composite_keys) >= _JM_SESSION_ROW_LIMIT:
                    import logging as _log
                    _log.getLogger("eventhawk.session").warning(
                        "JM session filter hit hard cap of %d rows for LogonId=%s; "
                        "result set may be incomplete.",
                        _JM_SESSION_ROW_LIMIT, logon_id,
                    )

            if not composite_keys:
                QMessageBox.information(self, "Logon Sessions",
                                        f"No events found for LogonId {logon_id}.")
                return False  # no-op — do not update badge

            # Apply composite-key filter to merged model and all open per-file JM tabs.
            _hw_model.apply_bookmark_filter(composite_keys)
            for _fm in self._jm_file_models:
                _fm.apply_bookmark_filter(composite_keys)
            # Remember active keys so tabs opened later can inherit this filter.
            self._active_jm_session_keys = composite_keys
            self._update_session_filter_badge(logon_id, session_info)
            self._update_count_label()
            return True  # filter successfully applied

        # Close any existing session browser (normal or JM) before opening a new one.
        self._close_logon_sessions_dlg()
        dlg = _LogonSessionDialog(
            events=events,
            on_filter_fn=_jm_session_filter,
            parent=self,
        )
        self._logon_sessions_dlg = dlg
        dlg.show()
        dlg.raise_()
        dlg.activateWindow()

    def _set_session_filter(self, logon_id: str | None, session_info: dict | None) -> None:
        """Apply or clear the session LogonId filter on all proxy models."""
        import logging as _log
        try:
            self._set_session_filter_impl(logon_id, session_info)
        except Exception:
            _log.getLogger("eventhawk.session").exception(
                "set_session_filter raised an exception for LogonId=%s", logon_id
            )
            raise  # propagate so _on_filter_clicked can show the error dialog

    def _set_session_filter_impl(self, logon_id: str | None, session_info: dict | None) -> None:
        """Apply or clear the session LogonId filter on all proxy models."""
        # Extract host + time scope so the filter doesn't match same-LUID
        # sessions from other hosts or later reuse on the same host.
        computer = (session_info or {}).get("computer", "") if logon_id else None
        scope_start_ts = (session_info or {}).get("scope_start_ts") if logon_id else None
        scope_end_ts = (session_info or {}).get("scope_end_ts") if logon_id else None
        scope_end_inclusive = bool((session_info or {}).get("scope_end_inclusive")) if logon_id else False
        linked_lid = (session_info or {}).get("linked_lid", "") or None if logon_id else None
        if linked_lid and logon_id:
            # Widen to union of both sibling windows so events belonging to
            # the linked session that fall outside the primary window are kept.
            _ls = (session_info or {}).get("linked_scope_start_ts") or ""
            _le = (session_info or {}).get("linked_scope_end_ts") or ""
            _lei = bool((session_info or {}).get("linked_scope_end_inclusive"))
            if _ls and (not scope_start_ts or _ls < scope_start_ts):
                scope_start_ts = _ls
            if _le:
                if not scope_end_ts or _le > scope_end_ts:
                    scope_end_ts = _le
                    scope_end_inclusive = _lei
                elif _le == scope_end_ts:
                    scope_end_inclusive = scope_end_inclusive or _lei
        # Pass linked_lid into set_session_filter() so all fields are committed
        # atomically before the single invalidateFilter() call — avoids the
        # double-invalidation that occurred when set_session_linked_lid() was
        # called as a separate step.
        self._proxy_model.set_session_filter(
            logon_id, computer, scope_start_ts, scope_end_ts, scope_end_inclusive,
            linked_lid=linked_lid,
        )
        for state in self._file_tabs.values():
            state.proxy.set_session_filter(
                logon_id, computer, scope_start_ts, scope_end_ts, scope_end_inclusive,
                linked_lid=linked_lid,
            )
        self._update_session_filter_badge(logon_id, session_info)
        self._update_count_label()

    def _clear_session_filter(self) -> None:
        """Clear the session filter from all proxies and hide the badge."""
        if self._hw_model is not None:
            # Juggernaut mode — filter lives on ArrowTableModels (merged + per-file tabs)
            self._hw_model.clear_record_id_filter()
            for _fm in getattr(self, "_jm_file_models", []):
                _fm.clear_record_id_filter()
            self._active_jm_session_keys = frozenset()
            self._update_session_filter_badge(None, None)
            self._update_count_label()
        else:
            self._set_session_filter(None, None)
        # Sync the dialog's internal badge so it doesn't claim a filter is
        # active after it was cleared from outside the dialog.
        _dlg = getattr(self, "_logon_sessions_dlg", None)
        if _dlg is not None:
            try:
                _dlg.notify_filter_cleared()
            except RuntimeError:
                pass

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
            logger.exception("Failed to open Threat Intel dialog")
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
            logger.exception("ATT&CK tactic CSV export failed: %s", path)
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
            logger.exception("IOC export failed: %s", path)
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
            lid            = self._proxy_model.get_session_filter()
            computer       = self._proxy_model.get_session_filter_computer()
            scope_start_ts = self._proxy_model.get_session_filter_start_ts()
            scope_end_ts   = self._proxy_model.get_session_filter_end_ts()
            scope_end_incl = self._proxy_model.get_session_filter_end_inclusive()
            linked_lid     = self._proxy_model.get_session_linked_lid()
            if lid:
                # Use the atomic form so the new proxy's filter is fully
                # committed before its single invalidateFilter() call — avoids
                # the extra invalidation that the old two-step path caused.
                proxy.set_session_filter(
                    lid,
                    computer,
                    scope_start_ts,
                    scope_end_ts,
                    scope_end_incl,
                    linked_lid=linked_lid,
                )

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
            logger.exception("Event export failed: %s", path)
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
            logger.exception("Per-file export failed: %s", out_dir)
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
            # ALWAYS append a unique (source_file, record_id) tiebreaker:
            #  1. same-timestamp rows export in deterministic, reproducible order;
            #  2. the HTML/XML path paginates with LIMIT/OFFSET — without a
            #     total order, ties spanning a batch boundary can be DUPLICATED
            #     or SKIPPED between batches (rows silently lost from exports).
            order_sql = (f"{sort_col} {direction}, "
                         f"source_file {direction}, record_id {direction}")

            # Open a temporary in-memory DuckDB connection on the Arrow table.
            # This gives us streaming SQL access without needing _hw_con.
            _exp_con = _duckdb.connect()
            _exp_con.register("events", self._hw_model._full_table)

            ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""

            # Fast path: streaming Python writer for CSV/JSON.
            if ext in ("csv", "json"):
                import csv as _csv
                import json as _json
                # The Arrow table excludes event_data_json (memory); without
                # re-attaching it, CSV/JSON exports would silently omit ALL
                # EventData in Juggernaut mode — incomplete forensic records.
                # A 1:1 composite-key LEFT JOIN back to the Parquet shards adds
                # event_data_json while preserving streaming (no full-set buffer)
                # and the exact filtered/ordered row set (no dup, no loss).
                _shard_paths = self._hw_model._get_shard_paths()
                if _shard_paths:
                    cursor = _exp_con.execute(
                        f"SELECT e.* EXCLUDE (ed_values), p.ed_json_full AS event_data_json "
                        f"FROM events e "
                        f"LEFT JOIN (SELECT record_id AS _jrid, "
                        f"           source_file AS _jsf, "
                        f"           event_data_json AS ed_json_full "
                        f"           FROM parquet_scan({_shard_paths})) p "
                        f"  ON e.record_id = p._jrid AND e.source_file = p._jsf "
                        f"WHERE {where_sql} "
                        f"ORDER BY {order_sql}",
                        params,
                    )
                else:
                    cursor = _exp_con.execute(
                        f"SELECT * EXCLUDE (ed_values) FROM events "
                        f"WHERE {where_sql} "
                        f"ORDER BY {order_sql}",
                        params,
                    )
                col_names = [d[0].strip() for d in cursor.description]
                if ext == "csv":
                    with open(path, "w", newline="", encoding="utf-8") as _f:
                        writer = _csv.writer(_f)
                        writer.writerow(col_names)
                        while True:
                            _batch = cursor.fetchmany(5000)
                            if not _batch:
                                break
                            writer.writerows(_batch)
                else:  # json
                    with open(path, "w", encoding="utf-8") as _f:
                        _f.write("[\n")
                        _first = True
                        while True:
                            _batch = cursor.fetchmany(5000)
                            if not _batch:
                                break
                            for _row in _batch:
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
                    f"SELECT * EXCLUDE (ed_values) FROM events "
                    f"WHERE {where_sql} "
                    f"ORDER BY {order_sql} "
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
            # Enrich event_data from Parquet shards (Arrow table only has metadata columns)
            _shard_paths = self._hw_model._get_shard_paths()
            if _shard_paths and events:
                try:
                    import json as _json_ed
                    import pyarrow as _pa_ed
                    _key_tbl = _pa_ed.table({
                        "k_src": [ev["source_file"] or "" for ev in events],
                        "k_rid": [ev["record_id"] for ev in events],
                    })
                    _exp_con.register("_export_keys", _key_tbl)
                    _ed_rows = _exp_con.execute(
                        f"SELECT p.source_file, p.record_id, p.event_data_json "
                        f"FROM parquet_scan({_shard_paths}) p "
                        f"INNER JOIN _export_keys k "
                        f"  ON p.source_file = k.k_src AND p.record_id = k.k_rid"
                    ).fetchall()
                    _ed_map = {(r[0], r[1]): r[2] for r in _ed_rows if r[2]}
                    for _ev in events:
                        _ed_json = _ed_map.get((_ev["source_file"], _ev["record_id"]))
                        if _ed_json:
                            try:
                                _ev["event_data"] = _json_ed.loads(_ed_json)
                            except Exception:
                                pass
                except Exception as _ed_exc:
                    logger.warning("HTML/XML export: could not load event_data from Parquet: %s", _ed_exc)
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
            logger.exception("Juggernaut export failed: %s", path)
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
                logger.warning("Failed to open output folder: %s", output_dir, exc_info=True)

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

        # Clear normal-mode session filter so a stale LogonId does not carry
        # over to a subsequent load.  JM session state is reset by cleanup above.
        self._set_session_filter(None, None)

        self._events             = []
        self._close_logon_sessions_dlg()   # close + invalidate session browser cache
        self._close_ra_dlg(clear_filter=True)  # M1: close + clear RA filter + kill worker
        self._close_computer_norm_dlg()    # invalidate cached aggregation
        self._attack_summary     = None
        self._iocs               = None
        self._chains             = []

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
        # Drop the cached Advanced Filter cfg.  Without this it would carry
        # across to the next parse, and — combined with the profile-stacking
        # fix in _on_hw_profile_filter_changed — toggling a profile on the
        # newly loaded dataset would silently re-apply the previous session's
        # advanced filter to it.  Also refresh the badge so it hides cleanly.
        self._adv_filter_cfg = None
        # Clear bookmarks — events no longer exist after a reset
        self._bookmarks.clear()
        self._bookmarked_keys.clear()
        self._refresh_bookmarks_tab()
        self._btn_bookmark_event.setText("☆ Bookmark")
        self._btn_bookmark_event.setChecked(False)
        self._update_bookmark_highlights()
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
        title = QLabel("<b>EventHawk v1.3</b>")
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
        2. Re-apply any active advanced filter so date bounds are recomputed in
           the new timezone (set_advanced_filter reads _tz_state at call time).
        3. Emit layoutChanged on every live EventTableModel so the table cells
           re-read COL_TS and re-render in the new timezone.
        4. Re-render the detail panel for the currently selected row (if any).
        """
        set_tz_config(
            self._tz_mode,
            self._tz_specific,
            self._tz_custom_offset_min,
        )

        # Re-apply the active advanced filter now that _tz_state is updated.
        # This recomputes _adv_date_from / _adv_date_to in the new timezone so
        # a specific-day or date-range filter continues to match the dates the
        # user sees in the table rather than drifting by a timezone offset.
        #
        # In JM mode we must rebuild the *combined* filter (profiles stacked on
        # top of the dialog cfg) — applying the dialog cfg alone would silently
        # wipe an active profile selection.  In normal mode the proxy holds
        # only the dialog cfg, so passing it through unchanged is correct.
        _cfg = getattr(self, "_adv_filter_cfg", None)
        if _cfg is not None or (
            self._hw_model is not None and self._get_checked_profiles()
        ):
            if self._hw_model is not None:
                try:
                    _effective = self._build_filter_config(base=_cfg)
                    self._hw_model.apply_filter(_effective)
                    for _fp, _st in self._file_tabs.items():
                        if _fp.startswith("__chain__"):
                            continue
                        try:
                            _st.model.apply_filter(_effective)
                        except Exception:
                            pass
                except Exception:
                    pass
            elif _cfg is not None:
                # Merged-mode proxy
                try:
                    if self._proxy_model.has_advanced_filter():
                        self._proxy_model.set_advanced_filter(_cfg)
                except Exception:
                    pass
                # Per-file tab proxies (separate mode)
                for _state in self._file_tabs.values():
                    try:
                        if _state.proxy.has_advanced_filter():
                            _state.proxy.set_advanced_filter(_cfg)
                    except Exception:
                        pass

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
        self._update_bookmark_highlights()

    def _update_bookmark_highlights(self) -> None:
        """Push current bookmarked keys to all models so rows are visually highlighted."""
        keys = frozenset(self._bookmarked_keys)
        if self._hw_model is not None:
            self._hw_model.set_bookmark_highlights(keys)
            for _fm in getattr(self, "_jm_file_models", []):
                _fm.set_bookmark_highlights(keys)
        else:
            self._event_model.set_bookmark_highlights(keys)
            for _state in self._file_tabs.values():
                _state.model.set_bookmark_highlights(keys)

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
        # Clear any active bookmark filter so the table shows all events again
        if self._hw_model is not None:
            self._hw_model.clear_record_id_filter()
            for _fm in getattr(self, "_jm_file_models", []):
                _fm.clear_record_id_filter()
        else:
            self._proxy_model.clear_bookmark_filter()
            for _state in self._file_tabs.values():
                _state.proxy.clear_bookmark_filter()
        # Remove amber highlight from all rows
        self._update_bookmark_highlights()

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
