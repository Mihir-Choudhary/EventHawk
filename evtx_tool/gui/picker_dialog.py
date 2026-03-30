"""
Picker dialog for the advanced filter.

Shows a scrollable, checkable list of values with event counts,
a search bar, and OK / Cancel buttons.

Used for Source, Category, User, and Computer fields —
mirrors Event Log Explorer's "Select sources" / "Select users" popups.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, QSortFilterProxyModel
from PySide6.QtGui import QStandardItem, QStandardItemModel, QFont
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton,
    QTreeView, QHeaderView, QLabel, QAbstractItemView,
)

from .theme import COLORS


class PickerDialog(QDialog):
    """
    Modal dialog that presents a list of checkable values with counts.

    Parameters
    ----------
    title : str
        Dialog title, e.g. "Select sources".
    items : dict[str, int]
        Mapping of value → event count, e.g. {"Application Error": 793, ...}.
    pre_selected : set[str] | None
        Values that should start checked.  None = start unchecked.
    parent : QWidget | None
    """

    def __init__(
        self,
        title: str,
        items: dict[str, int],
        pre_selected: set[str] | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(420, 480)
        self.setMinimumSize(300, 250)
        self._items = items
        self._pre_selected = pre_selected or set()
        self._build_ui()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # ── Model ─────────────────────────────────────────────────────────
        self._model = QStandardItemModel()
        self._model.setHorizontalHeaderLabels(["Value", "Count"])

        for value, count in self._items.items():
            item_val = QStandardItem(value)
            item_val.setCheckable(True)
            item_val.setEditable(False)
            if value in self._pre_selected:
                item_val.setCheckState(Qt.CheckState.Checked)
            else:
                item_val.setCheckState(Qt.CheckState.Unchecked)

            item_cnt = QStandardItem(str(count))
            item_cnt.setEditable(False)
            item_cnt.setTextAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )
            font = QFont("Consolas", 9)
            item_cnt.setFont(font)

            self._model.appendRow([item_val, item_cnt])

        # ── Proxy for search ──────────────────────────────────────────────
        self._proxy = QSortFilterProxyModel()
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._proxy.setFilterKeyColumn(0)

        # ── Tree view ─────────────────────────────────────────────────────
        self._tree = QTreeView()
        self._tree.setModel(self._proxy)
        self._tree.setRootIsDecorated(False)
        self._tree.setAlternatingRowColors(True)
        self._tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._tree.setSortingEnabled(True)
        self._tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._tree.header().setStretchLastSection(False)
        self._tree.setColumnWidth(0, 320)   # Name
        self._tree.setColumnWidth(1, 60)    # Size
        self._tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        layout.addWidget(self._tree)

        # ── Search + buttons ──────────────────────────────────────────────
        bottom = QHBoxLayout()
        lbl = QLabel("Search:")
        bottom.addWidget(lbl)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter values...")
        self._search.setClearButtonEnabled(True)
        self._search.textChanged.connect(self._on_search_changed)
        bottom.addWidget(self._search)

        # Select all / none
        btn_all = QPushButton("All")
        btn_all.setToolTip("Check all visible items")
        btn_all.clicked.connect(self._check_all)
        bottom.addWidget(btn_all)

        btn_none = QPushButton("None")
        btn_none.setToolTip("Uncheck all items")
        btn_none.clicked.connect(self._uncheck_all)
        bottom.addWidget(btn_none)

        btn_ok = QPushButton("OK")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self.accept)
        bottom.addWidget(btn_ok)

        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        bottom.addWidget(btn_cancel)

        layout.addLayout(bottom)

        # ── Style ─────────────────────────────────────────────────────────
        self.setStyleSheet(f"""
            QDialog {{
                background: {COLORS['bg_panel']};
                color: {COLORS['text']};
            }}
            QTreeView {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                alternate-background-color: {COLORS.get('bg_alt_row', '#ede8d8')};
                border: 1px solid {COLORS['border']};
                font-size: 9pt;
            }}
            QTreeView::item {{
                padding: 2px 4px;
            }}
            QHeaderView::section {{
                background: {COLORS['bg_header']};
                color: {COLORS['text_dim']};
                border: 1px solid {COLORS['border']};
                padding: 3px 6px;
                font-size: 8pt;
                font-weight: bold;
            }}
            QLineEdit {{
                background: {COLORS['bg_main']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 3px 6px;
            }}
            QPushButton {{
                background: {COLORS['bg_header']};
                color: {COLORS['text']};
                border: 1px solid {COLORS['border']};
                border-radius: 3px;
                padding: 4px 12px;
                font-size: 9pt;
            }}
            QPushButton:hover {{
                background: {COLORS.get('accent', '#7a5c1e')};
                color: white;
            }}
            QLabel {{
                color: {COLORS['text_dim']};
                font-size: 9pt;
            }}
        """)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _on_search_changed(self, text: str) -> None:
        """Update filter and auto-select matching items (Excel-like behavior)."""
        self._proxy.setFilterFixedString(text)
        if not text:
            # Search cleared — restore all items to checked
            for row in range(self._model.rowCount()):
                item = self._model.item(row, 0)
                if item:
                    item.setCheckState(Qt.CheckState.Checked)
            return
        # Build set of source rows that are visible after filtering
        visible_source_rows = set()
        for proxy_row in range(self._proxy.rowCount()):
            src_idx = self._proxy.mapToSource(self._proxy.index(proxy_row, 0))
            visible_source_rows.add(src_idx.row())
        # Check visible items, uncheck hidden items
        for row in range(self._model.rowCount()):
            item = self._model.item(row, 0)
            if item:
                state = Qt.CheckState.Checked if row in visible_source_rows else Qt.CheckState.Unchecked
                item.setCheckState(state)

    def _check_all(self) -> None:
        """Check all currently visible (not filtered out) items."""
        for row in range(self._proxy.rowCount()):
            src_idx = self._proxy.mapToSource(self._proxy.index(row, 0))
            item = self._model.itemFromIndex(src_idx)
            if item:
                item.setCheckState(Qt.CheckState.Checked)

    def _uncheck_all(self) -> None:
        """Uncheck every item (visible or not)."""
        for row in range(self._model.rowCount()):
            item = self._model.item(row, 0)
            if item:
                item.setCheckState(Qt.CheckState.Unchecked)

    # ── Result ────────────────────────────────────────────────────────────────

    def selected_values(self) -> set[str]:
        """Return the set of checked values after the dialog is accepted."""
        result: set[str] = set()
        for row in range(self._model.rowCount()):
            item = self._model.item(row, 0)
            if item and item.checkState() == Qt.CheckState.Checked:
                result.add(item.text())
        return result
