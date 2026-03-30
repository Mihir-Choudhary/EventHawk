"""
Results tab.

Displays:
  - Tier 4 critical alerts in a QTreeWidget grouped by ATT&CK technique
    (expandable rows with cmdline, lineage, sub-scores)
  - Tier 3 edge cases in a QTableWidget with justification column
  - Color coding: Tier 4 = red, Tier 3 = orange
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sentinel.gui.widgets import TIER_COLORS, TIER_TEXT_COLORS, section_label

_TIER4_BG = QColor("#3d0000")
_TIER4_FG = QColor("#ff6b6b")
_TIER3_BG = QColor("#3d2800")
_TIER3_FG = QColor("#ffb347")


class ResultsTab(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        splitter = QSplitter(Qt.Vertical)

        # ── Tier 4 — Critical Alerts ───────────────────────────────────────────
        t4_widget = QWidget()
        t4_layout = QVBoxLayout(t4_widget)
        t4_layout.setContentsMargins(0, 0, 0, 0)

        self._t4_label = section_label("Critical Alerts (Tier 4) — Grouped by ATT&CK Technique")
        t4_layout.addWidget(self._t4_label)

        self._t4_tree = QTreeWidget()
        self._t4_tree.setColumnCount(5)
        self._t4_tree.setHeaderLabels(["Technique / Process", "Score", "Parent", "User", "Timestamp"])
        self._t4_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self._t4_tree.header().setDefaultSectionSize(120)
        self._t4_tree.setAlternatingRowColors(False)
        self._t4_tree.setSelectionMode(QAbstractItemView.SingleSelection)
        self._t4_tree.setRootIsDecorated(True)
        t4_layout.addWidget(self._t4_tree)

        splitter.addWidget(t4_widget)

        # ── Tier 3 — Edge Cases ────────────────────────────────────────────────
        t3_widget = QWidget()
        t3_layout = QVBoxLayout(t3_widget)
        t3_layout.setContentsMargins(0, 0, 0, 0)

        self._t3_label = section_label("Edge Case Review (Tier 3)")
        t3_layout.addWidget(self._t3_label)

        self._t3_table = QTableWidget(0, 7)
        self._t3_table.setHorizontalHeaderLabels(
            ["Score", "Process", "Parent", "User", "Timestamp", "ATT&CK Tags", "Justification"]
        )
        self._t3_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self._t3_table.horizontalHeader().setDefaultSectionSize(110)
        self._t3_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._t3_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._t3_table.setAlternatingRowColors(True)
        t3_layout.addWidget(self._t3_table)

        splitter.addWidget(t3_widget)
        splitter.setSizes([400, 300])

        layout.addWidget(splitter)

    def populate(self, scored_events: list) -> None:
        """Fill the results tab from a list of ScoredEvent objects."""
        self._t4_tree.clear()
        self._t3_table.setRowCount(0)

        tier4 = [e for e in scored_events if e.tier == 4]
        tier3 = [e for e in scored_events if e.tier == 3]

        self._t4_label.setText(
            f"Critical Alerts (Tier 4) — {len(tier4)} event(s) — Grouped by ATT&CK Technique"
        )
        self._t3_label.setText(f"Edge Case Review (Tier 3) — {len(tier3)} event(s)")

        self._populate_tier4(tier4)
        self._populate_tier3(tier3)

    def _populate_tier4(self, events: list) -> None:
        from collections import defaultdict
        by_tech: dict[str, list] = defaultdict(list)
        for ev in sorted(events, key=lambda e: e.composite, reverse=True):
            tags = ev.raw.attck_tags or ["UNTAGGED"]
            for tag in tags:
                by_tech[tag].append(ev)

        bold = QFont()
        bold.setBold(True)

        for tech in sorted(by_tech.keys()):
            evts = by_tech[tech]
            tech_item = QTreeWidgetItem(self._t4_tree)
            tech_item.setText(0, f"{tech}  ({len(evts)} event(s))")
            tech_item.setForeground(0, _TIER4_FG)
            tech_item.setBackground(0, _TIER4_BG)
            tech_item.setFont(0, bold)
            for col in range(1, 5):
                tech_item.setBackground(col, _TIER4_BG)

            for ev in evts:
                raw = ev.raw
                child = QTreeWidgetItem(tech_item)
                child.setText(0, ev.normalized.proc_norm)
                child.setText(1, f"{ev.composite:.1f}")
                child.setText(2, ev.normalized.parent_norm)
                child.setText(3, raw.user)
                ts = raw.timestamp.strftime("%Y-%m-%d %H:%M:%S") if raw.timestamp else ""
                child.setText(4, ts)
                child.setForeground(0, _TIER4_FG)
                child.setBackground(0, _TIER4_BG)

                # Detail sub-item
                detail = QTreeWidgetItem(child)
                cmdline_display = raw.cmdline[:200] + "..." if len(raw.cmdline) > 200 else raw.cmdline
                detail_text = (
                    f"CMD: {cmdline_display} | "
                    f"NORM: {ev.normalized.cmdline_norm[:120]} | "
                    f"Chain: {' → '.join(ev.normalized.ancestry_chain)} | "
                    f"Surprisal: cmd={ev.surprisal_cmdline:.1f}b lin={ev.surprisal_lineage:.1f}b | "
                    f"Trie={ev.trie_depth_score:.2f} | "
                    f"Flags: {', '.join(raw.flags) or 'none'}"
                )
                if ev.justification_text:
                    detail_text += f" | {ev.justification_text}"
                detail.setText(0, detail_text)
                detail.setForeground(0, QColor("#cccccc"))

            tech_item.setExpanded(True)

    def _populate_tier3(self, events: list) -> None:
        self._t3_table.setRowCount(len(events))
        for row, ev in enumerate(sorted(events, key=lambda e: e.composite, reverse=True)):
            raw = ev.raw
            ts = raw.timestamp.strftime("%Y-%m-%d %H:%M:%S") if raw.timestamp else ""

            items = [
                f"{ev.composite:.1f}",
                ev.normalized.proc_norm,
                ev.normalized.parent_norm,
                raw.user,
                ts,
                ", ".join(raw.attck_tags) if raw.attck_tags else "",
                ev.justification_text,
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setForeground(_TIER3_FG)
                item.setBackground(_TIER3_BG)
                self._t3_table.setItem(row, col, item)

    def clear(self) -> None:
        self._t4_tree.clear()
        self._t3_table.setRowCount(0)
