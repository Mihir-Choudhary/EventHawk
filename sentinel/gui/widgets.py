"""
Shared small widgets for the Sentinel GUI.
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QLabel, QStyledItemDelegate, QStyleOptionViewItem, QWidget


# ── Tier color mapping ─────────────────────────────────────────────────────────
TIER_COLORS: dict[int, QColor] = {
    1: QColor("#3a3a3a"),    # suppressed — dark
    2: QColor("#2d4a2d"),    # aggregate — dark green
    3: QColor("#5a3e00"),    # highlight — dark orange
    4: QColor("#5a0000"),    # critical — dark red
}
TIER_TEXT_COLORS: dict[int, QColor] = {
    1: QColor("#888888"),
    2: QColor("#80c880"),
    3: QColor("#ffb347"),
    4: QColor("#ff6b6b"),
}
TIER_LABELS: dict[int, str] = {
    1: "T1",
    2: "T2",
    3: "T3",
    4: "T4",
}


class ScoreBadge(QLabel):
    """A compact colored label showing a score and tier badge."""

    def __init__(self, score: float, tier: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAlignment(Qt.AlignCenter)
        self.setFixedWidth(64)
        color = TIER_TEXT_COLORS.get(tier, QColor("white"))
        bg = TIER_COLORS.get(tier, QColor("#333333"))
        self.setText(f"{score:.1f}")
        self.setStyleSheet(
            f"background:{bg.name()}; color:{color.name()}; "
            f"border-radius:4px; padding:2px 4px; font-weight:bold;"
        )


class TierColorDelegate(QStyledItemDelegate):
    """
    Item delegate that colors table/tree rows by tier.
    The model must return tier (int 1-4) via Qt.UserRole for column 0.
    """

    def initStyleOption(
        self, option: QStyleOptionViewItem, index
    ) -> None:
        super().initStyleOption(option, index)
        tier_data = index.sibling(index.row(), 0).data(Qt.UserRole)
        if isinstance(tier_data, int) and tier_data in TIER_COLORS:
            option.backgroundBrush = TIER_COLORS[tier_data]
            option.palette.setColor(
                option.palette.Text,
                TIER_TEXT_COLORS[tier_data],
            )


def section_label(text: str, parent: QWidget | None = None) -> QLabel:
    """Bold section header label."""
    lbl = QLabel(text, parent)
    font = QFont()
    font.setBold(True)
    font.setPointSize(10)
    lbl.setFont(font)
    return lbl
