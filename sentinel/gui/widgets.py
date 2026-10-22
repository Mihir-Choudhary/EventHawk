"""
Shared small widgets for the Sentinel GUI.
"""
from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from typing import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QLabel, QMessageBox, QStyledItemDelegate, QStyleOptionViewItem, QWidget,
)


def show_blocking(parent: QWidget, icon: QMessageBox.Icon, title: str, text: str) -> None:
    """A modal message that cannot end up hidden behind its window.

    A modal runs a nested event loop: until it is dismissed the window looks
    alive but ignores every click.  On Windows it can open behind its parent
    when the user switched away during a long build or analysis -- the
    EventHawk issue #4 freeze.  Raising and activating it keeps it visible.
    Use for messages raised automatically when a background job ends.
    """
    box = QMessageBox(icon, title, text, QMessageBox.StandardButton.Ok, parent)
    box.setWindowFlag(Qt.WindowType.WindowStaysOnTopHint, True)
    box.show()            # realise the window so the next two calls apply
    box.raise_()
    box.activateWindow()
    box.exec()


class _ThreadWarningHandler(logging.Handler):
    def __init__(self, sink: Callable[[str], None]) -> None:
        super().__init__(logging.WARNING)
        self._sink = sink
        self._thread = threading.get_ident()

    def emit(self, record: logging.LogRecord) -> None:
        if record.thread != self._thread:      # another tab's job
            return
        try:
            self._sink(f"{record.levelname}: {record.getMessage()}")
        except Exception:
            self.handleError(record)


@contextmanager
def forward_warnings(sink: Callable[[str], None]):
    """Send sentinel WARNING+ records logged on this thread to ``sink``.

    The engine reports skipped records, unreadable timestamps, files that
    failed to open and similar through ``logging`` -- which the GUI never
    displayed (and pythonw has no console), so those caveats were invisible
    to the analyst.  Use inside a worker's run() with a signal's emit.
    """
    handler = _ThreadWarningHandler(sink)
    root = logging.getLogger("sentinel")
    root.addHandler(handler)
    try:
        yield
    finally:
        root.removeHandler(handler)


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
