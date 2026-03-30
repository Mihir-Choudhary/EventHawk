"""
Warm Cream / Beige theme for EventHawk GUI.

Aesthetic: Soft ecru / cream — document-reader warmth with professional contrast.
Warm off-white backgrounds, dark amber accents, dark-brown text.
"""

# ── Colour constants (also used by main_window for per-cell colouring) ────────

COLORS = {
    # Backgrounds
    "bg_main":    "#f5f0e8",   # soft cream — main window
    "bg_panel":   "#ede8df",   # warm beige — panels / sidebars
    "bg_header":  "#e4ddd3",   # warm sand — header bars
    "bg_input":   "#faf7f2",   # near-white cream — inputs
    "bg_hover":   "#e9e2d8",   # warm hover tint
    "bg_alt_row": "#ede8d8",   # alternating table row

    # Borders / separators
    "border":       "#c4bba8",  # warm taupe
    "border_focus": "#b8924a",  # amber focus ring

    # Text
    "text":       "#1e1a14",   # dark warm brown
    "text_dim":   "#5a4e42",   # medium warm brown
    "text_muted": "#9a8878",   # light warm brown (muted)

    # Accents
    "accent":          "#7a5c1e",  # dark amber
    "accent_hover":    "#9b7a2e",  # amber hover
    "selected_bg":     "#ddd4bc",  # warm tan selected
    "selected_border": "#7a5c1e",  # amber

    # Event levels
    "level_critical": "#a01800",  # dark crimson
    "level_error":    "#a01800",
    "level_warning":  "#7a4c00",  # dark amber-orange
    "level_info":     "#1e1a14",  # dark brown (same as main text)
    "level_verbose":  "#9a8878",  # muted brown

    # Analysis
    "attack_badge":   "#7a5c1e",  # amber
    "ioc_found":      "#2e6820",  # forest green
    "chain_critical": "#a01800",
    "chain_high":     "#7a4c00",
    "chain_medium":   "#2a5a8a",  # warm muted blue
    "chain_low":      "#5a4e42",

    # ATT&CK tactic colours
    "ta_recon":      "#6a5a4c",
    "ta_resource":   "#5a4e42",
    "ta_initial":    "#a01800",
    "ta_exec":       "#b03800",
    "ta_persist":    "#7a4c00",
    "ta_privesc":    "#6a3e00",
    "ta_defense":    "#6a2a8a",
    "ta_cred":       "#8a3c00",
    "ta_discovery":  "#2a5a8a",
    "ta_lateral":    "#2a6a2a",
    "ta_collect":    "#1e5c1e",
    "ta_c2":         "#8a4e00",
    "ta_exfil":      "#b03800",
    "ta_impact":     "#a01800",

    # Buttons
    "btn_bg":        "#e4ddd3",
    "btn_hover":     "#d8d1c5",
    "btn_pressed":   "#ccc5b5",
    "btn_parse_bg":  "#4a6830",   # forest green — Parse action
    "btn_parse_hov": "#5a8038",
    "btn_stop_bg":   "#a01800",
    "btn_stop_hov":  "#c02000",

    # Progress
    "progress_bg":   "#e4ddd3",
    "progress_fill": "#7a5c1e",
    "progress_text": "#1e1a14",
}

# ── Master QSS stylesheet ──────────────────────────────────────────────────────

DARK_QSS = """
/* ── Global ─────────────────────────────────────────── */
* {
    font-family: "Segoe UI", Arial, sans-serif;
    font-size: 9pt;
    color: #1e1a14;
    outline: none;
}

QMainWindow, QDialog {
    background: #f5f0e8;
}

QWidget {
    background: #f5f0e8;
    color: #1e1a14;
}

/* ── Scroll Areas ────────────────────────────────────── */
QScrollArea {
    border: none;
    background: #f5f0e8;
}
QScrollArea > QWidget > QWidget {
    background: #f5f0e8;
}

/* ── Labels ──────────────────────────────────────────── */
QLabel {
    background: transparent;
    color: #1e1a14;
}
QLabel#sectionHeader {
    color: #5a4e42;
    font-size: 8pt;
    font-weight: bold;
    letter-spacing: 1px;
    padding: 6px 0px 2px 0px;
    border-bottom: 1px solid #e4ddd3;
}
QLabel#statsLabel {
    color: #5a4e42;
    font-size: 8pt;
}
QLabel#countLabel {
    color: #7a5c1e;
    font-size: 8pt;
}

/* ── Radio Buttons ───────────────────────────────────── */
QRadioButton {
    background: transparent;
    color: #1e1a14;
    spacing: 6px;
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

/* ── GroupBox ────────────────────────────────────────── */
QGroupBox {
    border: none;
    border-top: 1px solid #e4ddd3;
    margin-top: 8px;
    padding-top: 6px;
    background: transparent;
    color: #5a4e42;
    font-size: 8pt;
    font-weight: bold;
    letter-spacing: 1px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 4px;
    color: #5a4e42;
}

/* ── Buttons ─────────────────────────────────────────── */
QPushButton {
    background: #e4ddd3;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    padding: 4px 10px;
    min-height: 22px;
}
QPushButton:hover {
    background: #d8d1c5;
    border-color: #9a8878;
}
QPushButton:pressed {
    background: #ccc5b5;
    border-color: #b8924a;
}
QPushButton:disabled {
    color: #9a8878;
    border-color: #d0c8b8;
    background: #ede8df;
}

QPushButton#parseBtn {
    background: #4a6830;
    color: #ffffff;
    border: 1px solid #5a8038;
    border-radius: 2px;
    font-weight: bold;
    min-height: 28px;
    font-size: 9pt;
}
QPushButton#parseBtn:hover {
    background: #5a8038;
    border-color: #6a9840;
}
QPushButton#parseBtn:pressed {
    background: #3a5824;
}
QPushButton#parseBtn:disabled {
    background: #c8d0b8;
    color: #9a8878;
    border-color: #d0c8b8;
}

QPushButton#stopBtn {
    background: #e4ddd3;
    color: #a01800;
    border: 1px solid #c04020;
    border-radius: 2px;
    min-height: 24px;
}
QPushButton#stopBtn:hover {
    background: #f5e0dc;
    border-color: #a01800;
}
QPushButton#stopBtn:disabled {
    color: #9a8878;
    border-color: #d0c8b8;
    background: #ede8df;
}

QPushButton#exportBtn {
    background: #e4ddd3;
    color: #2a5a8a;
    border: 1px solid #4a7aaa;
    border-radius: 2px;
    min-height: 24px;
}
QPushButton#exportBtn:hover {
    background: #dce8f0;
    border-color: #2a5a8a;
}
QPushButton#exportBtn:disabled {
    color: #9a8878;
    border-color: #d0c8b8;
    background: #ede8df;
}

/* ── Line Edits / Inputs ─────────────────────────────── */
QLineEdit, QTextEdit {
    background: #faf7f2;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    padding: 3px 6px;
    selection-background-color: #7a5c1e;
    selection-color: #ffffff;
}
QLineEdit:focus, QTextEdit:focus {
    border-color: #b8924a;
}
QLineEdit:disabled {
    color: #9a8878;
    background: #ede8df;
}
QLineEdit#filterBar {
    background: #ede8df;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    padding: 4px 8px;
    color: #1e1a14;
    font-size: 9pt;
}
QLineEdit#filterBar:focus {
    border-color: #b8924a;
    background: #f0ead8;
}

/* ── ComboBox ────────────────────────────────────────── */
QComboBox {
    background: #ede8df;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    padding: 3px 6px;
    min-height: 22px;
}
QComboBox:focus, QComboBox:on {
    border-color: #b8924a;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #5a4e42;
    width: 0;
    height: 0;
}
QComboBox QAbstractItemView {
    background: #faf7f2;
    border: 1px solid #c4bba8;
    selection-background-color: #ddd4bc;
    selection-color: #1e1a14;
    outline: none;
}

/* ── SpinBox / DateTimeEdit ──────────────────────────── */
QSpinBox, QDateTimeEdit {
    background: #ede8df;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    padding: 3px 6px;
    min-height: 22px;
}
QSpinBox:focus, QDateTimeEdit:focus {
    border-color: #b8924a;
}
QSpinBox::up-button, QSpinBox::down-button,
QDateTimeEdit::up-button, QDateTimeEdit::down-button {
    background: #e4ddd3;
    border: none;
    width: 16px;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover,
QDateTimeEdit::up-button:hover, QDateTimeEdit::down-button:hover {
    background: #d8d1c5;
}
QDateTimeEdit::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border-left: 1px solid #c4bba8;
    background: #e4ddd3;
}
QDateTimeEdit::drop-down:hover { background: #d8d1c5; }
QDateTimeEdit::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #5a4e42;
    width: 0; height: 0;
}

/* Calendar popup */
QCalendarWidget { background: #ede8df; color: #1e1a14; }
QCalendarWidget QAbstractItemView {
    background: #faf7f2;
    color: #1e1a14;
    selection-background-color: #7a5c1e;
    selection-color: #ffffff;
    alternate-background-color: #ede8d8;
    outline: none;
}
QCalendarWidget QAbstractItemView:enabled  { color: #1e1a14; }
QCalendarWidget QAbstractItemView:disabled { color: #9a8878; }
QCalendarWidget QWidget#qt_calendar_navigationbar {
    background: #e4ddd3;
    min-height: 28px;
}
QCalendarWidget QToolButton {
    background: #e4ddd3;
    color: #1e1a14;
    border: none;
    padding: 4px 8px;
    font-weight: bold;
}
QCalendarWidget QToolButton:hover {
    background: #d8d1c5;
    color: #7a5c1e;
}
QCalendarWidget QToolButton::menu-indicator { image: none; }
QCalendarWidget QSpinBox {
    background: #ede8df;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    selection-background-color: #7a5c1e;
}

/* ── CheckBox ────────────────────────────────────────── */
QCheckBox {
    background: transparent;
    spacing: 6px;
    color: #1e1a14;
}
QCheckBox::indicator {
    width: 13px;
    height: 13px;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    background: #faf7f2;
}
QCheckBox::indicator:checked {
    background: #7a5c1e;
    border-color: #9b7a2e;
}
QCheckBox::indicator:checked:hover {
    background: #9b7a2e;
}
QCheckBox::indicator:hover {
    border-color: #9a8878;
}
QCheckBox:disabled { color: #9a8878; }

/* ── List Widget ─────────────────────────────────────── */
QListWidget {
    background: #faf7f2;
    border: 1px solid #c4bba8;
    border-radius: 2px;
    outline: none;
}
QListWidget::item {
    padding: 3px 6px;
    border: none;
}
QListWidget::item:selected {
    background: #ddd4bc;
    color: #1e1a14;
}
QListWidget::item:hover {
    background: #e9e2d8;
}

/* ── Table View ──────────────────────────────────────── */
QTableView {
    background: #f5f0e8;
    alternate-background-color: #ede8d8;
    border: none;
    gridline-color: #e4ddd3;
    selection-background-color: #ddd4bc;
    selection-color: #1e1a14;
    outline: none;
}
QTableView::item {
    padding: 2px 6px;
    border: none;
}
QTableView::item:selected {
    background: #ddd4bc;
    color: #1e1a14;
    border-left: 2px solid #7a5c1e;
}
QHeaderView {
    background: #e4ddd3;
    border: none;
}
QHeaderView::section {
    background: #e4ddd3;
    color: #5a4e42;
    border: none;
    border-right: 1px solid #c4bba8;
    border-bottom: 1px solid #c4bba8;
    padding: 4px 6px;
    font-size: 8pt;
    font-weight: bold;
    letter-spacing: 0.5px;
}
QHeaderView::section:hover {
    background: #d8d1c5;
    color: #1e1a14;
}
QHeaderView::section:checked {
    background: #ddd4bc;
}

/* ── Tree Widget ─────────────────────────────────────── */
QTreeWidget {
    background: #f5f0e8;
    alternate-background-color: #ede8d8;
    border: none;
    outline: none;
}
QTreeWidget::item {
    padding: 3px 4px;
}
QTreeWidget::item:selected {
    background: #ddd4bc;
    color: #1e1a14;
}
QTreeWidget::branch {
    background: transparent;
}
QTreeWidget::branch:closed:has-children {
    border-image: none;
    image: none;
}

/* ── Tab Widget ──────────────────────────────────────── */
QTabWidget::pane {
    border: none;
    border-top: 1px solid #c4bba8;
    background: #f5f0e8;
}
QTabBar {
    background: #ede8df;
}
QTabBar::tab {
    background: #ede8df;
    color: #5a4e42;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 6px 14px;
    font-size: 9pt;
}
QTabBar::tab:selected {
    color: #1e1a14;
    border-bottom: 2px solid #7a5c1e;
    background: #f5f0e8;
}
QTabBar::tab:hover {
    color: #1e1a14;
    background: #e9e2d8;
}

/* Default close-button slot — replaced per-tab by a custom QPushButton widget.
   Keep at zero size so no ghost button appears if a tab is added before the
   custom widget is set. */
QTabBar::close-button {
    width: 0;
    height: 0;
    image: none;
    border: none;
    background: transparent;
}

/* ── Splitter ────────────────────────────────────────── */
QSplitter::handle {
    background: #e4ddd3;
}
QSplitter::handle:horizontal { width: 1px; }
QSplitter::handle:vertical   { height: 1px; }
QSplitter::handle:hover {
    background: #7a5c1e;
}

/* ── Scroll Bars ─────────────────────────────────────── */
QScrollBar:vertical {
    background: #f5f0e8;
    width: 8px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #5a3e1e;
    border-radius: 4px;
    min-height: 20px;
}
QScrollBar::handle:vertical:hover { background: #7a5c1e; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: #f5f0e8;
    height: 8px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #5a3e1e;
    border-radius: 4px;
    min-width: 20px;
}
QScrollBar::handle:horizontal:hover { background: #7a5c1e; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }

/* ── Progress Bar ────────────────────────────────────── */
QProgressBar {
    background: #e4ddd3;
    border: none;
    border-radius: 2px;
    text-align: center;
    color: #1e1a14;
    font-size: 8pt;
    max-height: 14px;
}
QProgressBar::chunk {
    background: #7a5c1e;
    border-radius: 2px;
}

/* ── Status Bar ──────────────────────────────────────── */
QStatusBar {
    background: #ede8df;
    border-top: 1px solid #c4bba8;
    color: #5a4e42;
    font-size: 8pt;
}
QStatusBar::item { border: none; }

/* ── Menu Bar ────────────────────────────────────────── */
QMenuBar {
    background: #ede8df;
    color: #1e1a14;
    border-bottom: 1px solid #c4bba8;
    padding: 2px 0;
}
QMenuBar::item {
    background: transparent;
    padding: 4px 10px;
}
QMenuBar::item:selected, QMenuBar::item:pressed {
    background: #e9e2d8;
    color: #1e1a14;
}
QMenu {
    background: #faf7f2;
    border: 1px solid #c4bba8;
    color: #1e1a14;
}
QMenu::item {
    padding: 5px 24px 5px 12px;
}
QMenu::item:selected {
    background: #ddd4bc;
    color: #1e1a14;
}
QMenu::separator {
    height: 1px;
    background: #c4bba8;
    margin: 3px 0;
}

/* ── Text Browser (event detail) ─────────────────────── */
QTextBrowser {
    background: #faf7f2;
    color: #1e1a14;
    border: none;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 9pt;
    selection-background-color: #7a5c1e;
}

/* ── Tool Tips ───────────────────────────────────────── */
QToolTip {
    background: #e4ddd3;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    padding: 4px 8px;
}

/* ── Message Box ─────────────────────────────────────── */
QMessageBox { background: #ede8df; }
QMessageBox QLabel { color: #1e1a14; background: transparent; }
QMessageBox QPushButton { min-width: 70px; }

/* ── Input Dialog ────────────────────────────────────── */
QInputDialog { background: #ede8df; }

/* ── Separator ───────────────────────────────────────── */
QFrame[frameShape="4"], QFrame[frameShape="5"] {
    color: #c4bba8;
    background: #c4bba8;
}

/* ── Search term chip tags ───────────────────────────── */
QWidget#searchTagWidget {
    background: #ddd4bc;
    border: 1px solid #7a5c1e;
    border-radius: 2px;
}
QLabel#searchTag {
    background: transparent;
    color: #5a4e42;
    font-size: 8pt;
    padding: 0px 1px;
}
QPushButton#searchTagRemove {
    background: transparent;
    color: #9a8878;
    border: none;
    padding: 0px;
    font-size: 11pt;
    font-weight: bold;
    min-height: 14px;
    max-height: 16px;
    min-width: 14px;
    max-width: 16px;
}
QPushButton#searchTagRemove:hover {
    color: #a01800;
    background: transparent;
}
"""


def apply_theme(app) -> None:
    """Apply the warm cream/beige theme to a QApplication."""
    from PySide6.QtGui import QFont, QPalette, QColor

    app.setStyleSheet(DARK_QSS)

    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor("#f5f0e8"))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor("#1e1a14"))
    palette.setColor(QPalette.ColorRole.Base,            QColor("#faf7f2"))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor("#ede8df"))
    palette.setColor(QPalette.ColorRole.Text,            QColor("#1e1a14"))
    palette.setColor(QPalette.ColorRole.Button,          QColor("#e4ddd3"))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor("#1e1a14"))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor("#7a5c1e"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link,            QColor("#7a5c1e"))
    palette.setColor(QPalette.ColorRole.ToolTipBase,     QColor("#e4ddd3"))
    palette.setColor(QPalette.ColorRole.ToolTipText,     QColor("#1e1a14"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#9a8878"))
    app.setPalette(palette)

    font = QFont("Segoe UI", 9)
    app.setFont(font)
