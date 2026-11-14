"""
Themes for EventHawk GUI: Light (warm cream, the default) and Dark.

Light aesthetic: Soft ecru / cream — document-reader warmth with professional
contrast. Warm off-white backgrounds, dark amber accents, dark-brown text.

Dark aesthetic: the same warm palette inverted — charcoal-brown backgrounds,
bright amber accents, cream text.

How the dark theme works
------------------------
The light colours are the single source of truth.  Every light hex the GUI
uses has exactly one dark counterpart in ``_DARK_MAP``, so:

* ``COLORS`` is a live dict — ``apply_theme()`` updates it in place, so code
  that reads ``COLORS[...]`` at render time (event detail pane, dialogs)
  follows the active theme automatically.
* Widget stylesheets written with literal light hexes are rewritten to their
  dark equivalents by an application event filter while the dark theme is on.
* ``tc()`` / ``qc()`` translate a light hex for code that builds colours
  directly (table models, per-item foreground/background, rich-text labels).
* Text documents (QTextBrowser / read-only QTextEdit) are recoloured through
  their character, block and table-cell FORMATS, never by rewriting their HTML.

Evidence text is never touched.  Only presentation properties change: a
stylesheet, a palette, an item's brush, a text format's colour.  Rewriting the
HTML of a text pane or a label would also rewrite any value in it that happens
to look like a colour code (``#a01800`` in an event field), and switching back
would turn a genuine dark-palette code into a light one.

The map is one-to-one and its dark values never appear as literals in the GUI
sources, so translating is idempotent and reversible — switching back to
Light restores every colour exactly.
"""

import hashlib
import os
import re
import tempfile

# ── Colour constants (also used by main_window for per-cell colouring) ────────

LIGHT_COLORS = {
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

# ── Dark counterparts ──────────────────────────────────────────────────────────
# Light hex -> dark hex, for every light-design colour used by the GUI.
# Colours not listed are kept as-is in both themes: white, the mid-tone flat
# UI reds/oranges/greys, the green Parse button, and the few widgets that were
# already styled dark (context menus, Juggernaut badge, IOC score tints).
# tests/test_dark_theme.py enforces that this map stays one-to-one and that no
# dark value collides with a colour literal in the GUI sources.

_DARK_MAP = {
    # Backgrounds
    "#f5f0e8": "#1b1814",   # main window
    "#ede8df": "#221e19",   # panels / sidebars
    "#e4ddd3": "#2b2620",   # header bars / buttons
    "#faf7f2": "#15130f",   # inputs
    "#e9e2d8": "#352f27",   # hover
    "#ede8d8": "#201c17",   # alternating row
    "#ddd4bc": "#46391f",   # selection
    "#e8c96e": "#5c4a17",   # bookmarked row
    "#d8d1c5": "#3a332b",   # button hover
    "#ccc5b5": "#463e34",   # button pressed
    "#d0c8b8": "#585040",
    "#c8d0b8": "#505840",
    "#d4c8a8": "#685b3b",
    "#d6cdbf": "#53493a",
    "#dce8f0": "#21303a",
    "#e0d8c4": "#4f4630",
    "#e0d8cc": "#483e30",
    "#e8dcc8": "#4a3e2a",
    "#e8e0cc": "#483f28",
    "#e8e0d0": "#453b28",
    "#f0ead8": "#3c3622",
    "#f3ede3": "#221d16",   # subtle row stripe on input background
    "#f5e0dc": "#37231f",
    "#edf7ed": "#192c19",   # pale green row tint
    # System Activity states (row fills) -- same hue, dark
    "#e3f4e1": "#1f3320",   # On
    "#dde7f7": "#1f2a3d",   # Sleep / Sleep or hibernate
    "#e6dff5": "#2a2340",   # Hibernate
    "#e4eef2": "#1f3036",   # Modern Standby
    "#e8e6e3": "#2e2c29",   # Shut down / Off
    "#f8dcd6": "#3d2420",   # Off (unexpected shutdown)
    "#fbefd2": "#3a3020",   # Locked / Screen saver
    "#fde8e0": "#30211b",   # pale red row tint
    "#fdf5dc": "#332d1d",   # pale yellow row tint
    "#fff3cd": "#3a3421",   # amber row tint
    "#fff8dc": "#322d1c",   # pale yellow row tint
    # Borders
    "#c4bba8": "#4b4339",
    "#b8b0a0": "#6d6556",
    "#c4b898": "#75694b",
    "#b8924a": "#d0a45a",   # focus ring
    # Text
    "#1e1a14": "#e9e2d6",   # main text
    "#5a4e42": "#b5a995",   # dim text
    "#9a8878": "#928473",   # muted text
    "#666666": "#a1a1a1",
    "#3a2a10": "#eed8b5",
    "#5a3e10": "#f2d099",
    "#5a3e1e": "#e3c29e",   # scrollbar handle
    "#5a4030": "#d1b4a2",
    "#6a5a4c": "#b9a899",
    "#6b4e18": "#ebca8d",
    "#8a6c2e": "#d8b978",
    # Accents — #7a5c1e is both accent text and the fill behind white text,
    # so its dark value is a mid amber that reads in both roles.
    "#7a5c1e": "#a8792a",
    "#9b7a2e": "#c09040",
    "#c4a535": "#d6b84a",
    # Event levels / severities
    "#a01800": "#ff6a4d",
    "#c02000": "#ff694b",
    "#c04020": "#e96949",
    "#b03800": "#ff8d57",
    "#7a4c00": "#f0a53a",
    "#7a3a00": "#ffbc80",
    "#8a3c00": "#ffb074",
    "#8a4800": "#ffbc74",
    "#8a4e00": "#ffc274",
    "#6a3e00": "#ffcf8c",
    "#c07000": "#ffb44b",
    # Greens / blues / purples
    "#2e6820": "#7cc56a",
    "#1e5c1e": "#9ce39c",
    "#2a6a2a": "#93d993",
    "#2a5a8a": "#6fa8dd",
    "#1e4d8c": "#73a5e7",
    "#4a6fa5": "#678bc1",
    "#4a7aaa": "#6292c1",
    "#0f6e6e": "#88f4f4",
    "#6a2a8a": "#ba78dc",
    "#6b1e6b": "#e58fe5",
}

_LIGHT_MAP = {v: k for k, v in _DARK_MAP.items()}

THEMES = ("light", "dark")
_SETTINGS_KEY = "ui_theme"
_current = "light"

_HEX_RE = re.compile(r"#[0-9a-fA-F]{6}\b")


def current_theme() -> str:
    """Name of the active theme: ``"light"`` or ``"dark"``."""
    return _current


def is_dark() -> bool:
    return _current == "dark"


_SVG_URL_RE = re.compile(r'url\(\s*"([^"]+?\.svg)"\s*\)', re.IGNORECASE)
_svg_dark_copy: dict = {}   # original image path -> dark copy path
_svg_original: dict = {}    # dark copy path -> original image path


def _dark_svg(path: str) -> str:
    """Path of a copy of the SVG at *path* with its colours mapped to dark.

    Stylesheet images (the date tree's expand arrows) have their colours
    baked into the file, so translating the stylesheet text alone left a
    dark arrow on the dark background.  The copy lives in the temp folder;
    the original file is never modified.  Returns *path* unchanged when the
    file cannot be read or has no theme colours.
    """
    hit = _svg_dark_copy.get(path)
    if hit is not None:
        return hit
    out = path
    try:
        with open(path, encoding="utf-8") as f:
            src = f.read()
        dst = _HEX_RE.sub(lambda m: _DARK_MAP.get(m.group(0).lower(), m.group(0)), src)
        if dst != src:
            folder = os.path.join(tempfile.gettempdir(), "eventhawk_theme_images")
            os.makedirs(folder, exist_ok=True)
            tag = hashlib.sha1(path.encode("utf-8")).hexdigest()[:10]
            target = os.path.join(folder, f"dark_{tag}_{os.path.basename(path)}")
            tmp = f"{target}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(dst)
            os.replace(tmp, target)
            out = target.replace("\\", "/")
    except OSError:
        out = path
    _svg_dark_copy[path] = out
    if out != path:
        _svg_original[out] = path
    return out


def _remap_svg_urls(text: str, dark: bool) -> str:
    if "url(" not in text:
        return text

    def swap(m):
        path = m.group(1)
        new = _dark_svg(path) if dark else _svg_original.get(path, path)
        return m.group(0) if new == path else f'url("{new}")'

    return _SVG_URL_RE.sub(swap, text)


def _ui_image(name: str, svg: str) -> str:
    """Path of a small stylesheet image (combo arrow, check mark), or "".

    Written once to the temp folder: the stylesheet needs a file path and the
    frozen build ships no image folder.  Its colours are light-palette values,
    so the dark stylesheet points at a recoloured copy (see _dark_svg).
    """
    folder = os.path.join(tempfile.gettempdir(), "eventhawk_theme_images")
    path = os.path.join(folder, name)
    try:
        os.makedirs(folder, exist_ok=True)
        current = None
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                current = f.read()
        if current != svg:
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(svg)
            os.replace(tmp, path)
    except OSError:
        return ""
    return path.replace("\\", "/")


_SVG_CHEVRON = ('<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" '
                'fill="none" stroke="#5a4e42" stroke-width="2.5" stroke-linecap="round" '
                'stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>')
_SVG_CHEVRON_UP = _SVG_CHEVRON.replace('d="m6 9 6 6 6-6"', 'd="m18 15-6-6-6 6"')
_SVG_CHECK = ('<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" '
              'fill="none" stroke="#ffffff" stroke-width="3.5" stroke-linecap="round" '
              'stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>')


def remap_colors(text: str, dark: bool) -> str:
    """Translate every light hex in *text* to its dark value (or back).

    SVG images referenced by ``url("...")`` follow too (see _dark_svg).
    """
    table = _DARK_MAP if dark else _LIGHT_MAP
    text = _remap_svg_urls(text, dark)
    return _HEX_RE.sub(lambda m: table.get(m.group(0).lower(), m.group(0)), text)


def tc(light_hex: str) -> str:
    """Colour string for *light_hex* in the active theme."""
    if _current == "dark":
        return _DARK_MAP.get(light_hex.lower(), light_hex)
    return light_hex


def qc(light_hex: str):
    """QColor for *light_hex* in the active theme."""
    from PySide6.QtGui import QColor
    return QColor(tc(light_hex))


COLORS = dict(LIGHT_COLORS)
DARK_COLORS = {k: remap_colors(v, True) for k, v in LIGHT_COLORS.items()}

# ── Master QSS stylesheet ──────────────────────────────────────────────────────

LIGHT_QSS = """
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
    padding: 2px 0px 2px 0px;
    border: none;
}
QLabel#statsLabel {
    color: #5a4e42;
    font-size: 8pt;
}
QLabel#countLabel {
    color: #5a4e42;
    font-size: 8pt;
}
QLabel#countLabel[filtered="true"] {
    color: #7a5c1e;
    font-weight: bold;
}
QLabel#modeChip {
    color: #7a5c1e;
    background: #ddd4bc;
    border-radius: 4px;
    padding: 2px 8px;
    font-size: 8pt;
    font-weight: bold;
}
QPushButton[active="true"] {
    color: #7a5c1e;
    border-color: #7a5c1e;
    background: #ddd4bc;
}
QPushButton[active="true"]:hover {
    background: #d4c8a8;
}

/* ── Radio Buttons ───────────────────────────────────── */
QRadioButton {
    background: transparent;
    color: #1e1a14;
    spacing: 6px;
}
QRadioButton:disabled { color: #9a8878; }

QRadioButton::indicator {
    width: 12px;
    height: 12px;
    border-radius: 7px;
    border: 1px solid #9a8878;
    background: #faf7f2;
}
QRadioButton::indicator:hover {
    border-color: #7a5c1e;
}
QRadioButton::indicator:focus {
    border-color: #b8924a;
}
QRadioButton::indicator:checked {
    width: 6px;
    height: 6px;
    border: 4px solid #7a5c1e;
    background: #faf7f2;
}
QRadioButton::indicator:checked:hover {
    border-color: #9b7a2e;
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
    border-radius: 4px;
    padding: 3px 10px;
    min-height: 22px;
}
QPushButton:hover {
    background: #d8d1c5;
    border-color: #9a8878;
}
QPushButton:focus {
    border-color: #b8924a;
}
QPushButton:pressed {
    background: #ccc5b5;
    border-color: #b8924a;
}
QPushButton:checked {
    background: #ddd4bc;
    border-color: #7a5c1e;
    color: #7a5c1e;
}
QPushButton:disabled {
    color: #9a8878;
    border-color: #d0c8b8;
    background: #ede8df;
}

QPushButton#parseBtn {
    background: #4a6830;
    color: #ffffff;
    border: 1px solid #4a6830;
    border-radius: 4px;
    font-weight: bold;
    min-height: 28px;
    font-size: 9pt;
}
QPushButton#parseBtn:focus {
    border-color: #3a5824;
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
    border-radius: 4px;
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
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 4px;
    min-height: 24px;
}
QPushButton#exportBtn:hover {
    background: #d8d1c5;
    border-color: #9a8878;
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
    border-radius: 4px;
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
    background: #faf7f2;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 4px;
    padding: 3px 8px;
    min-height: 22px;
}
QComboBox:hover {
    border-color: #9a8878;
}
QComboBox:focus, QComboBox:on {
    border-color: #b8924a;
}
QComboBox:disabled {
    color: #9a8878;
    background: #ede8df;
}
QComboBox::drop-down {
    border: none;
    width: 22px;
}
QComboBox::down-arrow {
    @CHEVRON@
    width: 10px;
    height: 10px;
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
    background: #faf7f2;
    color: #1e1a14;
    border: 1px solid #c4bba8;
    border-radius: 4px;
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
QSpinBox::up-arrow, QDateTimeEdit::up-arrow {
    @CHEVRON_UP@
    width: 8px;
    height: 8px;
}
QSpinBox::down-arrow {
    @CHEVRON@
    width: 8px;
    height: 8px;
}
QDateTimeEdit::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 20px;
    border: none;
    background: transparent;
}
QDateTimeEdit::drop-down:hover { background: #d8d1c5; }
QDateTimeEdit::down-arrow {
    @CHEVRON@
    width: 10px; height: 10px;
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
    width: 14px;
    height: 14px;
    border: 1px solid #9a8878;
    border-radius: 3px;
    background: #faf7f2;
}
QCheckBox::indicator:hover {
    border-color: #7a5c1e;
}
QCheckBox::indicator:focus {
    border-color: #b8924a;
}
QCheckBox::indicator:checked {
    background: #7a5c1e;
    border-color: #7a5c1e;
    @CHECK@
}
QCheckBox::indicator:checked:hover {
    background: #9b7a2e;
    border-color: #9b7a2e;
}
QCheckBox::indicator:disabled {
    border-color: #c4bba8;
    background: #ede8df;
}
QCheckBox:disabled { color: #9a8878; }

/* ── List Widget ─────────────────────────────────────── */
QListWidget {
    background: #faf7f2;
    border: 1px solid #c4bba8;
    border-radius: 4px;
    outline: none;
}
QListWidget::item {
    padding: 4px 6px;
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
/* No padding / border rule on table items (QTableView ::item): any such rule makes the
   stylesheet paint every cell itself and drop the cell's own background, so
   bookmarked rows, logon/WiFi/System Activity state fills and IOC score tints
   were never drawn. */
QTableView::item:selected {
    background: #ddd4bc;
    color: #1e1a14;
}
QHeaderView {
    background: #ede8df;
    border: none;
}
QHeaderView::section {
    background: #ede8df;
    color: #5a4e42;
    border: none;
    border-bottom: 1px solid #c4bba8;
    /* A faint edge between header sections: where to drag a column wider,
       or double-click to fit it (the cells themselves stay unruled unless
       View > Grid Lines is on). */
    border-right: 1px solid #d8d1c5;
    padding: 5px 4px;
    font-size: 8pt;
    font-weight: bold;
}
QHeaderView::section:hover {
    background: #e4ddd3;
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
QSplitter::handle:horizontal { width: 4px; }
QSplitter::handle:vertical   { height: 4px; }
QSplitter::handle:hover {
    background: #7a5c1e;
}

/* ── Scroll Bars ─────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #c4bba8;
    border-radius: 3px;
    min-height: 28px;
    margin: 2px;
}
QScrollBar::handle:vertical:hover { background: #9a8878; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QScrollBar:horizontal {
    background: transparent;
    height: 10px;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #c4bba8;
    border-radius: 3px;
    min-width: 28px;
    margin: 2px;
}
QScrollBar::handle:horizontal:hover { background: #9a8878; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }

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
QMenu::item:disabled {
    color: #9a8878;
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

def _with_images(qss: str) -> str:
    chevron = _ui_image("ui_chevron_down.svg", _SVG_CHEVRON)
    check = _ui_image("ui_check.svg", _SVG_CHECK)
    chevron_up = _ui_image("ui_chevron_up.svg", _SVG_CHEVRON_UP)
    qss = qss.replace("@CHEVRON@", f'image: url("{chevron}");' if chevron else "image: none;")
    qss = qss.replace("@CHEVRON_UP@", f'image: url("{chevron_up}");' if chevron_up else "image: none;")
    return qss.replace("@CHECK@", f'image: url("{check}");' if check else "image: none;")


LIGHT_QSS = _with_images(LIGHT_QSS)
DARK_QSS = remap_colors(LIGHT_QSS, True)


# ── Persistence ────────────────────────────────────────────────────────────────

def saved_theme() -> str:
    """Theme stored in QSettings, or ``"light"`` if none/invalid."""
    try:
        from PySide6.QtCore import QSettings
        name = str(QSettings("EventHawk", "GUI").value(_SETTINGS_KEY, "light") or "light")
    except Exception:
        return "light"
    return name if name in THEMES else "light"


def save_theme(name: str) -> None:
    from PySide6.QtCore import QSettings
    QSettings("EventHawk", "GUI").setValue(_SETTINGS_KEY, name)


# ── Change listeners ───────────────────────────────────────────────────────────
# Modules that cache QColor objects (the table models) register a callback to
# rebuild them when the theme changes.

_listeners: list = []


def add_theme_listener(fn) -> None:
    if fn not in _listeners:
        _listeners.append(fn)


def rebuild_on_theme(method):
    """Decorator: run a window's label-building method again after a switch.

    Rich-text labels get their colours from ``tc()`` when they are built and
    are never rewritten afterwards (rewriting a label's string could alter a
    value shown in it).  A window that stays open across a switch therefore
    rebuilds its label from the same inputs: the method is called again with
    the arguments it was last called with.  The listener goes when the window
    is destroyed.
    """
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        store = self.__dict__.setdefault("_eh_theme_rebuild", {})
        store[method.__name__] = (args, kwargs)
        if not self.__dict__.get("_eh_theme_hooked"):
            self.__dict__["_eh_theme_hooked"] = True

            def again(_name=None):
                try:
                    for name, (a, k) in list(store.items()):
                        getattr(self, name)(*a, **k)
                except RuntimeError:          # the window's C++ side is gone
                    remove_theme_listener(again)

            add_theme_listener(again)
            try:
                self.destroyed.connect(lambda *_: remove_theme_listener(again))
            except (AttributeError, RuntimeError):
                pass
        return method(self, *args, **kwargs)
    return wrapper


def remove_theme_listener(fn) -> None:
    if fn in _listeners:
        _listeners.remove(fn)


# ── Stylesheet translation for widgets ─────────────────────────────────────────

_remapper = None
_applied = False


def _make_remapper():
    """Application event filter that rewrites widget stylesheets to dark.

    ``setStyleSheet()`` sends QEvent.StyleChange (and first show sends
    QEvent.Polish), so catching those covers stylesheets set at any time —
    in constructors, in dialogs opened later, and in status-colour updates.
    Only installed while the dark theme is active.
    """
    from PySide6.QtCore import QObject, QEvent
    from PySide6.QtWidgets import QWidget

    watched = (QEvent.Type.StyleChange, QEvent.Type.Polish)

    class _StyleSheetRemapper(QObject):
        _busy = False

        def eventFilter(self, obj, event):
            if event.type() in watched and not self._busy and isinstance(obj, QWidget):
                ss = obj.styleSheet()
                if ss:
                    new = remap_colors(ss, True)
                    if new != ss:
                        self._busy = True
                        try:
                            obj.setStyleSheet(new)
                        finally:
                            self._busy = False
                if event.type() == QEvent.Type.Polish:
                    _watch_text_document(obj)
            return False

    return _StyleSheetRemapper()


# ── Text documents: formats only ───────────────────────────────────────────────

def recolor_document(doc, dark: bool) -> int:
    """Swap theme colours in *doc*'s formats; returns how many were changed.

    Walks character formats (text colour / highlight), block backgrounds and
    table / cell backgrounds and replaces a colour only when it is one of the
    theme's mapped colours.  The ranges are collected first and changed
    afterwards, through QTextCursor merges, so no character of the document
    is ever rewritten -- toPlainText() is identical before and after.
    """
    from PySide6.QtCore import Qt
    from PySide6.QtGui import (QBrush, QColor, QTextBlockFormat, QTextCharFormat,
                               QTextCursor, QTextFormat, QTextTable)
    table = _DARK_MAP if dark else _LIGHT_MAP

    def swapped(fmt, prop):
        if not fmt.hasProperty(prop):
            return None
        b = fmt.brushProperty(prop)
        if b.style() == Qt.BrushStyle.NoBrush:
            return None
        new = table.get(b.color().name())
        if new is None:
            return None
        c = QColor(new)
        c.setAlpha(b.color().alpha())
        return QBrush(c)

    FG, BG = QTextFormat.Property.ForegroundBrush, QTextFormat.Property.BackgroundBrush
    char_edits, block_edits = [], []
    block = doc.begin()
    while block.isValid():
        nb = swapped(block.blockFormat(), BG)
        if nb is not None:
            block_edits.append((block.position(), nb))
        it = block.begin()
        while not it.atEnd():
            frag = it.fragment()
            if frag.isValid():
                cf = frag.charFormat()
                fg, bg = swapped(cf, FG), swapped(cf, BG)
                if fg is not None or bg is not None:
                    char_edits.append((frag.position(), frag.length(), fg, bg))
            it += 1
        block = block.next()

    cell_edits = []

    def walk(frame):
        for child in frame.childFrames():
            if isinstance(child, QTextTable):
                tf = child.format()
                nb = swapped(tf, BG)
                if nb is not None:
                    cell_edits.append((child, None, None, nb))
                for r in range(child.rows()):
                    for c in range(child.columns()):
                        cell = child.cellAt(r, c)
                        nb = swapped(cell.format(), BG)
                        if nb is not None:
                            cell_edits.append((child, r, c, nb))
            walk(child)
    walk(doc.rootFrame())

    if not (char_edits or block_edits or cell_edits):
        return 0
    cur = QTextCursor(doc)
    cur.beginEditBlock()
    try:
        for pos, length, fg, bg in char_edits:
            c = QTextCursor(doc)
            c.setPosition(pos)
            c.setPosition(pos + length, QTextCursor.MoveMode.KeepAnchor)
            f = QTextCharFormat()
            if fg is not None:
                f.setForeground(fg)
            if bg is not None:
                f.setBackground(bg)
            c.mergeCharFormat(f)
        for pos, brush in block_edits:
            c = QTextCursor(doc)
            c.setPosition(pos)
            f = QTextBlockFormat()
            f.setBackground(brush)
            c.mergeBlockFormat(f)
        for tbl, r, col, brush in cell_edits:
            if r is None:
                tf = tbl.format()
                tf.setBackground(brush)
                tbl.setFormat(tf)
            else:
                cell = tbl.cellAt(r, col)
                cf = cell.format()
                cf.setBackground(brush)
                cell.setFormat(cf)
    finally:
        cur.endEditBlock()
    return len(char_edits) + len(block_edits) + len(cell_edits)


def _watch_text_document(widget) -> None:
    """While dark, recolour a text pane's formats whenever its content changes.

    Covers panes filled after the switch (setHtml in a dialog opened later).
    Formats only, as above; the content itself is never rewritten.
    """
    from PySide6.QtWidgets import QTextEdit
    if not isinstance(widget, QTextEdit) or not widget.isReadOnly():
        return
    if widget.property("_eh_theme_watched"):
        return
    widget.setProperty("_eh_theme_watched", True)
    from PySide6.QtCore import QTimer

    def on_change():
        if _current != "dark" or widget.property("_eh_recoloring"):
            return

        def run():
            try:
                widget.setProperty("_eh_recoloring", True)
                recolor_document(widget.document(), True)
            except RuntimeError:
                pass          # widget deleted meanwhile
            finally:
                try:
                    widget.setProperty("_eh_recoloring", False)
                except RuntimeError:
                    pass
        QTimer.singleShot(0, run)
    widget.document().contentsChanged.connect(on_change)
    if _current == "dark":
        on_change()


def _build_palette():
    from PySide6.QtGui import QPalette, QColor
    C = COLORS
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window,          QColor(C["bg_main"]))
    palette.setColor(QPalette.ColorRole.WindowText,      QColor(C["text"]))
    palette.setColor(QPalette.ColorRole.Base,            QColor(C["bg_input"]))
    palette.setColor(QPalette.ColorRole.AlternateBase,   QColor(C["bg_panel"]))
    palette.setColor(QPalette.ColorRole.Text,            QColor(C["text"]))
    palette.setColor(QPalette.ColorRole.Button,          QColor(C["btn_bg"]))
    palette.setColor(QPalette.ColorRole.ButtonText,      QColor(C["text"]))
    palette.setColor(QPalette.ColorRole.Highlight,       QColor(C["accent"]))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Link,            QColor(C["accent"]))
    palette.setColor(QPalette.ColorRole.ToolTipBase,     QColor(C["bg_header"]))
    palette.setColor(QPalette.ColorRole.ToolTipText,     QColor(C["text"]))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(C["text_muted"]))
    return palette


def _retheme_existing(app, dark: bool) -> None:
    """Translate colours already applied to live widgets (runtime switch)."""
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QBrush, QColor
    from PySide6.QtWidgets import (
        QTreeWidget, QTreeWidgetItemIterator, QTableWidget,
        QListWidget, QTextEdit, QAbstractItemView,
    )

    def _swap_brush(get, set_):
        b = get()
        if b.style() != Qt.BrushStyle.NoBrush:
            name = b.color().name()
            new = remap_colors(name, dark)
            if new != name:
                c = QColor(new)
                c.setAlpha(b.color().alpha())
                set_(QBrush(c))

    for w in app.allWidgets():
        ss = w.styleSheet()
        if ss:
            new = remap_colors(ss, dark)
            if new != ss:
                w.setStyleSheet(new)

        if isinstance(w, QTreeWidget):
            it = QTreeWidgetItemIterator(w)
            cols = w.columnCount()
            while it.value():
                item = it.value()
                for c in range(cols):
                    _swap_brush(lambda: item.foreground(c), lambda b: item.setForeground(c, b))
                    _swap_brush(lambda: item.background(c), lambda b: item.setBackground(c, b))
                it += 1
        elif isinstance(w, QTableWidget):
            for r in range(w.rowCount()):
                for c in range(w.columnCount()):
                    item = w.item(r, c)
                    if item is not None:
                        _swap_brush(item.foreground, item.setForeground)
                        _swap_brush(item.background, item.setBackground)
        elif isinstance(w, QListWidget):
            for r in range(w.count()):
                item = w.item(r)
                _swap_brush(item.foreground, item.setForeground)
                _swap_brush(item.background, item.setBackground)
        elif isinstance(w, QTextEdit) and w.isReadOnly():
            # Formats only -- the pane's text is never rewritten.  Rich-text
            # QLabels are deliberately not touched: their colours come from
            # tc() when they are built, and rewriting a label's string could
            # alter a value shown in it.
            recolor_document(w.document(), dark)

        if isinstance(w, QAbstractItemView):
            w.viewport().update()


def apply_theme(app, theme: str | None = None) -> None:
    """Apply *theme* (default: the saved one) to a QApplication.

    Safe to call again at runtime to switch themes live.
    """
    global _current, _remapper, _applied
    from PySide6.QtGui import QFont

    name = theme if theme in THEMES else saved_theme()
    first = not _applied
    if not first and name == _current:
        return
    dark = name == "dark"

    _current = name
    COLORS.clear()
    COLORS.update(DARK_COLORS if dark else LIGHT_COLORS)

    if dark and _remapper is None:
        _remapper = _make_remapper()
        app.installEventFilter(_remapper)
    elif not dark and _remapper is not None:
        app.removeEventFilter(_remapper)
        _remapper = None

    app.setStyleSheet(DARK_QSS if dark else LIGHT_QSS)
    app.setPalette(_build_palette())

    if first:
        app.setFont(QFont("Segoe UI", 9))
        _applied = True
    else:
        _retheme_existing(app, dark)

    for fn in list(_listeners):
        try:
            fn(name)
        except Exception:
            import logging
            logging.getLogger(__name__).exception("theme listener failed")
