"""Line icons for the EventHawk GUI.

One consistent set (24-unit grid, round caps and joins, 1.75 stroke, the
shapes follow the Lucide icon family) replaces the emoji and Unicode glyphs
the buttons used to carry -- those rendered in whatever colour and size the
platform's emoji font chose, and some (the refresh arrow) did not render at
all on a stock Windows install.

Icons are drawn from inline SVG in the active theme's colours, so they need
no image files at run time (the frozen build ships no data folder).  A widget
given an icon through :func:`set_icon` is redrawn when the theme changes.
"""

from __future__ import annotations

import weakref

from .theme import COLORS, add_theme_listener

# ── Shapes ─────────────────────────────────────────────────────────────────────
# Each entry is the inner SVG markup for a 24x24 viewBox.  "{c}" is the colour.
# Shapes that should be solid add fill="{c}" themselves.

_SHAPES: dict[str, str] = {
    "filter": '<path d="M22 3H2l8 9.46V19l4 2v-8.54L22 3z"/>',
    "filter-x": ('<path d="M13.01 3H2l8 9.46V19l4 2v-8.54l.9-1.06"/>'
                 '<path d="m22 3-5 5"/><path d="m17 3 5 5"/>'),
    "sidebar": '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 3v18"/>',
    "file-plus": ('<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7z"/>'
                  '<path d="M14 2v4a2 2 0 0 0 2 2h4"/><path d="M9 15h6"/><path d="M12 12v6"/>'),
    "folder-plus": ('<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9'
                    'A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2z"/>'
                    '<path d="M12 10v6"/><path d="M9 13h6"/>'),
    "x": '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    "refresh": ('<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/>'
                '<path d="M21 3v5h-5"/>'
                '<path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/>'
                '<path d="M8 16H3v5"/>'),
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "plus": '<path d="M5 12h14"/><path d="M12 5v14"/>',
    "pencil": ('<path d="M21.17 6.81a1 1 0 0 0-3.99-3.99L3.84 16.17a2 2 0 0 0-.5.83l-1.32 4.35'
               'a.5.5 0 0 0 .62.62l4.35-1.32a2 2 0 0 0 .83-.5z"/><path d="m15 5 4 4"/>'),
    "play": '<path d="M6 3.5v17a1 1 0 0 0 1.5.86l14-8.5a1 1 0 0 0 0-1.72l-14-8.5A1 1 0 0 0 6 3.5z" fill="{c}"/>',
    "stop": '<rect x="5" y="5" width="14" height="14" rx="2" fill="{c}"/>',
    "download": ('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>'
                 '<path d="m7 10 5 5 5-5"/><path d="M12 15V3"/>'),
    "star": ('<path d="M11.52 2.3a.53.53 0 0 1 .95 0l2.31 4.68a2.12 2.12 0 0 0 1.6 1.16l5.16.76'
             'a.53.53 0 0 1 .3.9l-3.74 3.64a2.12 2.12 0 0 0-.61 1.88l.88 5.14a.53.53 0 0 1-.77.56'
             'l-4.62-2.43a2.12 2.12 0 0 0-1.97 0L6.4 21.01a.53.53 0 0 1-.77-.56l.88-5.14'
             'a2.12 2.12 0 0 0-.61-1.88L2.16 9.8a.53.53 0 0 1 .3-.9l5.16-.76a2.12 2.12 0 0 0 1.6-1.16z"/>'),
    "star-filled": ('<path d="M11.52 2.3a.53.53 0 0 1 .95 0l2.31 4.68a2.12 2.12 0 0 0 1.6 1.16l5.16.76'
                    'a.53.53 0 0 1 .3.9l-3.74 3.64a2.12 2.12 0 0 0-.61 1.88l.88 5.14a.53.53 0 0 1-.77.56'
                    'l-4.62-2.43a2.12 2.12 0 0 0-1.97 0L6.4 21.01a.53.53 0 0 1-.77-.56l.88-5.14'
                    'a2.12 2.12 0 0 0-.61-1.88L2.16 9.8a.53.53 0 0 1 .3-.9l5.16-.76'
                    'a2.12 2.12 0 0 0 1.6-1.16z" fill="{c}"/>'),
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "shield-search": ('<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6'
                      'a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5'
                      'a1 1 0 0 1 1 1z"/><circle cx="11.5" cy="11.5" r="2.5"/><path d="m15 15-1.7-1.7"/>'),
    "chevron-left": '<path d="m15 18-6-6 6-6"/>',
    "chevron-right": '<path d="m9 18 6-6-6-6"/>',
    "chevron-down": '<path d="m6 9 6 6 6-6"/>',
    "inbox": ('<path d="M22 12h-6l-2 3h-4l-2-3H2"/>'
              '<path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89'
              'A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/>'),
    "search-x": ('<path d="m13.5 8.5-5 5"/><path d="m8.5 8.5 5 5"/>'
                 '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>'),
    "pointer": ('<path d="M9.04 9.69a.5.5 0 0 1 .65-.65l11 4.5a.5.5 0 0 1-.07.95l-4.35 1.04'
                'a1 1 0 0 0-.74.74l-1.04 4.35a.5.5 0 0 1-.95.07z"/>'
                '<path d="M14 4.1 12 6"/><path d="m5.1 8-2.9-.8"/><path d="m6 12-1.9 2"/>'
                '<path d="M7.2 2.2 8 5.1"/>'),
    "clock": '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    "circle-play": '<circle cx="12" cy="12" r="10"/><path d="M10 8.5v7l5.5-3.5z"/>',
}

ICON_NAMES = tuple(_SHAPES)


def svg_markup(name: str, color: str, stroke: float = 1.75) -> str:
    """Complete SVG document for icon *name* drawn in *color*."""
    inner = _SHAPES[name].replace("{c}", color)
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" '
            f'fill="none" stroke="{color}" stroke-width="{stroke}" '
            f'stroke-linecap="round" stroke-linejoin="round">{inner}</svg>')


def pixmap(name: str, color: str, size: int = 16, stroke: float = 1.75, gap: int = 0):
    """QPixmap of icon *name*, *size* logical pixels, drawn at 2x for crisp HiDPI.

    *gap* adds transparent space on the right: a button draws its label
    straight after the icon, and Qt has no icon-to-text spacing setting.
    """
    from PySide6.QtCore import QByteArray, QRectF, Qt
    from PySide6.QtGui import QPainter, QPixmap
    from PySide6.QtSvg import QSvgRenderer
    scale = 2
    pm = QPixmap((size + gap) * scale, size * scale)
    pm.fill(Qt.GlobalColor.transparent)
    renderer = QSvgRenderer(QByteArray(svg_markup(name, color, stroke).encode("utf-8")))
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    renderer.render(p, QRectF(0, 0, size * scale, size * scale))
    p.end()
    pm.setDevicePixelRatio(scale)
    return pm


def icon(name: str, color_key: str = "text_dim", size: int = 16, gap: int = 0):
    """QIcon of *name* in the theme colour *color_key*; dimmed when disabled."""
    from PySide6.QtGui import QIcon
    ic = QIcon()
    color = COLORS.get(color_key, color_key)
    ic.addPixmap(pixmap(name, color, size, gap=gap), QIcon.Mode.Normal)
    ic.addPixmap(pixmap(name, color, size, gap=gap), QIcon.Mode.Active)
    ic.addPixmap(pixmap(name, COLORS["text_muted"], size, gap=gap), QIcon.Mode.Disabled)
    return ic


# ── Level markers for the event tables ─────────────────────────────────────────

_DOT_LEVELS = {
    "Critical": "level_critical",
    "Error": "level_error",
    "Audit Failure": "level_error",
    "Warning": "level_warning",
}
_dot_cache: dict = {}


def level_dot(level):
    """Small round marker for a severe level (Critical, Error, Audit Failure,
    Warning) in the theme's level colour; a transparent spacer of the same
    size for every other level, so level names stay aligned.  The level's
    name is always drawn too -- colour is never the only signal."""
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor, QPainter, QPixmap
    key = _DOT_LEVELS.get(str(level or ""))
    color = COLORS[key] if key else None
    pm = _dot_cache.get(color)
    if pm is None:
        scale, size = 2, 10
        pm = QPixmap(size * scale, size * scale)
        pm.fill(Qt.GlobalColor.transparent)
        if color:
            p = QPainter(pm)
            p.setRenderHint(QPainter.RenderHint.Antialiasing)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            d = 7 * scale
            o = (size * scale - d) // 2
            p.drawEllipse(o, o, d, d)
            p.end()
        pm.setDevicePixelRatio(scale)
        _dot_cache[color] = pm
    return pm


# ── Theme-following icons on widgets ───────────────────────────────────────────

_bound: list = []          # (weakref to widget, name, color_key, size, checked_name)
_listener_added = False


def _apply(widget, name, color_key, size, checked_name) -> None:
    from PySide6.QtCore import QSize
    from PySide6.QtGui import QIcon
    has_text = hasattr(widget, "setIconSize") and bool(getattr(widget, "text", lambda: "")())
    gap = 6 if has_text else 0
    ic = icon(name, color_key, size, gap)
    if checked_name:
        on = COLORS.get("accent", color_key)
        ic.addPixmap(pixmap(checked_name, on, size, gap=gap), QIcon.Mode.Normal, QIcon.State.On)
        ic.addPixmap(pixmap(checked_name, on, size, gap=gap), QIcon.Mode.Active, QIcon.State.On)
        ic.addPixmap(pixmap(checked_name, COLORS["text_muted"], size, gap=gap),
                     QIcon.Mode.Disabled, QIcon.State.On)
    widget.setIcon(ic)
    try:
        widget.setIconSize(QSize(size + gap, size))
    except AttributeError:
        pass


def _refresh(_theme=None) -> None:
    alive = []
    for ref, name, color_key, size, checked_name in _bound:
        w = ref()
        if w is None:
            continue
        try:
            _apply(w, name, color_key, size, checked_name)
        except RuntimeError:          # C++ side already deleted
            continue
        alive.append((ref, name, color_key, size, checked_name))
    _bound[:] = alive


def set_icon(widget, name: str, color_key: str = "text_dim", size: int = 16,
             checked_name: str | None = None) -> None:
    """Give *widget* (a button or action) icon *name*, redrawn on theme change.

    *checked_name* is drawn in the accent colour while a checkable button is
    checked (an outline star that fills in, for example).
    """
    global _listener_added
    _apply(widget, name, color_key, size, checked_name)
    for i, (ref, *_rest) in enumerate(_bound):
        if ref() is widget:
            _bound[i] = (ref, name, color_key, size, checked_name)
            break
    else:
        _bound.append((weakref.ref(widget), name, color_key, size, checked_name))
    if not _listener_added:
        add_theme_listener(_refresh)
        _listener_added = True
