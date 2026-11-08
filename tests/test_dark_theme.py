"""The dark theme must cover the whole GUI, and switching must be lossless.

The dark theme is derived from the light one: every light hex the GUI uses
has one dark counterpart (theme._DARK_MAP), and stylesheets/colours are
translated through it.  That only works while three things stay true:

  * the map is one-to-one and its dark values never appear as literals in the
    GUI sources -- otherwise translating twice, or translating back to light,
    would corrupt colours;
  * every colour literal in the GUI is classified (mapped, or deliberately the
    same in both themes) -- otherwise a newly added light colour silently
    shows up as a bright patch in dark mode;
  * the result is readable -- text and accents keep enough contrast.

It then switches a real MainWindow Light -> Dark -> Light and checks that no
light colour survives in dark mode, that dialogs opened while dark are dark,
and that returning to Light restores every stylesheet byte-for-byte.

Run: QT_QPA_PLATFORM=offscreen python tests/test_dark_theme.py
"""
import glob, os, re, sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HEX = re.compile(r"#[0-9a-fA-F]{6}\b")

# Colours intentionally identical in both themes (see theme._DARK_MAP).
SAME_IN_BOTH = {
    "#ffffff",                                   # text on accent / Parse fills
    "#4a6830", "#5a8038", "#3a5824", "#6a9840",  # green Parse button
    "#e74c3c", "#e67e22", "#8b949e", "#7f8c8d",  # flat UI score / confidence
    "#888888",                                   # neutral pen
    "#0d1117", "#1c2130", "#2b2b2b", "#e8e8e8",  # already-dark widgets / docstring
    "#1a2a1a", "#2a2200", "#2a1010",             # IOC score row tints
    "#3d2e0a", "#d4a843", "#5a3e0e", "#4fc3f7",  # Juggernaut badge / banner
}


def _lum(h):
    def ch(c):
        c = int(h[c:c + 2], 16) / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * ch(1) + 0.7152 * ch(3) + 0.0722 * ch(5)


def _contrast(a, b):
    la, lb = sorted((_lum(a), _lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    from evtx_tool.gui import theme

    # ── 1. Map integrity ──────────────────────────────────────────────────────
    dark_vals = list(theme._DARK_MAP.values())
    check("dark map is one-to-one", len(dark_vals) == len(set(dark_vals)))

    # theme.py defines the dark values itself, so from it take only the light
    # palette and the light stylesheet.
    literals = {}
    for f in glob.glob(os.path.join(ROOT, "evtx_tool", "gui", "*.py")):
        if os.path.basename(f) == "theme.py":
            continue
        with open(f, encoding="utf-8") as fh:
            for h in HEX.findall(fh.read()):
                literals.setdefault(h.lower(), set()).add(os.path.basename(f))
    for h in HEX.findall(theme.LIGHT_QSS + " ".join(theme.LIGHT_COLORS.values())):
        literals.setdefault(h.lower(), set()).add("theme.py")
    collide = sorted(set(dark_vals) & set(literals))
    check("no dark value is also a colour literal in the GUI sources",
          not collide, f"collisions: {collide}")

    unclassified = sorted(h for h in literals
                          if h not in theme._DARK_MAP and h not in SAME_IN_BOTH)
    check("every GUI colour literal is mapped or deliberately kept",
          not unclassified,
          "add a dark value to theme._DARK_MAP (or to SAME_IN_BOTH here): "
          + ", ".join(f"{h} ({','.join(sorted(literals[h]))})" for h in unclassified))

    once = theme.remap_colors(theme.LIGHT_QSS, True)
    check("translating to dark is idempotent",
          theme.remap_colors(once, True) == once)
    check("translating back restores the light stylesheet exactly",
          theme.remap_colors(once, False) == theme.LIGHT_QSS)
    left = sorted({h.lower() for h in HEX.findall(theme.DARK_QSS)} & set(theme._DARK_MAP))
    check("DARK_QSS contains no light colours", not left, f"{left}")
    check("DARK_COLORS has every key of LIGHT_COLORS",
          set(theme.DARK_COLORS) == set(theme.LIGHT_COLORS))

    # ── 2. Readability ────────────────────────────────────────────────────────
    D = theme.DARK_COLORS
    bg = D["bg_main"]
    for key, need in (("text", 7.0), ("text_dim", 4.5), ("text_muted", 4.5),
                      ("accent", 4.5), ("level_critical", 4.5),
                      ("level_warning", 4.5), ("ioc_found", 4.5),
                      ("chain_medium", 4.5)):
        cr = _contrast(D[key], bg)
        check(f"dark {key} on background >= {need}:1", cr >= need, f"{cr:.2f}:1")
    for bg_key in ("bg_panel", "bg_input", "selected_bg", "bg_alt_row"):
        cr = _contrast(D["text"], D[bg_key])
        check(f"dark text on {bg_key} >= 7:1", cr >= 7.0, f"{cr:.2f}:1")
    cr = _contrast("#ffffff", D["accent"])
    check("white text on dark accent fill >= 3:1", cr >= 3.0, f"{cr:.2f}:1")

    # ── 3. Persistence round-trip (restores the user's real setting) ─────────
    from PySide6.QtCore import QSettings
    s = QSettings("EventHawk", "GUI")
    had = s.contains(theme._SETTINGS_KEY)
    prev = s.value(theme._SETTINGS_KEY)
    try:
        theme.save_theme("dark")
        check("saved theme reads back", theme.saved_theme() == "dark")
        s.setValue(theme._SETTINGS_KEY, "neon")
        check("unknown saved theme falls back to light", theme.saved_theme() == "light")
    finally:
        if had:
            s.setValue(theme._SETTINGS_KEY, prev)
        else:
            s.remove(theme._SETTINGS_KEY)

    # ── 4. Live switch on a real MainWindow ───────────────────────────────────
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    theme.apply_theme(app, "light")
    from evtx_tool.gui import models, heavyweight_model
    from evtx_tool.gui.main_window import MainWindow, EventTimeZoneDialog

    w = MainWindow()
    w.show(); app.processEvents()

    def sheets():
        return {id(x): x.styleSheet() for x in app.allWidgets() if x.styleSheet()}

    light_before = sheets()
    check("light: app stylesheet is the light one", app.styleSheet() == theme.LIGHT_QSS)
    check("light: COLORS are the light palette", theme.COLORS == theme.LIGHT_COLORS)

    w._on_theme_changed("dark"); app.processEvents()
    # the menu action is checked by the click; mirror it like a real click would
    check("dark: app stylesheet is the dark one", app.styleSheet() == theme.DARK_QSS)
    check("dark: COLORS are the dark palette", theme.COLORS == theme.DARK_COLORS)
    check("dark: window background is dark",
          w.palette().window().color().name() == theme.DARK_COLORS["bg_main"],
          w.palette().window().color().name())

    def light_leftovers():
        out = []
        for x in app.allWidgets():
            hits = {h.lower() for h in HEX.findall(x.styleSheet())} & set(theme._DARK_MAP)
            if hits:
                out.append(f"{type(x).__name__}({x.objectName()}): {sorted(hits)[:3]}")
        return out

    lo = light_leftovers()
    check("dark: no widget stylesheet keeps a light colour", not lo, "; ".join(lo[:5]))
    check("dark: normal-mode model rows use dark backgrounds",
          models._BG_NORMAL.name() == theme.DARK_COLORS["bg_main"])
    check("dark: Juggernaut model rows use dark backgrounds",
          heavyweight_model._BG_NORMAL.name() == theme.DARK_COLORS["bg_main"])

    dlg = EventTimeZoneDialog(w)
    dlg.show(); app.processEvents()
    lo = [x for x in light_leftovers() if x]
    check("dark: a dialog opened while dark has no light colours", not lo, "; ".join(lo[:5]))
    check("dark: dialog palette is dark",
          dlg.palette().window().color().name() == theme.DARK_COLORS["bg_main"],
          dlg.palette().window().color().name())
    dlg.close(); dlg.deleteLater(); app.processEvents()

    w._on_theme_changed("light"); app.processEvents()
    after = sheets()
    changed = [k for k, v in light_before.items() if k in after and after[k] != v]
    check("back to light: every stylesheet restored exactly", not changed,
          f"{len(changed)} widget(s) differ")
    check("back to light: app stylesheet is the light one", app.styleSheet() == theme.LIGHT_QSS)
    check("back to light: model colours are light again",
          models._BG_NORMAL.name() == theme.LIGHT_COLORS["bg_main"])
    check("back to light: no event filter left installed", theme._remapper is None)

    w.close()

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
