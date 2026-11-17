"""Text colours written into the GUI code are readable in both themes (Gemini 14-01).

The finding listed light-mode IOC rows, analysis status labels, Sentinel detail
rows and dark-mode greys below the WCAG 2.1 AA 4.5:1 text contrast. The theme
palette was fixed earlier; this checks every literal text colour that GUI code
sets itself (style sheets "color: #...", setForeground(QColor("#..."))), against
the light window backgrounds and, mapped the way the dark theme maps it, against
the dark ones. A colour set together with its own background on the same line
is checked against that background instead. Separator lines are not text.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def lum(h):
    h = h.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4   # noqa: E731
    r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    x, y = sorted((lum(a), lum(b)), reverse=True)
    return (x + 0.05) / (y + 0.05)


FG = re.compile(r"""(?<![-\w])color\s*:\s*(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})\b|setForeground\([^)]*?QColor\(\s*["'](#[0-9a-fA-F]{3,6})["']""")
BG = re.compile(r"""background(?:-color)?\s*:\s*(#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3})\b""")
NOT_TEXT = ("sep.setStyleSheet", 'QFrame[frameShape=')


def main() -> int:
    from evtx_tool.gui import theme as T
    dark = lambda h: T._DARK_MAP.get(h.lower(), h)              # noqa: E731
    L = T.LIGHT_COLORS
    backs = [L["bg_main"], L["bg_panel"], L["bg_input"]]
    bad = []
    n = 0
    files = []
    for base in ("evtx_tool/gui", "sentinel/gui"):
        for dp, _, fs in os.walk(os.path.join(ROOT, base)):
            files += [os.path.join(dp, f) for f in fs if f.endswith(".py")]
    for p in files:
        lines = open(p, encoding="utf-8", errors="replace").read().splitlines()
        for i, ln in enumerate(lines, 1):
            if any(t in ln for t in NOT_TEXT) or (i > 1 and 'QFrame[frameShape=' in lines[i - 2]):
                continue
            own_bg = BG.search(ln)
            if own_bg is None and "{" not in ln and "}" not in ln:
                # inside a style-sheet rule: the rule's own background, if any
                a = i - 1
                while a > 0 and "{" not in lines[a - 1] and "}" not in lines[a - 1] and i - a < 15:
                    a -= 1
                b = i
                while b < len(lines) and "}" not in lines[b - 1] and b - i < 15:
                    b += 1
                own_bg = BG.search("\n".join(lines[max(a - 1, 0):b]))
                if a > 0 and ":disabled" in lines[a - 1]:
                    continue      # WCAG 1.4.3 exempts text of inactive controls
            for m in FG.finditer(ln):
                c = m.group(1) or m.group(2)
                n += 1
                pairs = [(c, own_bg.group(1))] if own_bg else [(c, b) for b in backs]
                worst_l = min(ratio(a, b) for a, b in pairs)
                worst_d = min(ratio(dark(a), dark(b)) for a, b in pairs)
                if min(worst_l, worst_d) < 4.5:
                    bad.append(f"{os.path.relpath(p, ROOT)}:{i} {c} light {worst_l:.2f} dark {worst_d:.2f}")
    check(f"every literal text colour in GUI code reaches 4.5:1 in both themes ({n} checked)", not bad, "; ".join(bad)[:900])

    # Sentinel's tier rows set their own foreground and background
    import sentinel.gui.results_tab as R
    for name in ("4", "3"):
        fg, bg = getattr(R, f"_TIER{name}_FG").name(), getattr(R, f"_TIER{name}_BG").name()
        check(f"Sentinel tier {name} rows: {fg} on {bg} >= 4.5:1", ratio(fg, bg) >= 4.5, f"{ratio(fg, bg):.2f}")
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
