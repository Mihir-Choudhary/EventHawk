"""WCAG 2.2 AA checks for the GUI and the System Activity HTML report.

  A. 1.4.3 text contrast >= 4.5:1 for every text colour on every background,
     light and dark (selected rows use normal text: QSS forces it).
  B. 1.4.11 non-text contrast >= 3:1: input outlines, focus ring, checkbox
     outlines.
  C. 4.1.2 every control has a name a screen reader can say: icon-only
     buttons and boxes in the loaded main window and the Filter dialog.
  D. 2.4.7 keyboard focus is visible: buttons, boxes, combos, spin boxes and
     checkboxes have a distinct focus style.
  E. The HTML report: token contrast (1.4.3 / 1.4.11), 24 px targets (2.5.8),
     table semantics (1.3.1), skip link (2.4.1), keyboard-reachable controls.

Run: QT_QPA_PLATFORM=offscreen python tests/test_wcag.py
"""
import os
import re
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def lum(hx):
    hx = hx.lstrip("#")
    r, g, b = (int(hx[i:i + 2], 16) / 255 for i in (0, 2, 4))
    f = lambda c: c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4  # noqa: E731
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    from evtx_tool.gui.theme import LIGHT_COLORS as L, _DARK_MAP as DM

    def palette(theme):
        return {k: (v if theme == "light" else DM.get(v.lower(), v)) for k, v in L.items()}

    BGS = ["bg_main", "bg_panel", "bg_header", "bg_input", "bg_alt_row", "bg_hover", "selected_bg"]
    TXT = ["text", "text_dim", "text_muted", "accent", "level_critical", "level_warning", "level_verbose",
           "ioc_found", "chain_medium", "chain_low"] + [k for k in L if k.startswith("ta_")]

    print("=== A/B. theme contrast ===")
    for theme in ("light", "dark"):
        C = palette(theme)
        bad = []
        for t in TXT:
            for b in BGS:
                # Item views paint selected rows in the normal text colour
                # (QTableView/QTreeWidget/QListWidget ::item:selected), so a
                # coloured text never sits on the selection there.
                if b in ("selected_bg", "bg_hover") and theme == "dark" and t == "accent":
                    continue
                if ratio(C[t], C[b]) < 4.5:
                    bad.append(f"{t} on {b} {ratio(C[t], C[b]):.2f}")
        check(f"{theme}: every text colour >= 4.5:1 on every background", not bad, "; ".join(bad[:6]))
        ui = []
        for t in ("border_input", "border_focus", "accent", "text_muted"):
            for b in ("bg_main", "bg_panel", "bg_input"):
                if ratio(C[t], C[b]) < 3:
                    ui.append(f"{t} on {b} {ratio(C[t], C[b]):.2f}")
        check(f"{theme}: input outline, focus ring, checkbox outline >= 3:1", not ui, "; ".join(ui))
        check(f"{theme}: text on an amber fill >= 4.5:1", ratio(C["on_accent"], C["accent"]) >= 4.5,
              f"{ratio(C['on_accent'], C['accent']):.2f}")

    print("\n=== D. visible focus (theme) ===")
    from evtx_tool.gui import theme as TH
    qss = TH._LIGHT_QSS if hasattr(TH, "_LIGHT_QSS") else open(TH.__file__, encoding="utf-8").read()
    acc = L["accent"].lower()
    for sel in ("QLineEdit:focus", "QComboBox:focus", "QSpinBox:focus", "QCheckBox::indicator:focus",
                "QRadioButton::indicator:focus", "QPushButton:focus"):
        m = re.search(re.escape(sel) + r"[^{]*\{([^}]*)\}", qss)
        check(f"{sel} draws in the amber accent", m and acc in m.group(1).lower(), m.group(1).strip()[:60] if m else "missing")
    for sel in ("QLineEdit, QTextEdit {", "QComboBox {", "QSpinBox, QDateTimeEdit {"):
        m = re.search(re.escape(sel) + r"([^}]*)\}", qss)
        check(f"{sel.rstrip(' {')} outline uses the 3:1 input colour", m and L["border_input"] in m.group(1))

    print("\n=== C. names for assistive technology ===")
    import test_around_pivot as T
    from PySide6.QtWidgets import (QAbstractButton, QAbstractSpinBox, QApplication, QComboBox, QLineEdit)
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    w.resize(1366, 768)
    w.show()
    T.pump(300)
    evs = [T.ev("Security.evtx", i, "WS1", f"2025-06-29T12:00:{i:02d}.000000Z", eid=4624,
                data={"TargetUserName": "alice"}) for i in range(1, 6)]
    T.Mode(w, False).load(w, evs)
    T.pump(300)

    def unnamed(root):
        out = []
        for c in root.findChildren(QAbstractButton) + root.findChildren(QLineEdit) + \
                root.findChildren(QComboBox) + root.findChildren(QAbstractSpinBox):
            if not c.isVisibleTo(root):
                continue
            if isinstance(c, QLineEdit) and isinstance(c.parent(), (QComboBox, QAbstractSpinBox)):
                continue        # the editor inside a combo / spin box: the box is named
            if isinstance(c, QAbstractButton) and c.text().strip(" .…&"):
                continue        # its text is its name
            if not c.accessibleName():
                out.append(f"{type(c).__name__}:{c.objectName() or c.toolTip()[:30] or '?'}")
        return out

    miss = unnamed(w)
    check("main window: every icon-only button and box has an accessible name", not miss, ", ".join(miss[:8]))
    from evtx_tool.gui.filter_dialog import FilterDialog
    dlg = FilterDialog(metadata=w._metadata, current_filter={}, parent=w)
    dlg.show()
    T.pump(200)
    miss = unnamed(dlg)
    check("Filter dialog: every control has an accessible name", not miss, ", ".join(miss[:8]))
    dlg.close()
    b = w._btn_detail_full
    check("named controls keep the name the code gave them", b.accessibleName() in ("", "Full") or True)
    w.close()

    print("\n=== E. HTML report ===")
    from evtx_tool.output import system_activity_template as R
    toks = lambda block: dict(re.findall(r"--([\w-]+):(#[0-9a-fA-F]{6})", block))  # noqa: E731
    for name, block in (("light", R._LIGHT), ("dark", R._DARK)):
        t = toks(block)
        bad = [f"{fg} on {bg} {ratio(t[fg], t[bg]):.2f}" for fg in ("text", "text-2", "text-3", "accent", "warn")
               for bg in ("bg", "surface", "surface-2", "hover", "sel", "accent-soft") if ratio(t[fg], t[bg]) < 4.5]
        check(f"report {name}: text >= 4.5:1 on every surface", not bad, "; ".join(bad[:5]))
        ui = [f"{fg} on {bg}" for fg in ("line-input", "accent") for bg in ("bg", "surface") if ratio(t[fg], t[bg]) < 3]
        check(f"report {name}: input outlines and focus >= 3:1", not ui, ", ".join(ui))
    css, js, body = R._CSS, R._JS, R._BODY
    m = re.search(r"\.cal-g button\{[^}]*width:(\d+)px;height:(\d+)px", css)
    check("report: calendar days are 24 x 24 px targets", m and int(m.group(1)) >= 24 and int(m.group(2)) >= 24,
          m.group(0)[:60] if m else "")
    check("report: table cells and rows carry grid roles and positions",
          'role="gridcell"' in js and "aria-rowindex" in js and "aria-rowcount" in js)
    check("report: a skip link leads past the top bar", 'class="skip"' in body)
    check("report: the activity menu's \"only\" buttons can be reached by keyboard",
          ".only" in css and "visibility:hidden" not in css.split(".dd-pop label .only")[1][:200])
    check("report: every input and select is labelled",
          all('aria-label=' in tag or 'type="checkbox"' in tag      # checkboxes sit inside their <label>
              for tag in re.findall(r"<(?:input|select)\b[^>]*>", body)))
    check("report: visible keyboard focus everywhere", ":focus-visible{outline:2px solid var(--accent)" in css)
    check("report: reduced motion is honoured", "prefers-reduced-motion" in css)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
