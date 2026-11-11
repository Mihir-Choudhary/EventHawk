"""What a user sees: the fixes from the user-experience audit (UX-1, UX-3..UX-11).

Found by driving the app and reading screenshots:
UX-1  After Theme > Dark with an event selected, the Event Detail pane kept the
      light theme's colours (dark values on a dark pane) until another event
      was selected; the ATT&CK tab kept its old colours too.
UX-3  Rows of level LogAlways/Verbose (every event of a Security log) and the
      "#" and Source File columns were drawn at about 3.0:1 contrast.
UX-4  "ATT&CK" read "ATTCK" on the Analysis checkbox and the results tab.
UX-5  The Filter dialog's From/To started at one year ago .. today, so ticking
      Date on older logs showed nothing; dates read dd-MM-yyyy there and
      yyyy-MM-dd in the table.
UX-6  A file that is no event log gave only "failed to fill whole buffer"; a
      .txt was taken into the file list and refused only at Parse.
UX-7  Export preselected "All files combined" while a filter was active, and
      the Save dialog offered no file name.
UX-8  Dark theme: some tactic names were dark on dark.
UX-10 Filter dialog: text boxes without tooltips; "Category" labelled the
      channel box.
UX-11 The event table left a blank strip on its right.
Synthetic events only.
"""
import os
import re
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def lum(c):
    def f(v):
        v /= 255.0
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    return 0.2126 * f(c.red()) + 0.7152 * f(c.green()) + 0.0722 * f(c.blue())


def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QColor
    from PySide6.QtWidgets import QDialog, QFileDialog, QLabel, QLineEdit, QMessageBox, QTextEdit
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui import theme
    from evtx_tool.core.open_errors import explain_open_errors

    w = mw.MainWindow()
    w.resize(1500, 900)
    w.show()
    evs = T.dataset()
    for e in evs[::2]:
        e["level_name"], e["level"] = "LogAlways", 0
    T.Mode(mw, False).load(w, evs)
    T.pump(300)
    try:
        # ── UX-4
        tab_texts = [w._analysis_tabs.tabText(i) for i in range(w._analysis_tabs.count())]
        check("UX-4 the Analysis checkbox reads ATT&CK", w._chk_attack.text() == "ATT&&CK Mapping",
              repr(w._chk_attack.text()))
        check("UX-4 the results tab reads ATT&CK", "ATT&&CK" in tab_texts, repr(tab_texts[:2]))

        # ── UX-11
        check("UX-11 the event table uses its whole width",
              w._table.horizontalHeader().stretchLastSection())

        # ── UX-3 (both themes) and UX-1
        def row_contrasts():
            proxy = w._proxy_model
            worst = 99.0
            for r in range(min(proxy.rowCount(), 12)):
                for c in range(proxy.columnCount()):
                    idx = proxy.index(r, c)
                    fg = idx.data(Qt.ItemDataRole.ForegroundRole)
                    bg = idx.data(Qt.ItemDataRole.BackgroundRole)
                    if fg is None or bg is None:
                        continue
                    fg = fg.color() if hasattr(fg, "color") else QColor(fg)
                    bg = bg.color() if hasattr(bg, "color") else QColor(bg)
                    worst = min(worst, contrast(fg, bg))
            return worst
        worst = row_contrasts()
        check("UX-3 light theme: every table cell is at least 4.5:1", worst >= 4.5, f"lowest {worst:.2f}:1")

        w._table.selectRow(2)
        T.pump(300)
        pane = [x for x in w.findChildren(QTextEdit) if x.isVisible() and x.toPlainText().strip()][0]
        light_text = theme.tc("#1e1a14")
        calls = []
        real_refresh = w._refresh_attack_tab
        w._refresh_attack_tab = lambda: (calls.append(1), real_refresh())[1]
        w._on_theme_changed("dark")
        T.pump(500)
        html = pane.toHtml()
        dark_text = theme.tc("#1e1a14")
        check("UX-1 the selected event is redrawn in the new theme's colours",
              dark_text != light_text and dark_text in html and light_text not in html,
              f"old text colour still used {html.count(light_text)} time(s)")
        check("UX-1 the ATT&CK tab is redrawn too", bool(calls))
        worst = row_contrasts()
        check("UX-3 dark theme: every table cell is at least 4.5:1", worst >= 4.5, f"lowest {worst:.2f}:1")

        # ── UX-8
        base = QColor(theme.tc("#f5f0e8"))
        low = {k: round(contrast(QColor(v), base), 2) for k, v in theme.COLORS.items()
               if k.startswith("ta_") and contrast(QColor(v), base) < 4.5}
        check("UX-8 dark theme: every tactic colour is at least 4.5:1", not low, f"{low}")
        w._on_theme_changed("light")
        T.pump(300)
        base = QColor(theme.tc("#f5f0e8"))
        low = {k: round(contrast(QColor(v), base), 2) for k, v in theme.COLORS.items()
               if k.startswith("ta_") and contrast(QColor(v), base) < 4.5}
        check("UX-8 light theme: every tactic colour is at least 4.5:1", not low, f"{low}")

        # ── UX-5, UX-10: the Filter dialog as the Filter button opens it
        seen = {}

        def look(dlg):
            seen["from"] = dlg._dt_from.dateTime().toString("yyyy-MM-dd HH:mm:ss")
            seen["to"] = dlg._dt_to.dateTime().toString("yyyy-MM-dd HH:mm:ss")
            seen["fmt"] = (dlg._dt_from.displayFormat(), dlg._dt_to.displayFormat(),
                           dlg._de_specific_day.displayFormat())
            seen["no_tip"] = [e.placeholderText() for e in dlg.findChildren(QLineEdit)
                              if e.placeholderText() and not e.toolTip()]
            seen["labels"] = [x.text() for x in dlg.findChildren(QLabel)]
            return 0
        real_exec = mw.FilterDialog.exec
        mw.FilterDialog.exec = look
        try:
            w._on_advanced_filter_clicked()
        finally:
            mw.FilterDialog.exec = real_exec
        from evtx_tool.gui.models import apply_tz
        shown = sorted(apply_tz(e["timestamp"])[:19] for e in evs if e.get("timestamp"))
        check("UX-5 From starts at the first loaded event's day", seen.get("from") == shown[0][:10] + " 00:00:00",
              f"From {seen.get('from')}, first event {shown[0]}")
        check("UX-5 To ends at the last loaded event's day", seen.get("to") == shown[-1][:10] + " 23:59:59",
              f"To {seen.get('to')}, last event {shown[-1]}")
        check("UX-5 dates read year-month-day, as in the table",
              seen.get("fmt") == ("yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"), f"{seen.get('fmt')}")
        check("UX-10 every text box of the Filter dialog has a tooltip", seen.get("no_tip") == [],
              f"{seen.get('no_tip')}")
        check("UX-10 the channel box is labelled Channel",
              "Channel:" in seen.get("labels", []) and "Category:" not in seen.get("labels", []))

        # ── UX-6
        why = explain_open_errors(["failed to read EVTX file header block: failed to fill whole buffer"])
        check("UX-6 a file that is no event log is explained in plain words",
              "not an event log" in why.lower(), repr(why[:80]))
        tmp = tempfile.mkdtemp(prefix="ux_")
        txt = os.path.join(tmp, "notes.txt")
        open(txt, "w").write("notes")
        before = w._file_list.count()
        w._add_path(txt)
        T.pump(100)
        said = " ".join(x.text() for x in w.statusBar().findChildren(QLabel))
        check("UX-6 a file that is not .evtx is not taken into the file list",
              w._file_list.count() == before and "notes.txt" in said, f"status: {said[:90]!r}")

        # ── UX-7
        got = {}

        def scope_look(dlg):
            got.setdefault("scopes", []).append(["view", "combined", "separate", "specific"][dlg._btn_grp.checkedId()])
            return 0
        real_dexec = QDialog.exec
        mw._ExportScopeDialog.exec = scope_look
        try:
            w._on_export_clicked()
            from evtx_tool.core.filters import empty_filter
            w._proxy_model.set_advanced_filter(dict(empty_filter(), event_ids=[4624]))
            T.pump(200)
            w._on_export_clicked()
        finally:
            del mw._ExportScopeDialog.exec
            assert QDialog.exec is real_dexec
        check("UX-7 with no filter the export offers all files", got.get("scopes", [None])[0] == "combined",
              f"{got.get('scopes')}")
        check("UX-7 with a filter active the export offers the current view",
              len(got.get("scopes", [])) == 2 and got["scopes"][1] == "view", f"{got.get('scopes')}")
        names = []
        real_save = QFileDialog.getSaveFileName
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (names.append(a[2] if len(a) > 2 else ""), ("", ""))[1])
        try:
            mw._export_save_path(w, "Export", "csv")
        finally:
            QFileDialog.getSaveFileName = real_save
        check("UX-7 the Save dialog offers a file name",
              bool(names) and re.fullmatch(r"EventHawk_export_\d{8}_\d{6}\.csv", os.path.basename(names[0] or "")),
              f"{names}")
    finally:
        w.close()
        T.pump(200)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
