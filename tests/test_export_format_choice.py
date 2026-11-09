"""The export format is chosen in the Export dialog, per backend and scope.

Before, the format was chosen in the Save window's "Save as type" list for one
output file, and in a second prompt for one file per source.  The dialog now
has a Format box.  It offers exactly what each path could already write:

    Normal, one output file ......... HTML, PDF, CSV, JSON, XML
    Normal, one file per source ..... CSV, JSON, HTML, XML
    Juggernaut, one output file ..... HTML, CSV, JSON, XML
    Juggernaut, one file per source . CSV, JSON, HTML, XML

What must hold:

  * every format is shown; the ones a backend/scope cannot write are disabled
    with the reason, and the choice always lands on one it can write;
  * the last choice is remembered (the user's real setting is restored);
  * the Save window offers the chosen format; a name typed without an
    extension gets it, and if that name already exists the user is asked
    before anything is replaced (the Save window never saw that name); a name
    typed with another writable extension keeps it;
  * through the real MainWindow on real logs, each format writes a file that
    really IS that format, in Normal and Juggernaut mode.

The export CONTENT is unchanged by this: evidence/pr11 compares 20 outputs
byte for byte against 022c8d4.

Run: QT_QPA_PLATFORM=offscreen python tests/test_export_format_choice.py
     (set EVTX_TEST_LOGS for the real-export part)
"""
import csv
import json
import os
import shutil
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication, QDialog, QFileDialog, QMessageBox
    from PySide6.QtCore import QSettings
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw

    settings = QSettings("EventHawk", "GUI")
    had, prev = settings.contains(mw._EXPORT_FORMAT_KEY), settings.value(mw._EXPORT_FORMAT_KEY)
    tmp = tempfile.mkdtemp(prefix="exp_fmt_")
    patched = {}

    def patch(obj, name, fn):
        patched.setdefault((obj, name), getattr(obj, name))
        setattr(obj, name, fn)

    try:
        settings.remove(mw._EXPORT_FORMAT_KEY)
        paths = [r"C:\c\hostA\Security.evtx", r"C:\c\hostB\Security.evtx", r"C:\c\hostA\System.evtx"]

        def enabled(dlg):
            return [k for k, rb in dlg._fmt_buttons.items() if rb.isEnabled()]

        print("=== 1. the Format box, Normal mode ===")
        d = mw._ExportScopeDialog(paths, None, "separate", 10, None)
        d.show(); app.processEvents()
        check("all five formats are shown",
              [d._fmt_buttons[k].text() for k, _l, _h in mw._EXPORT_FORMATS]
              == ["HTML report", "PDF report", "CSV", "JSON", "XML"])
        check("HTML is the first-time default", d.selected_format() == "html")
        for rb, want in ((d._rb_view, ["html", "pdf", "csv", "json", "xml"]),
                         (d._rb_combined, ["html", "pdf", "csv", "json", "xml"]),
                         (d._rb_separate, ["html", "csv", "json", "xml"])):
            rb.setChecked(True); app.processEvents()
            check(f"{rb.text().split('  ')[0]}: enabled formats are what it can write",
                  sorted(enabled(d)) == sorted(want), f"{enabled(d)}")
        d._rb_specific.setChecked(True); d._rb_specific_one.setChecked(True); app.processEvents()
        check("Specific files into one file: PDF is available", "pdf" in enabled(d))
        d._fmt_buttons["pdf"].setChecked(True); app.processEvents()
        check("PDF's hint says it is a summary with the first 500 events",
              "first 500 events" in d._lbl_fmt_hint.text(), d._lbl_fmt_hint.text())
        d._rb_specific_each.setChecked(True); app.processEvents()
        check("switching to one file per EVTX moves off PDF to a writable format",
              d.selected_format() in d.available_formats() and d.selected_format() != "pdf",
              d.selected_format())
        check("…and PDF says why it is unavailable",
              not d._fmt_buttons["pdf"].isEnabled() and "one file per source" in d._fmt_buttons["pdf"].toolTip(),
              d._fmt_buttons["pdf"].toolTip())
        d._rb_combined.setChecked(True); d._fmt_buttons["csv"].click(); app.processEvents()
        d._on_ok()
        check("OK returns the chosen format", d.selected_format() == "csv")
        d2 = mw._ExportScopeDialog(paths, None, "separate", 10, None)
        check("the next Export dialog starts on the remembered format", d2.selected_format() == "csv")
        d.close(); d2.close()

        print("\n=== 1b. the hint is never cut off ===")
        def clipped(dlg):
            bad = []
            for rb in (dlg._rb_view, dlg._rb_combined, dlg._rb_separate, dlg._rb_specific):
                rb.setChecked(True); app.processEvents()
                for k in dlg.available_formats():
                    dlg._fmt_buttons[k].setChecked(True); app.processEvents()
                    lab = dlg._lbl_fmt_hint
                    need = lab.heightForWidth(lab.width())
                    if lab.height() < need or lab.geometry().bottom() > lab.parentWidget().height():
                        bad.append(f"{rb.text().split('  ')[0]}/{k}: {lab.height()} < {need}")
            return bad
        for backend in ("normal", "jm"):
            dd = mw._ExportScopeDialog(paths, None, "separate", 10, None, backend=backend)
            dd.show(); app.processEvents()
            bad = clipped(dd)
            check(f"{backend}: every format's hint shows in full in every scope", not bad, "; ".join(bad[:4]))
            dd.close()
        print("\n=== 1c. no format name is cut off (app theme applied) ===")
        from PySide6.QtGui import QImage

        def cut_names(buttons):
            # Draw each button at its real width and with 40 px to spare: ink
            # past the real width in the wide drawing is text the dialog cuts.
            # grab() is in device pixels, so compare at the device pixel ratio.
            bad = []
            for b in buttons:
                w, h = b.width(), b.height()
                b.resize(w + 40, h)
                img = b.grab().toImage().convertToFormat(QImage.Format.Format_RGB32)
                b.resize(w, h)
                dpr = img.devicePixelRatio() or 1.0
                bg = img.pixel(img.width() - 1, img.height() // 2)
                ink = [x for x in range(int(round(w * dpr)), img.width())
                       for y in range(img.height()) if img.pixel(x, y) != bg]
                if ink:
                    bad.append(f"{b.text()} (width {w}, text reaches {(max(ink) + 1) / dpr:.0f})")
            return bad
        from PySide6.QtGui import QFont, QPalette
        from evtx_tool.gui import theme as _theme
        _saved = (app.styleSheet(), QPalette(app.palette()), QFont(app.font()))
        try:
            _theme.apply_theme(app)
            # Every remembered format: the button that starts ticked is the one
            # measured short, so each must be the starting one once.
            for pref in ("html", "pdf", "csv", "json", "xml"):
                settings.setValue(mw._EXPORT_FORMAT_KEY, pref)
                for backend in ("normal", "jm"):
                    dd = mw._ExportScopeDialog(paths, None, "separate", 10, None, backend=backend)
                    dd.show(); app.processEvents()
                    bad = []
                    for k in dd.available_formats():
                        dd._fmt_buttons[k].setChecked(True); app.processEvents()
                        bad += [f"{k} picked: {x}" for x in cut_names(dd._fmt_buttons.values())]
                    check(f"{pref} remembered, {backend}: every format name shows in full whichever is picked",
                          not bad, "; ".join(bad[:3]))
                    dd.close()
            for backend in ("normal", "jm"):
                dd = mw._ExportScopeDialog(paths, None, "separate", 10, None, backend=backend)
                dd.show(); app.processEvents()
                # Same cause, same dialog: "Into one file" starts ticked, and
                # lost its last letter once "One file per EVTX" was picked.
                dd._rb_specific.setChecked(True); app.processEvents()
                pair = (dd._rb_specific_one, dd._rb_specific_each)
                for rb in (dd._rb_specific_each, dd._rb_specific_one):
                    rb.setChecked(True); app.processEvents()
                    bad = cut_names(pair)
                    check(f"{backend}, '{rb.text()}' picked: both output choices show in full", not bad, "; ".join(bad))
                dd.close()
        finally:
            # Leave the app as the rest of this file expects it (unthemed).
            app.setStyleSheet(_saved[0]); app.setPalette(_saved[1]); app.setFont(_saved[2])
        check("the app theme is restored after this section", app.styleSheet() == _saved[0])
        settings.setValue(mw._EXPORT_FORMAT_KEY, "pdf")
        dd = mw._ExportScopeDialog(paths, None, "separate", 10, None)
        dd.show(); app.processEvents()
        lab = dd._lbl_fmt_hint
        check("a dialog that opens on PDF shows its hint in full",
              dd.selected_format() == "pdf" and lab.height() >= lab.heightForWidth(lab.width()),
              f"{lab.height()} vs {lab.heightForWidth(lab.width())}")
        dd.close()

        print("\n=== 2. the Format box, Juggernaut ===")
        settings.setValue(mw._EXPORT_FORMAT_KEY, "pdf")
        j = mw._ExportScopeDialog(paths, None, "separate", 10, None, backend="jm")
        for rb in (j._rb_view, j._rb_combined, j._rb_separate):
            rb.setChecked(True); app.processEvents()
            check(f"Juggernaut {rb.text().split('  ')[0]}: PDF disabled, the other four enabled",
                  sorted(enabled(j)) == ["csv", "html", "json", "xml"], f"{enabled(j)}")
        check("a remembered PDF falls back to a format Juggernaut can write",
              j.selected_format() == "html", j.selected_format())
        check("…and PDF's tooltip says Juggernaut Mode", "Juggernaut Mode" in j._fmt_buttons["pdf"].toolTip())
        j._rb_combined.setChecked(True); j._on_ok()
        check("a fallback the user did not pick is not remembered (PDF stays the choice)",
              str(settings.value(mw._EXPORT_FORMAT_KEY)) == "pdf", str(settings.value(mw._EXPORT_FORMAT_KEY)))
        j.close()

        print("\n=== 3. the Save window ===")
        seen = {}
        typed = {}
        def fake_save(parent, title, default, filt, *a, **k):
            seen["filter"] = filt
            seen["n"] = seen.get("n", 0) + 1
            v = typed["v"]
            return (v.pop(0) if isinstance(v, list) else v), filt
        patch(QFileDialog, "getSaveFileName", staticmethod(fake_save))
        asked = []
        answer = {}
        patch(QMessageBox, "question", staticmethod(
            lambda *a, **k: (asked.append(a[2]), answer["v"])[1]))
        typed["v"] = os.path.join(tmp, "report")
        path, fmt = mw._export_save_path(None, "t", "json", ("csv", "json", "html", "xml"))
        check("the Save window offers the chosen format", seen["filter"] == "JSON (*.json)", seen["filter"])
        check("a name typed without an extension gets it", path.endswith("report.json") and fmt == "json", path)
        check("…and nothing is asked when no such file exists", not asked)
        existing = os.path.join(tmp, "report.json")
        open(existing, "w").write("keep me")
        answer["v"] = QMessageBox.StandardButton.No
        typed["v"] = [os.path.join(tmp, "report"), os.path.join(tmp, "other")]
        seen["n"] = 0
        path, fmt = mw._export_save_path(None, "t", "json", ("json",))
        check("an appended name that already exists is asked about first", len(asked) == 1, asked[:1])
        check("…'No' opens the Save window again (a new name can be typed); the file is left alone",
              seen["n"] == 2 and path.endswith("other.json") and open(existing).read() == "keep me",
              f"save windows {seen['n']}, path {path}")
        typed["v"] = [os.path.join(tmp, "report"), ""]
        path, fmt = mw._export_save_path(None, "t", "json", ("json",))
        check("…and cancelling that Save window cancels the export", path == "")
        typed["v"] = os.path.join(tmp, "report")
        answer["v"] = QMessageBox.StandardButton.Yes
        path, fmt = mw._export_save_path(None, "t", "json", ("json",))
        check("…'Yes' goes ahead with that name", path == existing)
        typed["v"] = os.path.join(tmp, "typed.csv")
        path, fmt = mw._export_save_path(None, "t", "html", ("html", "csv"))
        check("a typed extension the export can write is kept", path.endswith("typed.csv") and fmt == "csv")
        typed["v"] = os.path.join(tmp, "typed.pdf")
        path, fmt = mw._export_save_path(None, "t", "html", ("html", "csv", "json", "xml"))
        check("a typed extension it cannot write gets the chosen one added",
              path.endswith("typed.pdf.html") and fmt == "html", path)
        for (obj, name), orig in list(patched.items()):
            setattr(obj, name, orig)
        patched.clear()

        # ── 4. real exports ──────────────────────────────────────────────────
        LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
        logs = [os.path.join(LOGS, n) for n in ("Setup.evtx", "Windows PowerShell.evtx")
                if os.path.exists(os.path.join(LOGS, n))]
        if len(logs) < 2:
            print("\n  (no corpus — real exports skipped)")
            return finish()

        def valid(path, fmt):
            if not os.path.exists(path):
                return False
            head = open(path, "rb").read(64).lower()
            if fmt == "pdf":
                return head.startswith(b"%pdf")
            if fmt == "json":
                json.load(open(path, encoding="utf-8")); return True
            if fmt == "xml":
                ET.parse(path); return True
            if fmt == "csv":
                rows = list(csv.reader(open(path, encoding="utf-8-sig", newline="")))
                return len(rows) > 1 and rows[0][:2] == ["RecordNumber", "EventRecordID"]
            return b"<html" in head or b"<!doctype html" in head

        choice = {}

        class _Scope(mw._ExportScopeDialog):
            def exec(self):
                self._rb_combined.setChecked(True)
                self._fmt_buttons[choice["fmt"]].setChecked(True)
                self._on_ok()
                return QDialog.DialogCode.Accepted

        msgs = []
        patch(mw, "_ExportScopeDialog", _Scope)
        patch(QMessageBox, "information", staticmethod(lambda *a, **k: msgs.append(a[2] if len(a) > 2 else "")))
        patch(mw.MainWindow, "_warn_blocking", lambda self, t, text, **k: msgs.append(text))
        patch(QMessageBox, "question", staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))

        def pump(sec, until=None):
            end = time.time() + sec
            while time.time() < end:
                app.processEvents(); time.sleep(0.02)
                if until and until():
                    return

        for mode in ("normal", "jm"):
            w = mw.MainWindow()
            if mode == "normal":
                for f in logs:
                    w._add_path(f)
                w._on_parse_clicked()
                pump(300, lambda: w._active_proxy is not None and w._active_proxy.rowCount() > 0
                     and w._btn_parse.isEnabled())
            else:
                w._launch_juggernaut_mode(logs)
                pump(300, lambda: w._hw_model is not None and w._hw_model.rowCount() > 0)
            pump(2)
            fmts = ("html", "pdf", "csv", "json", "xml") if mode == "normal" else ("html", "csv", "json", "xml")
            for fmt in fmts:
                out = os.path.join(tmp, f"{mode}_export")    # no extension typed
                patch(QFileDialog, "getSaveFileName", staticmethod(lambda *a, _o=out, **k: (_o, "")))
                choice["fmt"] = fmt
                n0 = len(msgs)
                w._on_export_clicked()
                pump(240, lambda: len(msgs) > n0)
                pump(1)
                target = f"{out}.{fmt}"
                check(f"{mode}: choosing {fmt.upper()} in the dialog writes a real {fmt.upper()} file",
                      valid(target, fmt), f"{msgs[n0:][:1]}")
                if os.path.exists(target):
                    os.remove(target)
            w.close(); pump(0.5)
    finally:
        for (obj, name), orig in patched.items():
            setattr(obj, name, orig)
        if had:
            settings.setValue(mw._EXPORT_FORMAT_KEY, prev)
        else:
            settings.remove(mw._EXPORT_FORMAT_KEY)
        shutil.rmtree(tmp, ignore_errors=True)
    return finish()


def finish() -> int:
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
