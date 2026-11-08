"""Switching theme never changes evidence -- only how it is drawn.

The first version of the dark theme recoloured text panes and rich-text labels
by replacing colour codes in their HTML.  An event value that merely looks like
a colour code ("#a01800" in an EventData field) was rewritten with it, and
switching back to Light turned a genuine dark-palette code into a light one.

Now only presentation changes (stylesheets, palettes, item brushes, text
FORMATS); the detail pane is regenerated from the event; rich-text labels get
their colours when they are built.  What must hold, across repeated
Light -> Dark -> Light -> Dark -> Light switches:

  A. synthetic events whose values contain every palette colour code, in
     Normal AND Juggernaut mode: the table's displayed text, the detail pane's
     text, the copied row and CSV / JSON exports are identical at every step,
     while the detail pane really is drawn in the active theme;
  B. real logs, Normal mode: the logon sessions and System Activity windows
     (open during the switch, and opened fresh in Dark), the Advanced Filter
     and Export dialogs, and the PowerShell history tool show the same text in
     both themes, keep no light-only colour in Dark, and the PowerShell
     tool's output files are identical.

Run: QT_QPA_PLATFORM=offscreen python tests/test_dark_theme_evidence.py
     (set EVTX_TEST_LOGS for part B)
"""
import hashlib
import os
import re
import shutil
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import (QApplication, QDialog, QFileDialog, QMessageBox, QLabel,
                                   QTextEdit, QAbstractItemView, QAbstractButton, QWidget)
    from PySide6.QtGui import QTextDocument
    from PySide6.QtCore import Qt, QSettings
    app = QApplication.instance() or QApplication([])
    import test_around_pivot as T
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui import theme

    settings = QSettings("EventHawk", "GUI")
    had, prev = settings.contains(theme._SETTINGS_KEY), settings.value(theme._SETTINGS_KEY)
    tmp = tempfile.mkdtemp(prefix="dark_evidence_")
    patched = {}

    def patch(obj, name, fn):
        patched.setdefault((obj, name), getattr(obj, name))
        setattr(obj, name, fn)

    def pump(sec, until=None):
        end = time.time() + sec
        while time.time() < end:
            app.processEvents(); time.sleep(0.01)
            if until and until():
                return True
        return False

    SWITCHES = ["dark", "light", "dark", "light"]
    light_only = set(theme._DARK_MAP)
    dark_vals = set(theme._DARK_MAP.values())

    try:
        theme.apply_theme(app, "light")
        # ── A. evidence that looks like colour codes, both modes ──────────────
        codes = sorted(light_only)[:12] + sorted(dark_vals)[:12]
        evidence = " ".join(codes)
        evs = [T.ev(r"C:\c\Security.evtx", 1, "HOST-#a01800", T.T0, 4688, "Microsoft-Windows-Security-Auditing",
                    {"Data": {"CommandLine": f"paint.exe {evidence}", "Colour": "#1b1814",
                              "Note": "<span style='color:#a01800'>not markup</span>"}}),
               T.ev(r"C:\c\Security.evtx", 2, "HOST-2", T.T0 + T.FIVE, 4624)]

        for jm in (False, True):
            mode = "Juggernaut" if jm else "Normal"
            print(f"\n=== A. {mode}: evidence values across theme switches ===")
            w = mw.MainWindow()
            M = T.Mode(mw, jm)
            M.load(w, evs)
            model = M.main_source(w)
            w._table.setModel(model) if jm else None
            pump(0.5)
            msgs = []
            patch(w, "_warn_blocking", lambda t, text, **k: msgs.append(text))
            row = next(r for r in range(model.rowCount())
                       if "HOST-#a01800" in str(model.index(r, 4).data() or ""))
            w._table.selectRow(row)
            # Render the selected event through the app's own re-render path
            # (the synthetic Juggernaut load bypasses the selection wiring).
            w._on_detail_mode_toggled(not w._detail_full_mode)
            pump(0.5)

            class _Scope(mw._ExportScopeDialog):
                def exec(self):
                    self._rb_combined.setChecked(True)
                    self._on_ok()
                    return QDialog.DialogCode.Accepted

            def snap(tag):
                cells = [str(model.index(row, c).data() or "") for c in range(model.columnCount())]
                ev = (w._hw_model.get_event(row) if jm else w._active_proxy.get_source_event(row))
                w._copy_event_row(ev)
                copied = QApplication.clipboard().text()
                detail = w._detail_browser.toPlainText()
                outs = {}
                for ext in ("csv", "json"):
                    out = os.path.join(tmp, f"{mode}_{tag}.{ext}")
                    patch(mw, "_ExportScopeDialog", _Scope)
                    patch(QFileDialog, "getSaveFileName", staticmethod(lambda *a, _o=out, **k: (_o, "")))
                    patch(QMessageBox, "information", staticmethod(lambda *a, **k: msgs.append("info")))
                    n0 = len(msgs)
                    w._on_export_clicked()
                    pump(60, lambda: len(msgs) > n0 and os.path.exists(out))
                    pump(0.3)
                    outs[ext] = hashlib.sha256(open(out, "rb").read()).hexdigest() if os.path.exists(out) else None
                return {"cells": cells, "copied": copied, "detail": detail, "exports": outs}

            base = snap("light0")
            check(f"{mode}: the evidence value is shown as it is in the event",
                  "HOST-#a01800" in base["cells"] and evidence in base["detail"] and "#1b1814" in base["detail"],
                  base["detail"][:80])
            check(f"{mode}: both exports were written", all(base["exports"].values()), str(base["exports"]))
            for i, name in enumerate(SWITCHES, 1):
                w._on_theme_changed(name); pump(0.5)
                s = snap(f"{name}{i}")
                drawn = w._detail_browser.toHtml()
                want = theme.COLORS["text"]
                check(f"{mode} switch {i} ({name}): table text, detail text, copied row, CSV and JSON unchanged",
                      s == base, ", ".join(k for k in base if s[k] != base[k]) or "")
                check(f"{mode} switch {i} ({name}): the detail pane is drawn in the {name} theme",
                      want in drawn, want)
            w.close(); pump(0.5)

        # ── B. dialogs on real logs (Normal mode) ─────────────────────────────
        LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
        logs = [os.path.join(LOGS, n) for n in ("Security.evtx", "System.evtx", "Windows PowerShell.evtx")
                if os.path.exists(os.path.join(LOGS, n))]
        if len(logs) < 3:
            print("\n  (no corpus — part B skipped)")
            return finish()
        print("\n=== B. dialogs, real logs, Normal mode ===")
        theme.apply_theme(app, "light")
        w = mw.MainWindow()
        patch(w, "_warn_blocking", lambda *a, **k: None)
        for f in logs:
            w._add_path(f)
        w._on_parse_clicked()
        pump(300, lambda: w._active_proxy is not None and w._active_proxy.rowCount() > 0
             and w._btn_parse.isEnabled())
        pump(2)

        def text_of(root):
            out = []
            for x in [root] + root.findChildren(QWidget):
                if isinstance(x, QLabel):
                    t = x.text()
                    if x.textFormat() == Qt.TextFormat.RichText or (
                            x.textFormat() == Qt.TextFormat.AutoText and "<" in t):
                        d = QTextDocument(); d.setHtml(t); t = d.toPlainText()
                    out.append(t)
                elif isinstance(x, QTextEdit):
                    out.append(x.toPlainText())
                elif isinstance(x, QAbstractButton):
                    out.append(x.text())
                elif isinstance(x, QAbstractItemView) and x.model() is not None:
                    m = x.model()
                    for r in range(min(m.rowCount(), 3000)):
                        out.append("\t".join(str(m.index(r, c).data() or "") for c in range(m.columnCount())))
            return out

        def leftovers(root):
            bad = []
            for x in [root] + root.findChildren(QWidget):
                hits = {h.lower() for h in HEX.findall(x.styleSheet())} & light_only
                if hits:
                    bad.append(f"{type(x).__name__}: {sorted(hits)[:3]}")
            return bad

        # non-modal windows: open in Light, switch while open, reopen in Dark
        for label, opener, attr in (("Logon sessions", w._on_show_logon_sessions, "_logon_sessions_dlg"),
                                    ("System Activity", w._on_show_system_activity, "_system_activity_dlg")):
            opener(); pump(3)
            dlg = getattr(w, attr, None)
            if dlg is None:
                check(f"{label}: window opens", False); continue
            t_light = text_of(dlg)
            for i, name in enumerate(SWITCHES, 1):
                w._on_theme_changed(name); pump(0.5)
                same = text_of(dlg) == t_light
                left = leftovers(dlg) if name == "dark" else []
                check(f"{label}, open during switch {i} ({name}): same text"
                      + (", no light-only colour" if name == "dark" else ""),
                      same and not left, "; ".join(left[:3]))
            dlg.close(); pump(0.5)
            setattr(w, attr, None)
            w._on_theme_changed("dark"); pump(0.3)
            opener(); pump(3)
            dlg2 = getattr(w, attr)
            check(f"{label}, opened in Dark: same text as in Light, no light-only colour",
                  text_of(dlg2) == t_light and not leftovers(dlg2), "; ".join(leftovers(dlg2)[:3]))
            dlg2.close(); pump(0.5)
            setattr(w, attr, None)
            w._on_theme_changed("light"); pump(0.3)

        # modal dialogs: snapshot from inside exec, in each theme
        seen = {}

        def snap_exec(dlg, *a, **k):
            dlg.show(); pump(0.4)
            seen["text"], seen["left"] = text_of(dlg), leftovers(dlg)
            return QDialog.DialogCode.Rejected

        for label, cls, opener in (("Advanced Filter", mw.FilterDialog, w._on_advanced_filter_clicked),
                                   ("Export", mw._ExportScopeDialog, w._on_export_clicked)):
            patch(cls, "exec", snap_exec)
            res = {}
            for name in ("light", "dark", "light"):
                w._on_theme_changed(name); pump(0.3)
                seen.clear(); opener(); pump(0.3)
                res.setdefault(name, []).append((seen.get("text"), seen.get("left")))
            check(f"{label} dialog: same text in Light and Dark",
                  res["light"][0][0] is not None and res["light"][0][0] == res["dark"][0][0] == res["light"][1][0])
            check(f"{label} dialog: no light-only colour in Dark", not res["dark"][0][1], str(res["dark"][0][1][:3]))

        # PowerShell history: run in each theme, compare the window and the files
        ps_out = {}
        for name in ("light", "dark"):
            w._on_theme_changed(name); pump(0.3)
            out = os.path.join(tmp, f"ps_{name}")
            os.makedirs(out)
            patch(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, _o=out, **k: _o))
            patch(QMessageBox, "exec", lambda self, *a, **k: (seen.update(ps_text=self.text()), 0)[1])
            seen.pop("ps_text", None)
            w._on_ps_extract()
            pump(240, lambda: "ps_text" in seen)
            pump(1)
            files = {}
            for dp, _dn, fn in os.walk(out):
                for f in fn:
                    if f.endswith(".xlsx"):
                        continue        # zip container with its own timestamps
                    rel = os.path.relpath(os.path.join(dp, f), out)
                    files[rel] = hashlib.sha256(_without_run_time(os.path.join(dp, f))).hexdigest()
            ps_out[name] = (files, seen.get("ps_text", "").replace(out, "<out>"))
        lf, lt = ps_out["light"]
        df, dt = ps_out["dark"]
        check("PowerShell history: the tool ran and wrote files in both themes", bool(lf) and bool(df),
              f"{len(lf)} / {len(df)} files")
        check("PowerShell history: identical output files in Light and Dark", lf == df,
              ", ".join(sorted(set(lf) ^ set(df)) or [k for k in lf if lf[k] != df.get(k)])[:200])
        check("PowerShell history: identical result text in Light and Dark", lt == dt and bool(lt))
        w.close(); pump(0.5)
    finally:
        for (obj, name), orig in patched.items():
            try:
                setattr(obj, name, orig)
            except Exception:
                pass
        theme.apply_theme(app, "light")
        if had:
            settings.setValue(theme._SETTINGS_KEY, prev)
        else:
            settings.remove(theme._SETTINGS_KEY)
        shutil.rmtree(tmp, ignore_errors=True)
    return finish()


def _without_run_time(path) -> bytes:
    """File bytes with ONLY the writer's own run-time stamp blanked.

    The PowerShell writer stamps when it ran ("Generated :", "Run At :", and
    metadata.timestamp in the JSON); two runs in the same theme differ there
    and nowhere else.  Every other byte is compared.
    """
    data = open(path, "rb").read()
    if path.endswith(".json"):
        import json
        doc = json.loads(data.decode("utf-8"))
        if isinstance(doc.get("metadata"), dict) and "timestamp" in doc["metadata"]:
            doc["metadata"]["timestamp"] = "<run time>"
        return json.dumps(doc, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return re.sub(rb"^(Generated\s*:|Run At\s*:).*$", rb" <run time>", data, flags=re.M)


def finish() -> int:
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
