"""Export "Specific files": search the checklist, and export as one file or one per EVTX.

User (2026-11-01): "add a search bar above the checklist that filters the file
list by file name as you type ... Selections must stay checked when the filter
changes ... 'Select all filtered' / 'Clear' buttons.  Add a choice for how
selected EVTX files are exported: one combined file or separate files."
Spec R-9: a selected file with no events is reported, not written as an empty
file.  Normal mode here (Juggernaut: test_jm_export_scope).  Synthetic data.
"""
import csv
import os
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication, QMessageBox, QFileDialog, QInputDialog
    import evtx_tool.gui.main_window as mw

    paths = [rf"C:\case\host{i:02d}\{n}.evtx" for i in range(10) for n in ("Security", "System", "Application")]
    dlg = mw._ExportScopeDialog(paths, None, "separate", 999, None)
    dlg._rb_specific.setChecked(True)
    search = getattr(dlg, "_inp_file_search", None)
    check("a search box sits above the file checklist", search is not None)
    if search is None:
        return finish()
    visible = lambda: [fp for chk, fp in dlg._file_checks if not chk.isHidden()]    # noqa: E731
    search.setText("system")
    check("typing filters the list by file name (case-insensitive)",
          visible() == [p for p in paths if p.endswith("System.evtx")], f"{len(visible())} shown")
    dlg._btn_clear_shown.click()
    check("'Clear shown' unticks only the shown rows",
          dlg.selected_files() == {p for p in paths if not p.endswith("System.evtx")})
    search.setText("secur")
    check("ticks survive a filter change", dlg.selected_files() == {p for p in paths if not p.endswith("System.evtx")})
    dlg._file_checks[0][0].setChecked(False)             # host00 Security
    search.setText("")
    check("an empty search shows every file again", len(visible()) == len(paths))
    check("the count label says shown and selected",
          dlg._lbl_file_count.text() == f"{len(paths)} of {len(paths)} shown, {len(paths) - 11} selected",
          dlg._lbl_file_count.text())
    search.setText("system")
    dlg._btn_select_shown.click()
    check("'Select shown' ticks only the shown rows", len(dlg.selected_files()) == len(paths) - 1)
    check("one combined file is the default", dlg.specific_separate() is False)
    dlg._rb_specific_each.setChecked(True)
    check("'One file per EVTX' can be chosen", dlg.specific_separate() is True)

    # ── per-file export of selected files: one output per source, empty ones reported ──
    out = tempfile.mkdtemp(prefix="exp_pick_")
    w = mw.MainWindow()
    files = [r"C:\a\Security.evtx", r"C:\b\Security.evtx", r"C:\c\Empty.evtx"]
    counts = {files[0]: 3, files[1]: 5, files[2]: 0}
    w._per_file_data = {fp: {"events": [T.ev(fp, i + 1, "HOST", T.T0 + timedelta(seconds=i)) for i in range(n)]}
                        for fp, n in counts.items()}
    saved = {}
    real = (QFileDialog.getExistingDirectory, QInputDialog.getItem, QMessageBox.information)
    QFileDialog.getExistingDirectory = staticmethod(lambda *a, **k: out)
    QInputDialog.getItem = staticmethod(lambda *a, **k: ("CSV", True))
    QMessageBox.information = staticmethod(lambda _p, _t, text, *a, **k: saved.setdefault("msg", text))
    try:
        w._export_separate(files)
    finally:
        QFileDialog.getExistingDirectory, QInputDialog.getItem, QMessageBox.information = real
    written = sorted(os.listdir(out))
    rows = {}
    for f in written:
        with open(os.path.join(out, f), encoding="utf-8-sig") as fh:
            rows[f] = sum(1 for _ in csv.reader(fh)) - 1
    check("one output per selected source with events, distinct names",
          len(written) == 2 and sorted(rows.values()) == [3, 5], f"{rows}")
    msg = saved.get("msg", "")
    check("the empty selected file is reported, not written",
          "Empty.evtx" in msg and "no events" in msg.lower() and not any("Empty" in f for f in written), msg[:200])
    w.close()
    import shutil
    shutil.rmtree(out, ignore_errors=True)
    return finish()


def finish() -> int:
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication(sys.argv)
    sys.exit(main())
