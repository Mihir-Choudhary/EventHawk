"""Juggernaut export offers the same scopes as Normal mode (spec R-10).

Found while planning the user's export request (2026-11-01): Juggernaut export
had no scope chooser -- it always wrote the active tab's view, so "Specific
files" (with the new search and the one-file / one-per-EVTX choice) existed
in Normal mode only.  Expected: the same dialog, and each scope writes what it
names: current view, all files combined, one file per source, specific files
in one file or one per EVTX; a selected file with no events is reported, not
written.  Row counts are checked against the synthetic input.  Synthetic data.
"""
import csv
import os
import shutil
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


FILES = {r"C:\a\Security.evtx": 4, r"C:\b\Security.evtx": 6, r"C:\c\System.evtx": 3}


def csv_rows(path):
    with open(path, encoding="utf-8-sig") as fh:
        return sum(1 for _ in csv.reader(fh)) - 1


def main() -> int:
    from PySide6.QtWidgets import QDialog, QFileDialog, QInputDialog
    import evtx_tool.gui.main_window as mw

    evs, rid = [], 0
    for fp, n in FILES.items():
        for i in range(n):
            rid += 1
            evs.append(T.ev(fp, rid, "HOST", T.T0 + timedelta(seconds=rid)))
    w = mw.MainWindow()
    T.Mode(mw, True).load(w, evs)
    w._table.setModel(w._hw_model)
    msgs = []
    w._warn_blocking = lambda title, text, **k: msgs.append(text)

    choice = {}

    class _Scope(mw._ExportScopeDialog):
        def exec(self):
            {"view": self._rb_view, "combined": self._rb_combined, "separate": self._rb_separate,
             "specific": self._rb_specific}[choice["scope"]].setChecked(True)
            for chk, fp in self._file_checks:
                chk.setChecked(fp in choice.get("files", ()))
            (self._rb_specific_each if choice.get("each") else self._rb_specific_one).setChecked(True)
            self._on_ok()
            return QDialog.DialogCode.Accepted

    real = (mw._ExportScopeDialog, QFileDialog.getSaveFileName, QFileDialog.getExistingDirectory, QInputDialog.getItem)
    out = tempfile.mkdtemp(prefix="jm_scope_")
    mw._ExportScopeDialog = _Scope
    QInputDialog.getItem = staticmethod(lambda *a, **k: ("CSV", True))
    QFileDialog.getExistingDirectory = staticmethod(lambda *a, **k: out)

    def run(scope, name=None, files=(), each=False, wait_msgs=1):
        choice.clear(); choice.update(scope=scope, files=set(files), each=each)
        target = os.path.join(out, name) if name else None
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (target, "CSV (*.csv)"))
        n0 = len(msgs)
        w._export_juggernaut()
        T.wait_for(lambda: len(msgs) >= n0 + wait_msgs, 60)
        T.pump(200)
        return msgs[n0:]

    try:
        r = run("view", "view.csv")
        check("current view writes the view", csv_rows(os.path.join(out, "view.csv")) == len(evs), str(r)[:120])
        w._hw_model.set_quick_filters([{"key": "source_file", "value": r"C:\c\System.evtx", "include": True}])
        T.wait_for(lambda: w._hw_model.rowCount() == 3, 30); T.pump(300)
        r = run("combined", "all.csv")
        check("all files combined ignores the view's filter",
              csv_rows(os.path.join(out, "all.csv")) == len(evs), str(r)[:120])
        sel = [r"C:\a\Security.evtx", r"C:\c\System.evtx"]
        r = run("specific", "two.csv", files=sel)
        check("specific files into one file", csv_rows(os.path.join(out, "two.csv")) == 7, str(r)[:120])
        for f in os.listdir(out):
            os.remove(os.path.join(out, f))
        r = run("specific", files=sel, each=True)
        got = {f: csv_rows(os.path.join(out, f)) for f in os.listdir(out)}
        check("specific files one per EVTX: one output per selected source",
              sorted(got.values()) == [3, 4] and len(got) == 2, f"{got} {str(r)[:160]}")
        for f in os.listdir(out):
            os.remove(os.path.join(out, f))
        r = run("separate")
        got = {f: csv_rows(os.path.join(out, f)) for f in os.listdir(out)}
        check("all files separate: three outputs, the two Security.evtx kept apart",
              sorted(got.values()) == [3, 4, 6] and len(got) == 3, f"{got}")
        check("the summary names the folder and the counts",
              r and "13" in r[-1] and out in r[-1], str(r)[:200])
    finally:
        mw._ExportScopeDialog, QFileDialog.getSaveFileName, QFileDialog.getExistingDirectory, QInputDialog.getItem = real
        w.close(); T.pump(100)
        shutil.rmtree(out, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
