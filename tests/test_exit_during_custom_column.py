"""Exit while a Juggernaut custom column is being computed: quick, clean, no error box.

Found by Claude's Exit checks (2026-11-05): closing the window ran the
Juggernaut cleanup -- which deletes the Parquet folder -- BEFORE waiting for
running threads.  The custom-column worker still reading that folder failed
("No files found"), and its error box ("could not be computed") opened in the
middle of Exit; with nobody to click it, Exit never finished.

Expected: Exit cancels the computation, the window closes within a few
seconds, the process exits 0 with no error box, and the Parquet folder is
removed once nothing reads it.  Synthetic data; the window runs in a child
process (an in-process crash would kill the runner silently).
"""
import os
import subprocess
import sys
import tempfile
import textwrap
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


CHILD = textwrap.dedent(r"""
    import os, sys, time
    sys.path.insert(0, sys.argv[1]); sys.path.insert(0, os.path.join(sys.argv[1], "tests"))
    from datetime import timedelta
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])
    import test_around_pivot as T
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec
    tmp = sys.argv[2]
    evs = [T.ev(r"C:\a\Security.evtx", i + 1, "HOST", T.T0 + timedelta(milliseconds=i), 4624, data={
        "SubjectUserSid": "S-1-5-18", "SubjectUserName": "x", "TargetUserName": f"u{i % 97}",
        "LogonType": "3", "IpAddress": "10.0.0.1"}) for i in range(600_000)]
    table = T.write_jm(evs, tmp)
    boxes = []
    _orig = QMessageBox.exec
    QMessageBox.exec = lambda self: (boxes.append(self.text()), QMessageBox.StandardButton.Ok)[1]
    w = mw.MainWindow()
    w._events = []; w._hw_db_path = tmp
    w._hw_model = ArrowTableModel(table, parquet_dir=tmp, parent=w); w._jm_file_models = []
    w._table.setModel(w._hw_model); w.show()
    marks = {}
    def start():
        w._compute_custom_column(w._hw_model, compile_spec(CustomColumnSpec(col_id=1, title="x", template="{Data[3]}")), False)
        QTimer.singleShot(100, close)
    def close():
        marks["close"] = time.perf_counter(); w.close()
    QTimer.singleShot(300, start)
    QTimer.singleShot(60_000, app.quit)        # safety net: never hang the test
    rc = app.exec()
    print(f"RESULT close_to_exit={time.perf_counter() - marks['close']:.2f} boxes={len(boxes)} "
          f"first_box={boxes[0][:80] if boxes else ''!r}", flush=True)
    sys.exit(rc)
""")


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="exit_cc_")
    t = time.perf_counter()
    try:
        p = subprocess.run([sys.executable, "-c", CHILD, REPO, tmp], capture_output=True, text=True,
                           timeout=300, env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
    except subprocess.TimeoutExpired:
        check("the child process finished", False, "timed out after 300 s")
        return 1
    res = next((l for l in p.stdout.splitlines() if l.startswith("RESULT")), "")
    print(f"  child exit {p.returncode}, wall {time.perf_counter() - t:.1f} s; {res}")
    vals = dict(kv.split("=", 1) for kv in res.split()[1:3]) if res else {}
    check("the process exits 0", p.returncode == 0, f"{p.returncode} ({p.returncode & 0xFFFFFFFF:#x})")
    check("no error box opens during Exit", vals.get("boxes") == "0", res)
    secs = float(vals.get("close_to_exit", "999"))
    check("Exit completes within 5 s of the request", secs <= 5.0, f"{secs:.2f} s")
    check("the Parquet folder is removed after Exit", not os.path.isdir(tmp) or not os.listdir(tmp),
          str(os.listdir(tmp)[:3]) if os.path.isdir(tmp) else "gone")
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
