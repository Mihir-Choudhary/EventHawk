"""Stop and Exit never abort the process or strand the window.

Found by Codex in audit-5b (A5B-CANCEL, A5B-PARSE-EXIT, A5B-PREWARM-EXIT):

* Stop during a Juggernaut parse took ~111 s to finish (11 worker processes
  joined one after another with a 10 s timeout each, all blocked writing to a
  queue nobody drained any more), and afterwards Parse stayed disabled for
  good: the worker emits nothing when it was stopped, and only the
  finished/error slots re-enable Parse.
* File > Exit during a Juggernaut parse ended in a native abort (0xC0000409,
  "QThread destroyed while running"): cleanup dropped the only reference to
  the running, parentless parse thread.
* File > Exit while a column-prewarm query ran ended the same way: cancel()
  only set a flag that the running DuckDB query never looks at, the 500 ms
  wait expired and the window was destroyed with its child thread running.

Each case runs in a subprocess so an abort shows as a return code.  The two
parse cases need EVTX_TEST_LOGS (a folder with enough logs that a parse takes
more than a few seconds); without it they are skipped.
"""
import json
import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

CHECKS = []
QT_ABORT = (0xC0000409, -1073740791)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def _evtx_files(root):
    out = []
    for dp, _dn, fn in os.walk(root):
        out += [os.path.join(dp, f) for f in fn if f.lower().endswith(".evtx")]
    return sorted(out)


# ── child cases ──────────────────────────────────────────────────────────────

def child_engine_cancel(logs):
    """Stop the engine once records flow; time from stop() to run() returning."""
    import tempfile
    import threading
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    flowing = threading.Event()
    eng = HeavyweightEngine(parquet_dir=tempfile.mkdtemp(prefix="eh_cancel_"),
                            on_progress=lambda *a: flowing.set())
    res = {}
    th = threading.Thread(target=lambda: res.setdefault("r", eng.run(_evtx_files(logs))))
    th.start()
    flowing.wait(300)
    time.sleep(2.0)
    t = time.monotonic()
    eng.stop()
    th.join(600)
    print(json.dumps({"stop_to_return_s": round(time.monotonic() - t, 2), "joined": not th.is_alive()}))


def _window_with_parse(logs):
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    w.show()
    files = _evtx_files(logs)
    w._last_parsed_files = files
    w._launch_juggernaut_mode(files)
    t0 = time.monotonic()
    while w._progress_bar.value() <= 0 and time.monotonic() - t0 < 300:
        app.processEvents()
        time.sleep(0.05)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 2.0:
        app.processEvents()
        time.sleep(0.02)
    return app, w


def child_cancel_ui(logs):
    """Stop a running parse: the thread ends and Parse is usable again."""
    app, w = _window_with_parse(logs)
    hw = w._hw_worker
    t = time.monotonic()
    w._btn_stop.click()
    ended = None
    parse_on = None
    while time.monotonic() - t < 300:
        app.processEvents()
        time.sleep(0.05)
        if ended is None and not hw.isRunning():
            ended = round(time.monotonic() - t, 2)
        if ended is not None and w._btn_parse.isEnabled():
            parse_on = round(time.monotonic() - t, 2)
            break
        if ended is not None and time.monotonic() - t > ended + 10:
            break
    print(json.dumps({"thread_end_s": ended, "parse_enabled_s": parse_on,
                      "loading_dialog_open": w._hw_loading_dlg is not None,
                      "stop_enabled": w._btn_stop.isEnabled()}))
    w.close()
    for _ in range(50):
        app.processEvents()
        time.sleep(0.02)


def child_exit_parse(logs):
    """File > Exit while the parse runs, ending the way app.py does:
    sys.exit(app.exec()) with the window still referenced, so it is destroyed
    while the interpreter shuts down."""
    from PySide6.QtCore import QTimer
    app, window = _window_with_parse(logs)
    t = time.monotonic()
    QTimer.singleShot(0, window.close)
    rc = app.exec()
    print(json.dumps({"closed": not window.isVisible(), "close_s": round(time.monotonic() - t, 2)}), flush=True)
    sys.exit(rc)


def _slow_prewarm(parent):
    import pyarrow as pa
    from evtx_tool.gui.jm_col_worker import ColValuePrewarmWorker
    table = pa.table({"event_id": pa.array([4624, 4625, 4634], pa.int64())})
    # A subquery hashing a 1e9-row cross join (~20 s): many seconds of DuckDB
    # work inside one execute(), like a GROUP BY on a large dataset.  (A plain
    # count(*) of a cross join is answered without running it.)
    slow = "(SELECT sum(hash(a.range + b.range)) FROM range(10000) a, range(100000) b) > 0"
    return ColValuePrewarmWorker(table, ["event_id"], where_sql=slow, parent=parent)


def child_prewarm_cancel():
    """cancel() must stop a query that is already running inside DuckDB."""
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from PySide6.QtCore import QObject
    owner = QObject()
    w = _slow_prewarm(owner)
    w.start()
    time.sleep(1.0)
    t = time.monotonic()
    w.cancel()
    w.wait(120000)
    print(json.dumps({"cancel_to_end_s": round(time.monotonic() - t, 2)}))
    app.processEvents()


def child_exit_prewarm():
    """Exit while a prewarm query runs, ending the way app.py does."""
    from PySide6.QtCore import QTimer
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    window = mw.MainWindow()
    window.show()
    pw = _slow_prewarm(window)
    window._col_prewarm_workers = (pw,)
    window._track_col_worker(pw)
    pw.start()
    t = time.monotonic()
    QTimer.singleShot(1000, window.close)
    rc = app.exec()
    print(json.dumps({"closed": not window.isVisible(), "close_s": round(time.monotonic() - t - 1, 2)}), flush=True)
    sys.exit(rc)


# ── parent ───────────────────────────────────────────────────────────────────

def run_child(case, *args, timeout=900):
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONIOENCODING="utf-8")
    t = time.monotonic()
    try:
        p = subprocess.run([sys.executable, "-B", os.path.abspath(__file__), "--child", case, *args],
                           capture_output=True, text=True, timeout=timeout, env=env, cwd=ROOT)
    except subprocess.TimeoutExpired as exc:
        # A process that never ends after Exit is a failure, not a test crash.
        print(f"    [{case}] TIMEOUT after {timeout} s; stdout: {(exc.stdout or '')[-300:]!r}", flush=True)
        return -1, {"timeout": True}
    data = {}
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            try:
                data.update(json.loads(line))
            except ValueError:
                pass
    rc = p.returncode
    rc_u = rc & 0xFFFFFFFF
    print(f"    [{case}] rc={rc} ({rc_u:#x}) {round(time.monotonic() - t, 1)} s  {data}", flush=True)
    if rc != 0:
        print("    stderr tail: " + " | ".join(p.stderr.strip().splitlines()[-4:]), flush=True)
    return rc, data


def main() -> int:
    rc, d = run_child("prewarm_cancel")
    check("prewarm cancel() stops a running DuckDB query within 3 s",
          rc == 0 and d.get("cancel_to_end_s", 999) < 3.0, f"rc={rc} {d}")
    rc, d = run_child("exit_prewarm")
    check("Exit while a prewarm query runs: no native abort, window closes",
          rc == 0 and d.get("closed") is True, f"rc={rc} ({rc & 0xFFFFFFFF:#x}) {d}")

    logs = os.environ.get("EVTX_TEST_LOGS", "")
    if os.environ.get("SHUTDOWN_PREWARM_ONLY"):
        logs = ""
    if not logs or len(_evtx_files(logs)) < 50:
        print("EVTX_TEST_LOGS not set (or too few logs): parse cases skipped")
    else:
        rc, d = run_child("engine_cancel", logs)
        check("engine stop() returns within 20 s on the corpus (was ~111 s)",
              rc == 0 and d.get("joined") and d.get("stop_to_return_s", 999) < 20, f"rc={rc} {d}")
        rc, d = run_child("cancel_ui", logs)
        check("Stop during a JM parse: thread ends within 30 s",
              d.get("thread_end_s") is not None and d["thread_end_s"] < 30, str(d))
        check("Stop during a JM parse: Parse is enabled again, wait dialog closed",
              d.get("parse_enabled_s") is not None and d.get("loading_dialog_open") is False, str(d))
        check("Stop during a JM parse: process exits cleanly afterwards", rc == 0,
              f"rc={rc} ({rc & 0xFFFFFFFF:#x})")
        rc, d = run_child("exit_parse", logs, timeout=420)
        check("Exit during a JM parse: no native abort, window closes",
              rc == 0 and d.get("closed") is True, f"rc={rc} ({rc & 0xFFFFFFFF:#x}) {d}")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    if len(sys.argv) > 2 and sys.argv[1] == "--child":
        case = sys.argv[2]
        if case == "engine_cancel":
            child_engine_cancel(sys.argv[3])
        elif case == "cancel_ui":
            child_cancel_ui(sys.argv[3])
        elif case == "exit_parse":
            child_exit_parse(sys.argv[3])
        elif case == "prewarm_cancel":
            child_prewarm_cancel()
        elif case == "exit_prewarm":
            child_exit_prewarm()
        sys.exit(0)
    sys.exit(main())
