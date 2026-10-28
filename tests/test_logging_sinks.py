"""Every EventHawk process writes its log where the user can find it.

Reported by the user: "the logs are not being written".  Measured on beta
(and by Codex audit-2, A4):
  * the GUI log (%LOCALAPPDATA%\\EventHawk\\logs\\eventhawk_gui.log) kept
    WARNING+ only, so a whole session left a start and an exit line: no
    parse, no filter, no export;
  * the error boxes sent the user to "eventhawk_gui.log in the tool folder",
    which is not where it is, and no menu showed the folder;
  * the analysis worker wrote to <code>\\..\\..\\evtx_tool_logs, another folder;
  * Normal and Juggernaut parse worker processes had no log file at all, so a
    warning raised in one was lost when the app has no console.

Each process kind runs here as a real subprocess with LOCALAPPDATA pointed at
a temporary folder (the user's real logs are never touched), raises a marker,
and the marker must be in a file in <LOCALAPPDATA>\\EventHawk\\logs.
"""
import glob
import os
import subprocess
import sys
import tempfile
import textwrap

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run(code, base, timeout=180):
    env = dict(os.environ, LOCALAPPDATA=base, QT_QPA_PLATFORM="offscreen", PYTHONIOENCODING="utf-8")
    script = os.path.join(base, "probe.py")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(f"import sys\nsys.path.insert(0, {REPO!r})\n" + textwrap.dedent(code))
    p = subprocess.run([PY, "-B", script], cwd=base, env=env, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    return p.returncode, (p.stdout + p.stderr)[-1500:]


def logs_text(base):
    out = {}
    for f in glob.glob(os.path.join(base, "EventHawk", "logs", "*.log*")):
        out[os.path.basename(f)] = open(f, encoding="utf-8", errors="replace").read()
    return out


def has(base, marker):
    return [n for n, t in logs_text(base).items() if marker in t]


def main() -> int:
    # 1. The helper that names the folder.
    base = tempfile.mkdtemp(prefix="eh_log_")
    rc, out = run("""
        from evtx_tool.core.logsetup import log_directory
        print("DIR=" + log_directory())
    """, base)
    want = os.path.join(base, "EventHawk", "logs")
    check("log_directory() is <LOCALAPPDATA>\\EventHawk\\logs", rc == 0 and f"DIR={want}" in out, out[-300:])

    # 2. GUI process: INFO reaches the file (WARNING+ only before).
    base = tempfile.mkdtemp(prefix="eh_log_")
    rc, out = run("""
        import logging
        from evtx_tool.gui.app import _setup_gui_logging
        _setup_gui_logging()
        logging.getLogger("probe").info("GUI-INFO-MARK")
        logging.getLogger("probe").warning("GUI-WARN-MARK")
        for h in logging.getLogger().handlers: h.flush()
    """, base)
    check("GUI: an INFO line reaches eventhawk_gui.log", has(base, "GUI-INFO-MARK") == ["eventhawk_gui.log"],
          f"rc={rc} files={has(base, 'GUI-INFO-MARK')} {out[-200:] if rc else ''}")
    check("GUI: a WARNING line reaches eventhawk_gui.log", has(base, "GUI-WARN-MARK") == ["eventhawk_gui.log"])

    # 3. Normal parse worker process (ProcessPool child, initialised by _worker_init).
    base = tempfile.mkdtemp(prefix="eh_log_")
    rc, out = run("""
        import logging, multiprocessing as mp
        def child(repo):
            from evtx_tool.core.engine import _worker_init
            _worker_init(repo)
            logging.getLogger("evtx_tool.core.engine").warning("NORMAL-CHILD-MARK")
        if __name__ == "__main__":
            mp.freeze_support()
            p = mp.get_context("spawn").Process(target=child, args=(sys.path[0],))
            p.start(); p.join(60); print("EXIT", p.exitcode)
    """, base)
    check("Normal parse worker: a warning in the child process reaches a log file",
          bool(has(base, "NORMAL-CHILD-MARK")), f"rc={rc} {out[-300:]}")

    # 4. Juggernaut parse worker process (_hw_worker_loop as a spawned process).
    base = tempfile.mkdtemp(prefix="eh_log_")
    rc, out = run("""
        import logging, multiprocessing as mp
        def child():
            from evtx_tool.core.heavyweight.engine import _hw_worker_loop
            ctx = mp.get_context("spawn")
            q_in, q_out, stop = ctx.Queue(), ctx.Queue(), ctx.Event()
            q_in.put(None)
            _hw_worker_loop(q_in, q_out, stop)
            logging.getLogger("evtx_tool.core.heavyweight.engine").warning("JM-CHILD-MARK")
        if __name__ == "__main__":
            mp.freeze_support()
            p = mp.get_context("spawn").Process(target=child)
            p.start(); p.join(60); print("EXIT", p.exitcode)
    """, base)
    check("Juggernaut parse worker: a warning in the child process reaches a log file",
          bool(has(base, "JM-CHILD-MARK")), f"rc={rc} {out[-300:]}")

    # 5. Analysis worker process.  The marker is unique per run so a file left
    # by an earlier (pre-fix) run cannot make the stray-folder check pass or fail.
    import uuid
    mark = f"ANALYSIS-MARK-{uuid.uuid4().hex}"
    base = tempfile.mkdtemp(prefix="eh_log_")
    rc, out = run(f"""
        import logging
        from evtx_tool.analysis.analysis_worker_proc import _setup_worker_file_logging
        _setup_worker_file_logging()
        logging.getLogger("evtx_tool.analysis").warning("{mark}")
        for h in logging.getLogger().handlers: h.flush()
    """, base)
    check("Analysis worker: its warnings go to the same log folder as the GUI",
          bool(has(base, mark)), f"rc={rc} files in folder: {sorted(logs_text(base))}")
    stray = os.path.join(REPO, "evtx_tool_logs", "eventhawk_gui.log")
    stray_hit = os.path.exists(stray) and mark in open(stray, encoding="utf-8", errors="replace").read()
    check("Analysis worker: nothing goes to evtx_tool_logs beside the code", not stray_hit)

    # 6. The GUI names the real folder and opens it.
    base = tempfile.mkdtemp(prefix="eh_log_")
    rc, out = run("""
        from PySide6.QtWidgets import QApplication
        from PySide6.QtGui import QDesktopServices
        app = QApplication([])
        opened = []
        QDesktopServices.openUrl = staticmethod(lambda url: opened.append(url.toLocalFile()) or True)
        import evtx_tool.gui.main_window as mw
        from evtx_tool.core.logsetup import log_directory
        w = mw.MainWindow()
        acts = [a for a in w.menuBar().findChildren(type(w.menuBar().actions()[0])) if "Open Log Folder" in a.text()]
        if acts:
            acts[0].trigger()
        import os
        print("ACTIONS", len(acts))
        print("OPENED_OK", bool(opened) and os.path.normcase(os.path.normpath(opened[0])) == os.path.normcase(log_directory()))
        w.close()
    """, base)
    check("Help > Open Log Folder exists and opens the log folder", "ACTIONS 1" in out and "OPENED_OK True" in out,
          out[-300:])
    src = open(os.path.join(REPO, "evtx_tool", "gui", "main_window.py"), encoding="utf-8").read()
    check("no message sends the user to the log 'in the tool folder'", "in the tool folder" not in src)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
