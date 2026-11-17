"""Closing Sentinel stops its work; one Sentinel window at a time (Gemini 12-02).

The Sentinel window had no close handling: its baseline build and analysis
threads had no parent, no way to stop, and replaced QThread.finished with their
own signal (so "the thread has ended" could not be observed). Closing the window
left them running; their results then landed on a hidden window, and EventHawk's
close could not find them to stop. Every menu click also opened another Sentinel
window.

Expected: both workers belong to their tab, keep QThread's own finished signal,
and stop when asked; closing (or Esc) the window stops a running build or
analysis, which delivers no result; EventHawk opens one Sentinel window and
brings it back on the next click. Synthetic; the engine is stubbed.
"""
import os
import sys
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def wait(app, cond, secs=8.0):
    end = time.time() + secs
    while time.time() < end and not cond():
        app.processEvents()
        time.sleep(0.02)
    return cond()


def slow(progress_cb=None, **_):
    for i in range(500):                 # ~10 s unless stopped
        if progress_cb:
            progress_cb("working", i / 500)
        time.sleep(0.02)
    return [], {"events_scored": 0}


def main() -> int:
    from PySide6.QtCore import QThread
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import sentinel.analysis.engine as E
    import sentinel.baseline.builder as B
    import sentinel.analysis.parser as P
    import sentinel.gui.analysis_tab as AT
    import sentinel.gui.baseline_tab as BT
    from sentinel.gui.window import SentinelWindow

    for cls in (AT._AnalysisWorker, BT._BuildWorker):
        check(f"{cls.__name__} keeps QThread's own finished signal", "finished" not in cls.__dict__)
        check(f"{cls.__name__} can be asked to stop", callable(getattr(cls, "request_stop", None)))

    saved = (E.run_analysis, B.build_baseline, P.find_relevant_evtx_files)
    E.run_analysis = lambda paths, bdir, sdir=None, progress_cb=None, **k: slow(progress_cb)
    B.build_baseline = lambda paths, out, sdir=None, progress_cb=None, **k: slow(progress_cb)
    P.find_relevant_evtx_files = lambda folder, progress_cb=None: [Path("x.evtx")]
    try:
        for kind in ("analysis", "build"):
            w = SentinelWindow()
            w.show()
            tab = w._analysis_tab if kind == "analysis" else w._baseline_tab
            if kind == "analysis":
                worker = AT._AnalysisWorker([Path("x.evtx")], Path("B"), None, parent=tab)
            else:
                worker = BT._BuildWorker(Path("in"), Path("out"), None, parent=tab)
            results = []
            sig = getattr(worker, "result", None)
            if sig is not None:
                sig.connect(lambda *a: results.append(a))
            tab._worker = worker
            ended = []
            worker.finished.connect(lambda *a: ended.append(1))
            worker.start()
            wait(app, lambda: worker.isRunning(), 2)
            t0 = time.time()
            w.reject()                       # Esc / close button
            stopped = wait(app, lambda: not worker.isRunning(), 6)
            check(f"{kind}: closing the window stops the running work", stopped, f"{time.time() - t0:.1f}s")
            check(f"{kind}: the thread's end is observable (QThread.finished)", wait(app, lambda: bool(ended), 2))
            check(f"{kind}: a stopped run delivers no result", not results, str(results)[:100])
            check(f"{kind}: the worker belongs to its tab", worker.parent() is tab)
            w.deleteLater()
            app.processEvents()
    finally:
        E.run_analysis, B.build_baseline, P.find_relevant_evtx_files = saved

    from evtx_tool.gui.main_window import MainWindow
    mw = MainWindow()
    mw._launch_sentinel()
    mw._launch_sentinel()
    wins = [c for c in mw.findChildren(SentinelWindow)]
    check("EventHawk opens one Sentinel window, not one per click", len(wins) == 1, str(len(wins)))
    if wins:
        wins[0].close()
        app.processEvents()
        mw._launch_sentinel()
        wins2 = mw.findChildren(SentinelWindow)
        check("after closing it, the menu shows Sentinel again", len(wins2) == 1 and wins2[0].isVisible(), str(len(wins2)))
    for c in mw.findChildren(SentinelWindow):
        c.close()
    mw.close()
    app.processEvents()
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
