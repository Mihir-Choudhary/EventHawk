"""Stopping work really stops it: no stale result, Esc cancels, Clear Files stops the workers.

Gemini audit 12-03 (High): AnalysisRunner emitted a finished result that
arrived after request_stop(), so a stopped analysis replaced the newer one.
12-05 (High): Esc closes a dialog through reject(), which ThreatIntelDialog
and the PowerShell progress dialog did not handle: the run went on.
12-06 (High): Clear Files left a running parse, analysis and PowerShell
extraction going; their results landed on the cleared window.

Expected: each stopped.  Stubs stand in for the workers (no thread starts).
"""
import os
import queue
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QObject, Signal
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])

    from evtx_tool.analysis.analysis_runner import AnalysisRunner
    r = AnalysisRunner()
    r._progress_q, r._result_q = queue.Queue(), queue.Queue()
    r._result_q.put({"iocs": {"x": 1}, "chains": [], "metadata": {}})
    r._process = None
    got = []
    r.finished.connect(lambda *a: got.append(a))
    r.request_stop()
    r._poll()
    check("a result arriving after stop is not emitted", got == [], str(got))

    from evtx_tool.gui.threat_intel_dialog import ThreatIntelDialog
    d = ThreatIntelDialog(None)
    d._cancel_flag[0] = False
    d.reject()
    check("Esc (reject) cancels the threat-intel run", d._cancel_flag[0] is True)

    import evtx_tool.gui.main_window as mw
    pd = mw._PSProgressDialog()
    seen = []
    pd.cancel_requested.connect(lambda: seen.append(1))
    pd.reject()
    check("Esc (reject) cancels the PowerShell extraction", seen == [1] and pd.isVisible() is False or seen == [1])

    class W(QObject):
        finished = Signal(object, object, object, object, object)
        error = Signal(str)
        progress = Signal(object)

        def __init__(self):
            super().__init__()
            self.stopped = False

        def isRunning(self):
            return not self.stopped

        def request_stop(self):
            self.stopped = True

        def wait(self, *_):
            return True

    class R:
        def __init__(self):
            self.stopped = False

        def is_running(self):
            return not self.stopped

        def request_stop(self):
            self.stopped = True

    w = mw.MainWindow()
    try:
        pw, ar, ps = W(), R(), W()
        landed = []
        w._on_parse_finished = lambda *a: landed.append(a)
        w._worker = pw
        pw.finished.connect(w._on_parse_finished)
        w._analysis_runner = ar
        w._ps_worker = ps
        w._on_clear_files()
        pw.finished.emit(1, 2, 3, 4, 5)
        check("Clear Files stops the parse, and its result does not land", pw.stopped and landed == [], str(landed))
        check("Clear Files stops the analysis", ar.stopped)
        check("Clear Files stops the PowerShell extraction", ps.stopped)
        w._ps_worker = None
    finally:
        w.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
