"""The Normal-mode parse worker belongs to the window (Gemini 12-01, remaining part).

ParseWorker was created without a parent, so the window's own thread checks
(stop every running child at Exit; keep Juggernaut folders until no child
thread runs) could not see it; only the special-case code for self._worker did.
Expected: a parse started from the window runs on a thread the window owns;
starting the next parse releases the finished one (no build-up of old workers,
each holding its parse engine). The worker's run is held/stubbed: no log is
parsed. Synthetic file paths.
"""
import os
import sys
import tempfile
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QThread
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])
    for _n in ("warning", "information", "critical"):
        setattr(QMessageBox, _n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    import evtx_tool.gui.main_window as mw
    import evtx_tool.gui.worker as W
    tmp = tempfile.mkdtemp(prefix="pwo_")
    f = os.path.join(tmp, "Security.evtx")
    open(f, "wb").write(b"\0" * 4096)
    gate = threading.Event()
    real_run = W.ParseWorker.run
    W.ParseWorker.run = lambda self: gate.wait(20)
    try:
        w = mw.MainWindow()
        w._collect_files_report = lambda: ([f], [])
        w._check_volume = lambda files: "normal"
        w._on_parse_clicked()
        T.pump(100)
        first = w._worker
        check("a parse started from the window runs on a thread the window owns",
              first is not None and first.parent() is w and first in w.findChildren(QThread),
              f"parent={first.parent() if first else None}")
        gate.set()
        first.wait(5000)
        T.pump(100)
        gate.clear()
        w._on_parse_clicked()
        T.pump(300)
        from PySide6.QtCore import QEvent
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete)   # what the event loop does; processEvents() does not
        T.pump(50)
        alive = [t for t in w.findChildren(QThread) if isinstance(t, W.ParseWorker)]
        check("the next parse releases the finished worker", first not in alive and len(alive) == 1, f"{len(alive)} owned")
        gate.set()
        w._worker.wait(5000)
        T.pump(100)
        w.close()
        T.pump(200)
    finally:
        W.ParseWorker.run = real_run
        gate.set()
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
