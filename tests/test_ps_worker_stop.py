"""Stop and window close also stop a running PowerShell extraction.

Gemini audit 9-11 (Medium): PSWorker's cancel method is request_cancel(),
but the window's Stop button and its close path ask threads for
request_stop() / cancel() / stop(), so a running extraction was never told
to stop and went on writing its files.

Expected: both the Stop button and the close path cancel it.
Synthetic; the worker is made to look running without starting it.
"""
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.ps_worker import PSWorker
    ok = 0
    w = mw.MainWindow()
    try:
        for name, act in (("the Stop button", lambda: w._on_stop_clicked()),
                          ("the close path", lambda: w._stop_running_threads())):
            pw = PSWorker([], tempfile.gettempdir(), parent=w)
            pw.isRunning = lambda: True          # looks running; never started
            w._ps_worker = pw
            act()
            good = pw.is_cancelled
            ok += good
            print(f"  {'PASS' if good else 'FAIL'}  {name} cancels the PowerShell extraction")
            pw.isRunning = lambda: False
            w._ps_worker = None
    finally:
        w.close()
    print(f"{ok}/2 checks passed")
    return 0 if ok == 2 else 1


if __name__ == "__main__":
    sys.exit(main())
