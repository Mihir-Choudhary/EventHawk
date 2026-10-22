"""Logon Sessions shows it is working, and never strands its wait dialog.

Sessions are built on the GUI thread in both modes (Juggernaut also queries
the shards there): ~0.4 s per 122k events, so a large Security log froze the
window for tens of seconds with nothing to say it was working -- the "looks
hung" experience behind issue #4.  A Please-Wait dialog now covers the build
above _LOGON_BUSY_MIN_ROWS events, and is closed before any message box (the
wait dialog has no close button: left up, it would lock the window).

Needs EVTX_TEST_LOGS (skipped without it).
"""
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QEventLoop, QTimer, Qt                 # noqa: E402
from PySide6.QtWidgets import QApplication, QListWidgetItem, QMessageBox  # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def load(mw, mode, path):
    w = mw.MainWindow()
    it = QListWidgetItem(os.path.basename(path)); it.setData(Qt.ItemDataRole.UserRole, path)
    w._file_list.addItem(it)
    if mode == "jm":
        w._last_parsed_files = [path]; w._launch_juggernaut_mode([path])
    else:
        w._on_parse_clicked()
    loop = QEventLoop(); t0 = time.monotonic()

    def poll():
        wk = getattr(w, "_worker", None); hw = getattr(w, "_hw_worker", None)
        busy = (wk is not None and wk.isRunning()) or (hw is not None and hw.isRunning())
        if (not busy and w._btn_parse.isEnabled()) or time.monotonic() - t0 > 300:
            loop.quit()
    p = QTimer(); p.timeout.connect(poll); p.start(100); loop.exec(); p.stop()
    for _ in range(20):
        _app.processEvents(); time.sleep(0.02)
    return w


def main() -> int:
    logs = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    sec = os.path.join(logs, "Security.evtx")
    if not os.path.exists(sec):
        print(f"no Security.evtx under {logs!r} -- skipped")
        return 0
    import evtx_tool.gui.main_window as mw
    mw.MainWindow._LOGON_BUSY_MIN_ROWS = 1000          # the real log is ~30k events

    real_init = mw._LogonSessionDialog.__init__
    during = {}

    def spy(self, *a, **k):
        owner = k.get("parent")
        dlg = getattr(owner, "_hw_loading_dlg", None) if owner is not None else None
        during["visible"] = bool(dlg is not None and dlg.isVisible())
        real_init(self, *a, **k)
    mw._LogonSessionDialog.__init__ = spy

    for mode in ("normal", "jm"):
        print(f"=== {mode} ===")
        w = load(mw, mode, sec)
        during.clear()
        w._on_show_logon_sessions()
        for _ in range(10):
            _app.processEvents(); time.sleep(0.02)
        check(f"{mode}: the wait dialog is up while sessions are built",
              during.get("visible") is True, str(during))
        check(f"{mode}: it is gone once the browser opens",
              w._hw_loading_dlg is None)
        dlg = getattr(w, "_logon_sessions_dlg", None)
        check(f"{mode}: the session browser opened", dlg is not None and dlg.isVisible())
        if dlg is not None:
            dlg.close()
        w._logon_sessions_dlg = None

        if mode == "jm":
            # Error path: the dataset cannot be read.  The wait dialog must be
            # down BEFORE the message box blocks, or the window is locked.
            at_box = {}

            def sweep():
                m = _app.activeModalWidget()
                if isinstance(m, QMessageBox):
                    at_box["wait_dialog_up"] = w._hw_loading_dlg is not None
                    at_box["text"] = m.text()
                    m.done(0)
            t = QTimer(); t.timeout.connect(sweep); t.start(20)
            w._hw_db_path = os.path.join(logs, "no_such_dataset_dir")
            w._on_show_logon_sessions()
            t.stop()
            check("jm error: the message names the real problem",
                  "manifest" in at_box.get("text", "").lower(), at_box.get("text", "")[:80])
            check("jm error: the wait dialog is down before the message box",
                  at_box.get("wait_dialog_up") is False, str(at_box.get("wait_dialog_up")))
            check("jm error: nothing is left up afterwards", w._hw_loading_dlg is None)
        w.close()

    mw._LogonSessionDialog.__init__ = real_init
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
