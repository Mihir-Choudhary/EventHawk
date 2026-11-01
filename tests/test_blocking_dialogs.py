"""GitHub issue #4: the tool must never sit frozen behind a dialog.

"If one of the included EVTX files has no recorded events, the program hangs
when trying to parse it.  The buttons/ui appear responsive but I can't
effectively do anything else in the software and have to terminate it."

Root cause, reproduced before the fix: an empty EVTX was falsely reported as
missing a record, which raised a modal "Parse Integrity Warning".  A
QMessageBox runs a NESTED event loop and blocks the window until dismissed;
on Windows it can land behind its parent, so the app looks alive but ignores
every click.  On the pre-fix build ONE empty file left the process blocked
indefinitely (killed at 90 s); after the fix it completes in under a second.

These checks pin both halves:
  1. an empty EVTX raises no dialog at all, and the GUI thread never blocks;
  2. every dialog raised automatically at the end of a background job is
     forced to the front, and state is cleaned up BEFORE it blocks.
"""
import os
import sys
import glob
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QEventLoop, QTimer, Qt                  # noqa: E402
from PySide6.QtWidgets import (QApplication, QListWidgetItem,      # noqa: E402
                               QMessageBox)

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def pump(ms):
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def main() -> int:
    from evtx_tool.gui.main_window import MainWindow

    print("=== 1. _warn_blocking forces the dialog to the front ===")
    w = MainWindow()
    seen = {}

    def inspect():
        m = _app.activeModalWidget()
        if isinstance(m, QMessageBox):
            seen["title"] = m.windowTitle()
            seen["on_top"] = bool(m.windowFlags() & Qt.WindowType.WindowStaysOnTopHint)
            seen["visible"] = m.isVisible()
            seen["detail"] = m.detailedText()
            seen["icon"] = m.icon()
            m.done(0)
    QTimer.singleShot(150, inspect)
    w._warn_blocking("Probe", "body", icon=QMessageBox.Icon.Critical, detail="trace")
    check("the dialog is the active modal while it blocks",
          seen.get("title") == "Probe", str(seen.get("title")))
    check("it is marked stay-on-top, so it cannot hide behind the window",
          seen.get("on_top") is True)
    check("it is actually visible", seen.get("visible") is True)
    check("its original severity is kept",
          seen.get("icon") == QMessageBox.Icon.Critical)
    check("its detail text is kept", seen.get("detail") == "trace")

    print("\n=== 2. a parse error cleans up BEFORE it blocks ===")
    w2 = MainWindow()
    w2._worker = object()
    w2._hw_worker = object()
    state = {}

    def fake_warn(title, text, **kw):
        # Captured at the instant the dialog would start blocking.
        state["worker"] = w2._worker
        state["hw_worker"] = w2._hw_worker
        state["title"] = title
        state["icon"] = kw.get("icon")
    w2._warn_blocking = fake_warn
    w2._on_parse_error("boom")
    check("the parse error is still shown", state.get("title") == "Parse Error")
    check("it is shown as Critical, as before",
          state.get("icon") == QMessageBox.Icon.Critical)
    check("the parse worker is released before the dialog blocks",
          state.get("worker") is None)
    check("the Juggernaut worker is released before the dialog blocks",
          state.get("hw_worker") is None)
    check("the Parse button is usable again", w2._btn_parse.isEnabled())

    print("\n=== 3. every automatic end-of-job dialog uses the helper ===")
    import inspect as _inspect
    src = _inspect.getsource(MainWindow)
    for slot in ("_on_parse_error", "_on_analysis_error", "_on_analysis_finished"):
        body = _inspect.getsource(getattr(MainWindow, slot))
        uses_raw = ("QMessageBox.warning(" in body or "QMessageBox.critical(" in body
                    or ".exec()" in body)
        check(f"{slot} raises no un-hardened blocking dialog",
              not uses_raw and "_warn_blocking(" in body)
    check("both Parse Integrity Warnings go through the helper",
          src.count('"Parse Integrity Warning"') >= 2
          and 'QMessageBox.warning(\n                    self, "Parse Integrity Warning"' not in src)
    # Juggernaut feature fetches and the Juggernaut export run on worker
    # threads; their result/error dialogs appear when the job ends, possibly
    # after the user switched away -- the same hazard.
    for slot in ("_on_wifi_jm_events_ready", "_on_wifi_jm_fetch_error",
                 "_on_remote_assist_jm_ready", "_on_remote_assist_jm_error",
                 "_on_computer_norm_jm_ready", "_on_computer_norm_jm_error",
                 "_export_juggernaut", "_export_juggernaut_separate", "_run_jm_export",
                 "_on_ps_finished", "_on_ps_error"):
        body = _inspect.getsource(getattr(MainWindow, slot))
        # Only the Juggernaut export's completion callbacks; the checks before
        # the worker starts answer a click directly.
        if slot == "_export_juggernaut":
            body = body[body.index("def _done"):body.index("self._run_jm_export(")]
        elif slot == "_export_juggernaut_separate":
            body = body[body.index("def _summary"):body.index("def _step")]
        elif slot == "_run_jm_export":
            body = body[body.index("def _on_ok"):body.index("worker.progress.connect")]
        raw = [m for m in ("QMessageBox.information(", "QMessageBox.warning(",
                           "QMessageBox.critical(", ".exec()") if m in body]
        check(f"{slot} raises no un-hardened blocking dialog", not raw, str(raw))

    print("\n=== 4. issue #4 end to end: empty EVTX, nobody clicks anything ===")
    LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    empties = []
    if os.path.isdir(LOGS):
        empties = [p for p in sorted(glob.glob(os.path.join(LOGS, "*.evtx")),
                                     key=os.path.getsize)
                   if os.path.getsize(p) <= 69632]
    if not empties:
        print(f"  (no empty EVTX found under {LOGS!r} — skipped)")
    else:
        for n in (1, 5):
            files = empties[:n]
            w3 = MainWindow()
            for f in files:
                it = QListWidgetItem(os.path.basename(f))
                it.setData(Qt.ItemDataRole.UserRole, f)
                w3._file_list.addItem(it)
            beats, modals = [], []
            last = {"t": time.monotonic()}

            def beat():
                now = time.monotonic()
                beats.append(now - last["t"])
                last["t"] = now
                m = _app.activeModalWidget()
                if m is not None:
                    modals.append(m.windowTitle())
                    m.close()          # unblock so the test itself can finish
            hb = QTimer(); hb.timeout.connect(beat); hb.start(50)
            t0 = time.monotonic()
            w3._on_parse_clicked()
            done = {"ok": False}
            loop = QEventLoop()

            def poll():
                wk = getattr(w3, "_worker", None)
                if w3._btn_parse.isEnabled() and not (wk and wk.isRunning()):
                    done["ok"] = True
                    loop.quit()
            pt = QTimer(); pt.timeout.connect(poll); pt.start(100)
            QTimer.singleShot(60000, loop.quit)
            loop.exec()
            hb.stop(); pt.stop()
            el = time.monotonic() - t0
            check(f"{n} empty file(s): the parse completes", done["ok"],
                  f"{el:.1f}s")
            check(f"{n} empty file(s): no dialog is raised at all", not modals,
                  str(modals))
            check(f"{n} empty file(s): the GUI thread never blocks over 1s",
                  max(beats or [0]) < 1.0, f"worst gap {max(beats or [0]):.2f}s")
            w3.close()

    w.close(); w2.close()
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
