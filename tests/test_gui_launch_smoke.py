"""The application must actually start.

Every other suite imports pieces of the app; none of them proves the real
entrypoint runs. That gap is how a tree with 300+ passing checks could still
fail to launch on the user's machine -- which happened once already, and cost
the user's trust rather than just a bug report.

This runs the REAL `eventhawk_gui.py` with `QApplication.exec` patched to pump
events for a few seconds and return, so the entrypoint executes end to end
instead of blocking. It asserts a MainWindow was constructed and shown and that
nothing reached the excepthook.

Headless (offscreen) proves the CODE starts. It cannot prove the user's Qt
platform plugins are installed -- for that, run it without QT_QPA_PLATFORM on a
real display.

Run: QT_QPA_PLATFORM=offscreen python tests/test_gui_launch_smoke.py
"""
import os, sys, time, runpy, traceback, threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SETTLE_SECONDS = 5.0


def main() -> int:
    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    errs = []
    _orig = sys.excepthook
    def _hook(t, v, tb):
        errs.append(f"{t.__name__}: {v}")
        _orig(t, v, tb)
    sys.excepthook = _hook
    threading.excepthook = lambda a: errs.append(f"[thread] {a.exc_type.__name__}: {a.exc_value}")

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])

    pumped = {"n": 0}
    def fake_exec(self=None, *a, **k):
        end = time.time() + SETTLE_SECONDS
        while time.time() < end:
            app.processEvents(); pumped["n"] += 1; time.sleep(0.01)
        return 0
    QApplication.exec = fake_exec
    QApplication.exec_ = fake_exec

    entry = os.path.join(ROOT, "eventhawk_gui.py")
    check("the GUI entrypoint exists", os.path.exists(entry), entry)

    cwd = os.getcwd()
    started, raised = True, None
    try:
        os.chdir(ROOT)
        runpy.run_path(entry, run_name="__main__")
    except SystemExit as e:
        if e.code not in (0, None):
            started, raised = False, f"SystemExit({e.code})"
    except Exception:
        started, raised = False, traceback.format_exc(limit=6)
    finally:
        os.chdir(cwd)

    check("the entrypoint runs without raising", started, raised or "")
    check("the event loop actually ran", pumped["n"] > 0, f"{pumped['n']} pump iterations")

    inst = QApplication.instance()
    tops = list(inst.topLevelWidgets()) if inst else []
    mains = [w for w in tops if type(w).__name__ == "MainWindow"]
    check("a MainWindow was constructed", len(mains) == 1,
          f"{len(mains)} found among {len(tops)} top-level widget(s)")
    if mains:
        w = mains[0]
        check("the main window is shown with a real size and title",
              w.isVisible() and w.width() > 200 and w.height() > 200 and bool(w.windowTitle()),
              f"title={w.windowTitle()!r} {w.width()}x{w.height()} visible={w.isVisible()}")

    check("no uncaught exception during startup", not errs,
          f"{len(errs)}: {errs[:3]}")

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
