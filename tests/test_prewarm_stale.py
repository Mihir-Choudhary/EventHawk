"""Column-popup prewarm (Normal mode): a cancelled sweep files nothing.

When the filter changes, the running prewarm sweep is cancelled and the popup
cache cleared.  Results the sweep had already emitted were still queued for the
GUI thread and landed in the fresh cache: values for the OLD slice (keyed by its
size, so never shown, but kept for nothing).  test_header_popup_e2e caught it
only under load; this reproduces it directly.

  - results from the current sweep are filed
  - results from a cancelled sweep are dropped
  - results from a sweep that a newer one replaced are dropped

Run: QT_QPA_PLATFORM=offscreen python tests/test_prewarm_stale.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QObject, Signal
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.jm_col_worker as jcw
    import evtx_tool.gui.main_window as mw

    made = []

    class _FakeSweep(QObject):              # never runs: the test emits for it
        column_ready = Signal(str, object)
        finished = Signal()

        def __init__(self, by_col, parent=None):
            super().__init__(parent)
            self.by_col = by_col
            self._cancel = False
            made.append(self)

        def cancel(self):
            self._cancel = True

        def start(self):
            pass

        def isRunning(self):
            return not self._cancel

        def wait(self, *_a):
            return True

    jcw.NormalColValuePrewarmWorker = _FakeSweep
    w = mw.MainWindow()
    w._track_col_worker = lambda _w: None
    w._proxy_model.collect_source_events_for_popup = lambda ck: [{"event_id": 1}] * 5
    w._col_value_cache = {}

    w._start_normal_col_prewarm()
    first = made[-1]
    col = next(iter(first.by_col))
    first.column_ready.emit(col, {"x": 1})
    check("the current sweep's values are filed", len(w._col_value_cache) == 1, str(list(w._col_value_cache)))

    w._col_value_cache = {}                 # the filter changed: cache cleared...
    first.cancel()                          # ...and the sweep cancelled
    first.column_ready.emit(col, {"x": 1})  # a result that was already queued
    check("a cancelled sweep's queued result is dropped", not w._col_value_cache, str(list(w._col_value_cache)))

    w._start_normal_col_prewarm()
    second = made[-1]
    w._norm_prewarm_worker = second
    first._cancel = False                   # even if not flagged: it is not the current sweep
    first.column_ready.emit(col, {"x": 1})
    check("a replaced sweep's result is dropped", not w._col_value_cache, str(list(w._col_value_cache)))
    second.column_ready.emit(col, {"y": 2})
    check("the newer sweep still files", len(w._col_value_cache) == 1, str(list(w._col_value_cache)))

    # The case seen under load: nothing cancelled the sweep (clearing quick
    # filters only drops the cache), so it is still "current" -- yet its values
    # are for the slice that was in view when it started.
    w._invalidate_col_value_cache()
    second.column_ready.emit(col, {"y": 2})
    check("a sweep files nothing after the slice changed under it (not cancelled)",
          not w._col_value_cache, str(list(w._col_value_cache)))
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
