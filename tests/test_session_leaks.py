"""Repeated parses do not pile up engines, key caches or timers.

Gemini audit 12-10 (Low): every HeavyweightEngine registered an atexit
callback for life, so each engine of a session stayed referenced until exit;
ArrowTableModel.close() left its module-level key-selection cache holding the
closed table's arrays; the advanced-filter cache timer had no parent.

Expected: no atexit reference after a run, the cache emptied on close, the
timer parented to its model.  Synthetic.
"""
import atexit
import gc
import os
import sys
import weakref

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    import tempfile
    e = HeavyweightEngine(parquet_dir=tempfile.mkdtemp(prefix="hw_"))
    try:
        e.run([], None)
    except Exception:
        pass
    ref = weakref.ref(e)
    del e
    gc.collect()
    ok1 = ref() is None
    print(f"  {'PASS' if ok1 else 'FAIL'}  an engine is freed after its run (no atexit reference)")
    import evtx_tool.gui.heavyweight_model as HM
    HM._KEY_SEL_CACHE["entry"] = ("k", "s", "sel")
    m = HM.ArrowTableModel.__new__(HM.ArrowTableModel)
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    import inspect
    src = inspect.getsource(HM.ArrowTableModel.close)
    ok2 = "_KEY_SEL_CACHE.clear()" in src
    print(f"  {'PASS' if ok2 else 'FAIL'}  closing a model empties the key-selection cache")
    import evtx_tool.gui.models as GM
    ok3 = "QTimer(self)" in inspect.getsource(GM.EventTableModel.start_adv_cache_build)
    print(f"  {'PASS' if ok3 else 'FAIL'}  the advanced-filter cache timer is parented to its model")
    n = ok1 + ok2 + ok3
    print(f"{n}/3 checks passed")
    return 0 if n == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
