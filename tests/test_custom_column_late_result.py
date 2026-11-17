"""A custom-column result for a dataset that is gone never lands on the new one (Codex PR19-6).

A custom column is computed on a worker from a snapshot of the events. When
the dataset was cleared or reloaded meanwhile, nothing tied the result to its
dataset: in Normal mode the same table model is reused, so the old values were
installed on the new events (matched by object identity, so every cell was
blank) and a filter on the column then hid real events.

Expected, in both modes: a result computed for an older dataset is not
installed; the column is computed again for the events now loaded, and its
cells hold their values. Synthetic data; the worker is held with an event so
the order is fixed.
"""
import os
import sys
import tempfile
import threading
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events(base, vals):
    return [T.ev(r"C:\c\Security.evtx", base + i + 1, "HOST", T.T0 + timedelta(seconds=base + i), 4624,
                 data={"LogonType": v}) for i, v in enumerate(vals)]


def main() -> int:
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])  # noqa: F841
    for _n in ("warning", "information", "critical"):
        setattr(QMessageBox, _n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    import evtx_tool.gui.main_window as mw
    from evtx_tool.core.custom_columns import compile_spec, CustomColumnSpec
    from evtx_tool.gui.models import COLUMNS
    spec = CustomColumnSpec(col_id=7, title="Logon type", template="{Data[LogonType]}",
                            eid_expr="", providers=(), kind="text")
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, events(0, ["2", "3", "10"]))
        if jm:
            w._table.setModel(w._hw_model)
        T.pump(200)
        main = w._hw_model if jm else w._event_model
        gate = threading.Event()
        real = mw._CustomColumnWorker.run

        def held(self, _real=real):
            gate.wait(20)
            return _real(self)
        mw._CustomColumnWorker.run = held
        try:
            w._compute_custom_column(main, compile_spec(spec), editing=False, quiet=True)
            T.pump(100)
            # a new dataset arrives while the worker is held
            w._clear_results()
            m2 = T.Mode(mw, jm)
            m2.load(w, events(100, ["5", "5", "11", "7"]))
            if jm:
                w._table.setModel(w._hw_model)
            T.pump(200)
            main2 = w._hw_model if jm else w._event_model
        finally:
            gate.set()
            mw._CustomColumnWorker.run = real
        T.wait_for(lambda: main2.custom_col_index(7) is not None, 30)
        T.wait_for(lambda: not any(w._thread_running(x) for x in getattr(w, "_custom_col_workers", [])), 30)
        T.pump(400)
        idx = main2.custom_col_index(7)
        vals = sorted(str(main2.data(main2.index(r, idx)) or "") for r in range(main2.rowCount())) if idx else []
        check(f"{tag}: the column on the new events holds the new events' values", vals == ["11", "5", "5", "7"],
              f"col={idx} {vals}")
        check(f"{tag}: and is there once", main2.columnCount() == len(COLUMNS) + 1, str(main2.columnCount()))
        w.close()
        T.pump(200)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    tempfile.tempdir = None
    sys.exit(main())
