"""Clearing the Advanced Filter (its badge X) brings every event back, in both modes.

Found by the dynamic filter-timing run on a real baseline (2026-11-01): in
Juggernaut Mode, Advanced Filter -> clear the Advanced Filter left the view
at the filtered count (37,510 of 784,156) every time, while adding it worked.
Expected: the Advanced Filter applied, then cleared, shows every event; with a
quick filter also active, only the quick filter remains.  Synthetic data only.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from PySide6.QtWidgets import QDialog                               # noqa: E402

CHECKS = []
SEC = r"C:\s\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    evs = [T.ev(SEC, i + 1, "HOST-A" if i % 2 else "HOST-B", T.T0 + timedelta(seconds=i), 4624 if i < 4 else 7036)
           for i in range(10)]
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    m.load(w, evs)

    def count():
        if jm:
            T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
            T.pump(400)
            T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
            return w._hw_model.rowCount()
        T.pump(100)
        return w._proxy_model.rowCount()

    from evtx_tool.core.filters import empty_filter
    cfg = empty_filter()
    cfg["event_ids"] = [4624]

    class _Dlg:
        def __init__(self, *a, **k): pass
        def exec(self): return QDialog.DialogCode.Accepted
        def get_filter_config(self): return dict(cfg)
    real = mw.FilterDialog
    mw.FilterDialog = _Dlg
    try:
        w._on_advanced_filter_clicked()
    finally:
        mw.FilterDialog = real
    check(f"{tag}: the Advanced Filter applies (4 of 10)", count() == 4, str(count()))
    w._clear_advanced_filter()
    check(f"{tag}: clearing the Advanced Filter shows all 10 again", count() == 10, str(count()))

    mw.FilterDialog = _Dlg
    try:
        w._on_advanced_filter_clicked()
    finally:
        mw.FilterDialog = real
    w._apply_quick_filter("computer", "HOST-A", True)
    check(f"{tag}: Advanced Filter + quick filter stack (2 of 10)", count() == 2, str(count()))
    w._clear_advanced_filter()
    check(f"{tag}: clearing the Advanced Filter keeps only the quick filter (5 of 10)", count() == 5, str(count()))
    w.close()
    T.pump(200)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    for jm in (False, True):
        run(mw, jm)
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
