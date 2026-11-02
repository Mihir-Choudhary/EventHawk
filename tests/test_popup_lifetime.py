"""A closed column-filter popup is freed, and a late search result is harmless.

Found by Codex in audit-5 (E5-10, pre-existing): every popup the window
opened stayed alive after it closed (a child of the main window, never
deleted) -- after 100 open/close cycles 100 popups remained, each with its
value list, and memory grew 663 MiB (Normal) / 2,303 MiB (JM).  Expected:
at most one popup (the latest) stays alive, whichever way they close (OK,
Cancel); a popup is never deleted while its own OK is still being handled
(a busy dialog's nested event loop could close and delete it, and OK then
raised on a deleted object); and a full-dataset search that finishes after
its popup is gone does nothing.  Synthetic events.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
CYCLES = 20


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def flush_deletes():
    from PySide6.QtCore import QCoreApplication, QEvent
    for _ in range(3):
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        T.pump(20)


def main() -> int:
    from PySide6.QtWidgets import QPushButton
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.main_window import ColumnFilterPopup
    col = next(i for i, k in ColumnFilterPopup.FILTERABLE.items() if k == "computer")
    evs = [T.ev(r"C:\c\Security.evtx", i + 1, f"HOST-{i % 7}", T.T0 + timedelta(seconds=i), 4624)
           for i in range(50)]
    errors = []
    old_hook = sys.excepthook
    sys.excepthook = lambda t, v, tb: errors.append(f"{t.__name__}: {v}")    # recorded, then asserted
    try:
        for jm in (False, True):
            tag = "JM" if jm else "Normal"
            w = mw.MainWindow()
            m = T.Mode(mw, jm)
            m.load(w, evs)
            if jm:
                w._table.setModel(w._hw_model)
            T.pump(200)
            vals = {f"HOST-{i}": 1 for i in range(7)}
            for i in range(CYCLES):
                w._show_col_filter_popup(col, dict(vals))
                pop = w.findChildren(ColumnFilterPopup)[-1]
                T.pump(20)
                btn = "OK" if i % 2 else "Cancel"
                next(b for b in pop.findChildren(QPushButton) if b.text() == btn).click()
                T.pump(20)
            flush_deletes()
            left = len(w.findChildren(ColumnFilterPopup))
            check(f"{tag}: {CYCLES} popups opened and closed (OK / Cancel), at most the latest left alive",
                  left <= 1, f"{left} left")

            # OK while a nested event loop runs (as the busy dialog does): the
            # popup loses focus, closes, and deferred deletes are processed.
            w._show_col_filter_popup(col, dict(vals))
            pop = w.findChildren(ColumnFilterPopup)[-1]
            T.pump(20)

            def nested(*_a, p=pop):
                p.close()
                flush_deletes()
            pop.filterApplied.connect(nested)
            pop._checkboxes[0].setChecked(False)
            raised = None
            try:
                pop._apply()
            except RuntimeError as exc:
                raised = str(exc)
            check(f"{tag}: OK survives a nested event loop that closes the popup", raised is None, str(raised))
            T.pump(50)

            # A full-dataset search still running when its popup closes.
            w._show_col_filter_popup(col, dict(vals))
            pop = w.findChildren(ColumnFilterPopup)[-1]
            pop._inp_search.setText("HOST-3")
            pop._pending_search_term = "HOST-3"
            pop._run_full_search()                     # starts the worker
            next(b for b in pop.findChildren(QPushButton) if b.text() == "Cancel").click()
            w._show_col_filter_popup(col, dict(vals))  # the next popup frees the closed one
            flush_deletes()
            T.pump(1500)                               # the worker finishes after the popup is gone
            flush_deletes()
            check(f"{tag}: a search finishing after its popup closed raises nothing", not errors,
                  "; ".join(errors)[:200])
            errors.clear()
            T.teardown(w, jm, m)
    finally:
        sys.excepthook = old_hook

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
