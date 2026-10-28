"""A column popup shows the values of the tab it was opened in.

Codex review-1 F3, reproduced again by audit-2: in Normal mode the popup cache
was keyed on (column, number of visible rows).  Two Around tabs with the same
number of rows shared a key, so the second tab's Event ID popup offered the
first tab's event ID and count -- a value matching none of its rows; picking it
hides all of the tab's evidence.  JM keys on the table and was right.

Two tabs of two events each, different event IDs; open the Event ID popup in
A, B, A again.  Each must show exactly its own tab's values.  Synthetic data.
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
SEC = r"C:\synthetic\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    t1 = T.T0 + timedelta(hours=1)
    return [T.ev(SEC, 1, "HOST-A", T.T0, 4624), T.ev(SEC, 2, "HOST-A", T.T0 + timedelta(seconds=5), 4624),
            T.ev(SEC, 3, "HOST-B", t1, 4688), T.ev(SEC, 4, "HOST-B", t1 + timedelta(seconds=5), 4688)]


def popup_values(w, st, jm):
    shown = []
    w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(st.table))
    T.pump(100)
    real = w._show_col_filter_popup
    w._show_col_filter_popup = lambda idx, vals: shown.append(dict(vals))
    try:
        w._on_col_header_clicked(1)                 # Event ID
        T.wait_for(lambda: bool(shown), 30)
    finally:
        w._show_col_filter_popup = real
    return {str(k): v for k, v in (shown[0] if shown else {}).items()}


def run(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    evs = dataset()
    m.load(w, evs)
    _ka, a = T.open_tab(w, dict(evs[0]), T.FIVE, T.FIVE, "host", jm)
    _kb, b = T.open_tab(w, dict(evs[2]), T.FIVE, T.FIVE, "host", jm)
    check(f"{tag}: two Around tabs of two events each", a is not None and b is not None)
    if a is None or b is None:
        w.close()
        return
    want_a, want_b = {"4624": 2}, {"4688": 2}
    for step, (st, want) in enumerate(((a, want_a), (b, want_b), (a, want_a)), 1):
        got = popup_values(w, st, jm)
        check(f"{tag}: popup {step} shows its own tab's event IDs", got == want, f"{got} vs {want}")
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
