"""Normal separate-tabs view: an applied profile filters All Events and every file tab.

Codex audit-3 P1: Apply Profiles in Normal mode went to `_global_proxy`, the
active tab's proxy, so with a file tab in front (as right after Parse in the
separate view) All Events stayed unfiltered; and a file tab opened after the
profile was applied did not inherit it.  Expected, whichever tab is in front:
All Events and every file tab show only the profile's events, including tabs
opened later; untick + Apply restores them all.  Synthetic data only.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from PySide6.QtCore import Qt                                       # noqa: E402

CHECKS = []
PROFILE = "Logon/Logoff Activity"       # includes 4624, not 7036
A, B, C = r"C:\s\A.evtx", r"C:\s\B.evtx", r"C:\s\C.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def tick(w, names):
    m = w._profile_combo._chk_model
    for i in range(m.rowCount()):
        m.item(i).setCheckState(Qt.CheckState.Checked if m.item(i).text() in names else Qt.CheckState.Unchecked)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import EventTableModel
    evs = []
    for f in (A, B, C):
        for i, eid in enumerate((4624, 7036, 4624)):
            evs.append(T.ev(f, len(evs) + 1, "HOST", T.T0 + timedelta(seconds=len(evs)), eid))
    w = mw.MainWindow()
    w._view_mode = "separate"
    T.Mode(mw, False).load(w, evs)
    for f in (A, B, C):
        es = [e for e in evs if e["source_file"] == f]
        w._per_file_data[f] = {"events": es, "search_cache": [EventTableModel._build_search_str(e) for e in es]}
    for f in (A, B):
        w._create_file_tab(f)
    w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(w._file_tabs[A].table))
    T.pump(100)

    tick(w, [PROFILE])
    w._btn_apply_profiles.click()
    T.pump(200)
    check("with a file tab in front, All Events is filtered", w._proxy_model.rowCount() == 6,
          f"{w._proxy_model.rowCount()} of 9 (want 6)")
    check("...and every open file tab", all(st.proxy.rowCount() == 2 for st in (w._file_tabs[A], w._file_tabs[B])),
          str([w._file_tabs[x].proxy.rowCount() for x in (A, B)]))
    w._create_file_tab(C)
    T.pump(100)
    check("a file tab opened later inherits the applied profile", w._file_tabs[C].proxy.rowCount() == 2,
          f"{w._file_tabs[C].proxy.rowCount()} of 3 (want 2)")
    tick(w, [])
    w._btn_apply_profiles.click()
    T.pump(200)
    check("untick + Apply restores All Events and every tab",
          w._proxy_model.rowCount() == 9 and all(w._file_tabs[x].proxy.rowCount() == 3 for x in (A, B, C)),
          f"{w._proxy_model.rowCount()} / {[w._file_tabs[x].proxy.rowCount() for x in (A, B, C)]}")
    w.close()
    T.pump(200)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
