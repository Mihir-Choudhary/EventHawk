"""A file tab opened after profiles were applied shows them, in both modes.

Found by Codex in audit-5 (E5-08): in Juggernaut, a profile ticked before
Parse (applied when the load finishes) filtered All Events and the open
tabs, but a file tab opened afterwards showed every event of its file (963
shown, 80 expected).  Normal mode already gave a new tab the applied
profiles (Codex audit-3 P1).  Synthetic events.
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
A, B = r"C:\c\Security.evtx", r"C:\d\Security.evtx"
PROFILE = "Logon/Logoff Activity"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import EventTableModel
    evs = []
    for f in (A, B):
        for eid in (4624, 4634, 7036, 4688, 4625):
            evs.append(T.ev(f, len(evs) + 1, "HOST", T.T0 + timedelta(seconds=len(evs)), eid))
    want = sum(1 for e in evs if e["source_file"] == A and e["event_id"] in (4624, 4634, 4625))
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        w._view_mode = "separate"
        m = T.Mode(mw, jm)
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
        cm = w._profile_combo._chk_model
        for i in range(cm.rowCount()):
            cm.item(i).setCheckState(Qt.CheckState.Checked if cm.item(i).text() == PROFILE else Qt.CheckState.Unchecked)
        w._on_apply_profiles_clicked()
        T.pump(300)
        if jm:
            w._jm_pending = {f: w._hw_model._full_table for f in (A, B)}
            w._open_jm_file_tab(A)
            mdl = w._file_tabs[A].model
            T.pump(300)
            T.wait_for(lambda: mdl._filter_thread._q.empty(), 30); T.pump(500)
            got = mdl.rowCount()
        else:
            es = [e for e in evs if e["source_file"] == A]
            w._per_file_data[A] = {"events": es, "search_cache": [EventTableModel._build_search_str(e) for e in es]}
            w._create_file_tab(A)
            T.pump(100)
            got = w._file_tabs[A].proxy.rowCount()
        check(f"{tag}: a file tab opened after Apply Profiles shows only the profile's events", got == want,
              f"{got} vs {want}")
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
