"""A file tab opened while an Advanced Filter is on shows that filter too.

Gemini audit 3-11 (Medium): opening a per-file tab (Normal _create_file_tab,
Juggernaut _open_jm_file_tab) applied only the ticked profiles
(_build_filter_config(base=None)) and dropped the active Advanced Filter,
so the new tab showed events the filter excludes while the badge said
"Filter Active".

Expected, in both modes: with an Advanced Filter on Computer HOST-A, a file
tab opened afterwards shows only that file's HOST-A events.  Synthetic events.
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
F = r"C:\c\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.core.filters import empty_filter
    evs = [T.ev(F, i + 1, "HOST-A" if i < 2 else "HOST-B", T.T0 + timedelta(seconds=i), 4624) for i in range(5)]
    for jm in (False, True):
        mode = "Juggernaut" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
            w._connect_jm_model_signals(w._hw_model)
        w._warn_blocking = lambda *a, **k: None
        cfg = empty_filter()
        cfg["computers"] = ["HOST-A"]
        w._apply_adv_cfg_to_all_views(cfg, "Filtering…")
        T.pump(500)
        if jm:
            w._jm_pending = {F: w._hw_model._full_table}     # as a separate-view load fills
            w._open_jm_file_tab(F)
        else:
            w._per_file_data = {F: {"events": list(evs), "search_cache": []}}   # as a separate-view load fills
            w._create_file_tab(F)
        T.pump(800)
        st = w._file_tabs.get(F)
        mdl = (st.model if jm else st.proxy) if st else None
        if jm and mdl is not None:
            T.wait_for(lambda: mdl.rowCount() == 2, 15)
        n = mdl.rowCount() if mdl is not None else -1
        check(f"{mode}: a file tab opened under the Advanced Filter shows only HOST-A (2)", n == 2, f"{n} rows")
        T.teardown(w, jm, m)
    k = sum(ok for _, ok, _ in CHECKS)
    print(f"{k}/{len(CHECKS)} checks passed")
    return 0 if k == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
