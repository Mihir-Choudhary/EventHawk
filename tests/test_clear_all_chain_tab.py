"""Clear All Filters works with a chain tab open in Juggernaut mode.

Found by Gemini in audit-5 (B8): in Juggernaut mode Clear All called
clear_all_filters() on every tab's *model*.  A chain tab keeps its events in
memory (an EventTableModel behind a filter proxy, as in Normal mode) and that
model has no such method: AttributeError, and the rest of Clear All never
ran -- the chain tab kept its filter and the ATT&CK filter, column-filter
markers and badges were left as they were.  Expected: Clear All clears every
layer in every tab, raising nothing, in both modes.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_around_review_fixes import _Item                          # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        evs = T.dataset()
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
        chain = {"rule_name": "probe", "severity": "high", "events": [dict(evs[5]), dict(evs[9])]}
        w._open_chain_events_tab([_Item(chain)])
        key = [k for k in w._file_tabs if k.startswith("__chain__")][-1]
        st = w._file_tabs[key]
        T.pump(50)
        st.proxy.add_quick_filter("computer", "OTHER", True)
        check(f"{tag}: the chain tab's filter applies", st.proxy.rowCount() == 1, str(st.proxy.rowCount()))
        w._active_tactic_filter = "Execution"
        err = None
        try:
            w._clear_all_filters()
        except Exception as exc:                     # the defect: raised mid-way
            err = f"{type(exc).__name__}: {exc}"
        T.pump(200)
        check(f"{tag}: Clear All raises nothing", err is None, str(err))
        check(f"{tag}: Clear All clears the chain tab's filter", st.proxy.rowCount() == 2,
              f"{st.proxy.rowCount()} of 2")
        check(f"{tag}: Clear All finishes (ATT&CK filter cleared too)", w._active_tactic_filter is None,
              str(w._active_tactic_filter))
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
