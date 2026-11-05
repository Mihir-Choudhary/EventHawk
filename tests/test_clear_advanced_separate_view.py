"""Clearing the Advanced Filter with a file tab in front also clears it on All Events.

Codex audit-3 P1 (remaining part, found by Claude 2026-11-06): Apply Profiles
was fixed to filter All Events whichever tab is in front, but Clear Advanced
Filter still went to `_global_proxy` -- the file tab in front -- plus the file
tabs: All Events kept the old Advanced Filter, showing fewer events than the
user had asked for, with no badge saying so.

Expected (Normal mode, separate view, file tab in front): after Clear, All
Events and every file tab show the applied profile's events again (with a
profile) or every event (without).  Synthetic data only.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_profile_separate_view import PROFILE, A, B, tick         # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def setup(mw):
    from evtx_tool.gui.models import EventTableModel
    evs = []
    for f in (A, B):
        for eid in (4624, 7036, 4624, 4634):
            evs.append(T.ev(f, len(evs) + 1, "HOST", T.T0 + timedelta(seconds=len(evs)), eid))
    w = mw.MainWindow()
    w._view_mode = "separate"
    T.Mode(mw, False).load(w, evs)
    for f in (A, B):
        es = [e for e in evs if e["source_file"] == f]
        w._per_file_data[f] = {"events": es, "search_cache": [EventTableModel._build_search_str(e) for e in es]}
        w._create_file_tab(f)
    w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(w._file_tabs[A].table))
    T.pump(100)
    return w


def advanced_everywhere(w, cfg):
    """What the Advanced Filter dialog does when 'All Events' and every file tab are chosen."""
    w._adv_filter_cfg = cfg
    eff = w._build_filter_config(base=cfg)
    w._proxy_model.set_advanced_filter(eff)
    for st in w._file_tabs.values():
        st.proxy.set_advanced_filter(eff)
    T.pump(100)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.core.filters import empty_filter

    only_4624 = dict(empty_filter(), event_ids=[4624])
    # With a profile applied (4624 + 4634 are logon/logoff; 7036 is not).
    w = setup(mw)
    tick(w, [PROFILE])
    w._btn_apply_profiles.click()
    T.pump(200)
    base = w._proxy_model.rowCount()
    advanced_everywhere(w, only_4624)
    check("setup: Advanced Filter narrows All Events", w._proxy_model.rowCount() < base,
          f"{w._proxy_model.rowCount()} of {base}")
    w._clear_advanced_filter()
    T.pump(200)
    check("with a profile: Clear restores All Events to the profile's events", w._proxy_model.rowCount() == base,
          f"{w._proxy_model.rowCount()} (want {base})")
    check("...and every file tab", all(st.proxy.rowCount() == base // 2 for st in w._file_tabs.values()),
          str([st.proxy.rowCount() for st in w._file_tabs.values()]))
    w.close(); T.pump(200)

    # Without a profile.
    w = setup(mw)
    advanced_everywhere(w, only_4624)
    w._clear_advanced_filter()
    T.pump(200)
    check("without a profile: Clear shows every event on All Events (8)", w._proxy_model.rowCount() == 8,
          str(w._proxy_model.rowCount()))
    check("...and on every file tab (4 each)", all(st.proxy.rowCount() == 4 for st in w._file_tabs.values()),
          str([st.proxy.rowCount() for st in w._file_tabs.values()]))
    w.close(); T.pump(200)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
