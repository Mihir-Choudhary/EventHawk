"""Global filters leave an Around tab's window alone; Clear All resets its own filters.

Codex review-1, reproduced again by audit-2 on 92e3f3e:
  F1  In Normal mode, Apply Profiles and the merged Advanced Filter were applied
      first to ``_active_proxy`` -- the Around tab's proxy whenever that tab
      was in front -- so the window lost rows (6 -> 5 and 6 -> 1 here; 601 -> 92
      on real data) while All Events did not change.  JM was right.
  F2  In JM, Clear All Filters skipped Around tabs entirely, so a quick filter
      set inside one survived (1 -> 1; Normal went back to 6).

Expected, in both modes: a global filter changes All Events and never an
Around tab; Clear All Filters clears every tab's own filters but keeps an
Around tab's window (its six events).  Synthetic data only.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from PySide6.QtCore import Qt                                       # noqa: E402
from PySide6.QtWidgets import QDialog                               # noqa: E402

CHECKS = []
PROFILE = "Logon/Logoff Activity"        # its event IDs include 4624; the dataset's other events are 6011


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def settle(w, m, st):
    if m.jm:
        for model in [w._hw_model] + ([st.model] if st is not None else []):
            T.wait_for(lambda: model._filter_thread._q.empty(), 30)
        T.pump(500)
    else:
        T.pump(150)


def around_count(st, jm):
    return st.model.rowCount() if jm else st.proxy.rowCount()


def tick(w, names):
    cm = w._profile_combo._chk_model
    for i in range(cm.rowCount()):
        cm.item(i).setCheckState(Qt.CheckState.Checked if cm.item(i).text() in names else Qt.CheckState.Unchecked)


def run(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    evs = T.dataset()
    m.load(w, evs)
    total = m.main_count(w)
    n4624 = sum(1 for e in evs if e["event_id"] == 4624)
    key, st = T.open_tab(w, dict(evs[0]), T.FIVE, T.FIVE, "host", jm)
    check(f"{tag}: the Around tab is in front with its 6 events",
          st is not None and around_count(st, jm) == len(T.HOST) and w._active_file_tab == key,
          f"{around_count(st, jm) if st else None}")

    # F1a: profile applied with the Around tab in front
    tick(w, [PROFILE])
    w._btn_apply_profiles.click()
    settle(w, m, st)
    check(f"{tag}: Apply Profiles leaves the Around tab's window whole", around_count(st, jm) == len(T.HOST),
          f"{around_count(st, jm)} of {len(T.HOST)}")
    check(f"{tag}: ...and filters All Events", m.main_count(w) == n4624, f"{m.main_count(w)} vs {n4624} of {total}")
    w._btn_clear_all_filters.click()
    settle(w, m, st)

    # F1b: merged Advanced Filter (event ID 6011) with the Around tab in front
    from evtx_tool.core.filters import empty_filter
    cfg = empty_filter()
    cfg["event_ids"] = [6011]

    class _Dlg:
        def __init__(self, *a, **k):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def get_filter_config(self):
            return dict(cfg)
    real_dlg = mw.FilterDialog
    mw.FilterDialog = _Dlg
    try:
        w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(st.table))
        T.pump(50)
        w._on_advanced_filter_clicked()
    finally:
        mw.FilterDialog = real_dlg
    settle(w, m, st)
    check(f"{tag}: the merged Advanced Filter leaves the Around tab's window whole",
          around_count(st, jm) == len(T.HOST), f"{around_count(st, jm)} of {len(T.HOST)}")
    check(f"{tag}: ...and filters All Events", m.main_count(w) == 1, f"{m.main_count(w)} of {total}")
    w._btn_clear_all_filters.click()
    settle(w, m, st)

    # F2: a quick filter inside the Around tab, then Clear All Filters
    w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(st.table))
    T.pump(50)
    w._apply_quick_filter("computer", "OLD-NAME", True)
    settle(w, m, st)
    check(f"{tag}: a quick filter in the Around tab narrows it to 1", around_count(st, jm) == 1,
          f"{around_count(st, jm)}")
    w._btn_clear_all_filters.click()
    settle(w, m, st)
    check(f"{tag}: Clear All Filters clears the Around tab's own filter and keeps its window",
          around_count(st, jm) == len(T.HOST), f"{around_count(st, jm)} of {len(T.HOST)}")
    check(f"{tag}: ...and All Events shows everything", m.main_count(w) == total, f"{m.main_count(w)} of {total}")

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
