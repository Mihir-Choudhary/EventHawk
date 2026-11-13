"""The toolbar's quick search box filters like the Advanced Filter's Text box.

The search box is the Advanced Filter's text criterion without opening the
dialog, so it must behave exactly like it, in Normal and Juggernaut mode:

  * Enter applies the term; emptying the box removes it;
  * on its own it creates the Advanced Filter and removing the term removes it
    (no "Filter active" badge then: the box itself shows the filter);
  * stacked on a dialog filter it narrows it, and removing the term keeps the
    dialog's other criteria;
  * a text term set in the dialog shows in the box;
  * Clear All Filters empties the box and shows every event;
  * before anything is loaded it does nothing (and does not raise).

Synthetic data only.
Run: QT_QPA_PLATFORM=offscreen python tests/test_quick_search.py
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
    # 10 events: HOST-A on odd rows (5), event 4624 on the first four (2 of them HOST-A).
    evs = [T.ev(SEC, i + 1, "HOST-A" if i % 2 else "HOST-B", T.T0 + timedelta(seconds=i),
                4624 if i < 4 else 7036)
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

    def search(text):
        w._quick_search.setText(text)
        w._apply_quick_search()

    def dialog(cfg):
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

    from evtx_tool.core.filters import empty_filter

    # 1. On its own
    search("HOST-A")
    check(f"{tag}: Enter on 'HOST-A' shows the 5 HOST-A events", count() == 5, str(count()))
    check(f"{tag}: the search is the Advanced Filter's text term",
          (w._adv_filter_cfg or {}).get("text_search") == "HOST-A", str(w._adv_filter_cfg))
    check(f"{tag}: no 'Filter active' badge for a search-only filter (the box shows it)",
          w._lbl_adv_filter_badge.isHidden())
    w._quick_search.setText("")          # the clear button / Esc
    check(f"{tag}: emptying the box shows all 10 again", count() == 10, str(count()))
    check(f"{tag}: and removes the Advanced Filter it created", w._adv_filter_cfg is None,
          str(w._adv_filter_cfg))

    # 2. Stacked on a dialog filter
    cfg = empty_filter()
    cfg["event_ids"] = [4624]
    dialog(cfg)
    check(f"{tag}: dialog filter applies (4 of 10)", count() == 4, str(count()))
    search("HOST-A")
    check(f"{tag}: the search narrows the dialog filter (2 of 10)", count() == 2, str(count()))
    check(f"{tag}: the badge shows while a dialog filter is active",
          not w._lbl_adv_filter_badge.isHidden())
    w._quick_search.setText("")
    check(f"{tag}: removing the search keeps the dialog filter (4 of 10)", count() == 4, str(count()))
    check(f"{tag}: the dialog's event ID criterion is still there",
          (w._adv_filter_cfg or {}).get("event_ids") == [4624], str(w._adv_filter_cfg))

    # 3. A text term set in the dialog shows in the box
    cfg2 = empty_filter()
    cfg2["text_search"] = "HOST-B"
    dialog(cfg2)
    check(f"{tag}: dialog text term applies (5 of 10)", count() == 5, str(count()))
    check(f"{tag}: and shows in the search box", w._quick_search.text() == "HOST-B",
          repr(w._quick_search.text()))
    w._quick_search.setText("")
    check(f"{tag}: emptying the box removes the dialog's text term (10 of 10)", count() == 10,
          str(count()))

    # 4. Clear All Filters
    search("HOST-A")
    count()
    w._btn_clear_all_filters.click()
    check(f"{tag}: Clear All Filters shows every event", count() == 10, str(count()))
    check(f"{tag}: and empties the search box", w._quick_search.text() == "",
          repr(w._quick_search.text()))

    w.close()
    T.pump(200)


def before_load(mw):
    print("\n=== nothing loaded ===", flush=True)
    w = mw.MainWindow()
    w._quick_search.setText("anything")
    try:
        w._apply_quick_search()
        ok = True
    except Exception as e:                     # noqa: BLE001
        ok = False
        print(e)
    check("searching before a parse does not raise", ok)
    check("and sets no filter", w._adv_filter_cfg is None, str(w._adv_filter_cfg))
    w.close()
    T.pump(100)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    for jm in (False, True):
        run(mw, jm)
    before_load(mw)
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
