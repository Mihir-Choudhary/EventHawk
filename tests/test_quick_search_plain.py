"""The toolbar search box always does a plain search, whatever the Filter dialog's text options say.

The box writes its term into the Advanced Filter's text criterion.  It used to
keep the dialog's text options -- Exclude, mode NOT, Regex -- so with one of
them left on from an earlier search, typing "HOST-A" showed the events WITHOUT
HOST-A (Exclude / NOT), or a term with regex characters found nothing (Regex), and
the box gave no sign of it (review of PR #19, QS-1, 2026-11-15).

Expected, Normal and Juggernaut mode:
- a term typed in the box is a plain, include, contains search (AND), even when
  the dialog's filter had Exclude, NOT or Regex on; the dialog's other criteria
  stay;
- a dialog text term that has Exclude, NOT or Regex is NOT shown in the box as if
  it were a plain search (the box stays empty; the badge shows the filter), and
  emptying the box leaves that criterion alone.
Synthetic data only.
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
    # 10 events: HOST-A on rows 1, 3, 5 (3); event 4624 on the first four (2 of them HOST-A).
    # HOST-A events carry "svc(1).exe" in their data: as a regex, "svc(1)" matches "svc1", not the text.
    evs = []
    for i in range(10):
        e = T.ev(SEC, i + 1, "HOST-A" if i in (1, 3, 5) else "HOST-B", T.T0 + timedelta(seconds=i),
                 4624 if i < 4 else 7036)
        if i in (1, 3, 5):
            e["event_data"] = dict(e.get("event_data") or {}, Image=r"C:\Tools\svc(1).exe")
        evs.append(e)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    m.load(w, evs)
    if jm:
        w._hw_model.busy_finished.connect(w._on_hw_filter_busy_finished)

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

    for label, opts in (("Exclude", {"text_exclude": True}), ("mode NOT", {"search_mode": "NOT"}),
                        ("Regex", {"text_regex": True})):
        cfg = empty_filter()
        cfg.update(opts)
        cfg["text_search"] = "zz-no-such-text"
        dialog(cfg)
        count()
        check(f"{tag}: a dialog text term with {label} is not shown in the box as a plain search",
              w._quick_search.text() == "", repr(w._quick_search.text()))
        n_dialog = count()
        w._quick_search.setText("")
        check(f"{tag}: emptying the (already empty) box leaves the {label} criterion alone",
              count() == n_dialog and (w._adv_filter_cfg or {}).get("text_search") == "zz-no-such-text",
              f"{count()} rows, cfg {w._adv_filter_cfg and w._adv_filter_cfg.get('text_search')!r}")
        search("HOST-A")
        check(f"{tag}: with {label} left on in the dialog, 'HOST-A' in the box shows the 3 HOST-A events",
              count() == 3, str(count()))
        search("svc(1)")
        check(f"{tag}: with {label} left on, 'svc(1)' (regex characters) finds the 3 events that hold it",
              count() == 3, str(count()))
        w._btn_clear_all_filters.click()
        count()

    # The dialog's other criteria stay
    cfg = empty_filter()
    cfg["event_ids"] = [4624]
    cfg["text_exclude"] = True
    cfg["text_search"] = "zz-no-such-text"
    dialog(cfg)
    search("HOST-A")
    check(f"{tag}: the box's term narrows the dialog's event ID filter (2 of 10)", count() == 2, str(count()))
    check(f"{tag}: the event ID criterion is still there",
          (w._adv_filter_cfg or {}).get("event_ids") == [4624], str(w._adv_filter_cfg))
    w.close()
    T.pump(200)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])   # noqa: F841
    for jm in (False, True):
        run(mw, jm)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"\n{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
