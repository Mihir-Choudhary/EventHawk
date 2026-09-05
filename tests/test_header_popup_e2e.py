"""Clicking a column header, through a real MainWindow.

Everything else drives ColumnFilterPopup directly.  This goes through the
actual path a user takes: _on_col_header_clicked -> NormalColValueWorker ->
_show_col_filter_popup -> the popup's own signal -> _on_col_filter_applied ->
quick filters on the active proxy.  It is the only check that the date tree is
reachable, positioned, and wired to the model in the assembled application.
"""
import os
import sys
import glob
import collections

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt, QEventLoop, QTimer                 # noqa: E402
from PySide6.QtWidgets import QApplication                        # noqa: E402

_app = QApplication.instance() or QApplication([])

from evtx_tool.gui.main_window import MainWindow, ColumnFilterPopup  # noqa: E402
from evtx_tool.gui.models import apply_tz                         # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def pump(ms=4000):
    """Spin a real event loop so worker threads deliver their results."""
    loop = QEventLoop()
    QTimer.singleShot(ms, loop.quit)
    loop.exec()


def open_popup(w, col):
    """Click a header and return the popup that appears, or None."""
    seen = {}
    orig = w._show_col_filter_popup

    def spy(idx, values, _o=orig):
        _o(idx, values)
        for ch in w.children():
            if isinstance(ch, ColumnFilterPopup) and ch.isVisible():
                seen["p"] = ch
        seen.setdefault("values", values)
    w._show_col_filter_popup = spy
    try:
        w._on_col_header_clicked(col)
        for _ in range(20):
            pump(200)
            if "p" in seen:
                break
    finally:
        w._show_col_filter_popup = orig
    return seen.get("p"), seen.get("values")


def main() -> int:
    LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    if not os.path.isdir(LOGS):
        print(f"no corpus at {LOGS!r} — skipping")
        return 0
    from evtx_tool.core.parser import iter_events
    evs = []
    for f in sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:1]:
        for e in iter_events(f):
            evs.append(e)
    if not evs:
        print("no events — skipping")
        return 0
    print(f"corpus: {len(evs):,} events\n")

    w = MainWindow()
    w._events = evs
    w._event_model.set_events(evs)
    pump(300)
    total = w._proxy_model.rowCount()
    check(f"the window holds the corpus ({total} rows)", total == len(evs))

    truth = collections.Counter(apply_tz(e["timestamp"])[:10].lower() for e in evs)

    print("\n=== clicking the Timestamp header ===")
    pop, values = open_popup(w, 3)
    check("a popup opens for the timestamp column", pop is not None)
    if pop is None:
        return 1
    check("it is the Year -> Month -> Day tree", pop._tree is not None)
    check("it is populated from the real dates",
          set(values or {}) == set(truth), f"{len(values or {})} values")
    check("years were built", len(pop._year_items) > 0,
          str(sorted(pop._year_items)))
    check("leaves match the dates in the data",
          {x.property("filter_value") for x in pop._checkboxes} == set(truth))

    print("\n=== picking a whole month and pressing OK ===")
    ym = sorted(pop._month_items)[0]
    pop._check_none()
    pop._month_items[ym].setCheckState(0, Qt.CheckState.Checked)
    picked = {x.property("filter_value") for x in pop._checkboxes if x.isChecked()}
    pop._apply()
    pump(500)
    qf = w._active_proxy.get_quick_filters()
    check("quick filters landed on the active proxy", bool(qf), str(qf[:2]))
    check("they are all for timestamp_date",
          all(f.get("key") == "timestamp_date" for f in qf))
    exp = sum(c for d, c in truth.items() if d in picked)
    got = w._active_proxy.rowCount()
    check(f"the table now shows exactly {ym[0]}-{ym[1]}", got == exp,
          f"rows={got} expected={exp}")

    print("\n=== reopening reflects the active filter ===")
    pop2, _ = open_popup(w, 3)
    check("the popup reopens", pop2 is not None)
    if pop2 is not None:
        rechecked = {x.property("filter_value") for x in pop2._checkboxes
                     if x.isChecked()}
        check("exactly the filtered days come back checked",
              rechecked == picked,
              f"{len(rechecked)} vs {len(picked)}")
        check("its month row shows fully checked",
              pop2._month_items[ym].checkState(0) == Qt.CheckState.Checked)
        other_years = [y for y in pop2._year_items if y != ym[0]]
        check("an unrelated year is unchecked",
              all(pop2._year_items[y].checkState(0) == Qt.CheckState.Unchecked
                  for y in other_years) if other_years else True)
        pop2.reject()

    print("\n=== clearing restores the table ===")
    w._clear_quick_filters()
    pump(300)
    check("clearing quick filters restores every row",
          w._active_proxy.rowCount() == total,
          f"{w._active_proxy.rowCount()} vs {total}")
    check("the invalidation left no cached popup values",
          not w._col_value_cache, str(list(w._col_value_cache))[:80])
    # _on_col_filter_applied rebuilds the ENTIRE quick-filter list from
    # _col_filters.  If a cleared column is still in there, the next column the
    # analyst filters silently re-applies the one they just cleared -- a
    # narrower view than they believe they are looking at, with no indication.
    check("clearing also drops the column-filter bookkeeping",
          not w._col_filters, str(w._col_filters)[:100])
    check("no column still shows a filter marker",
          not getattr(w._active_model, "_header_overrides", {}),
          str(getattr(w._active_model, "_header_overrides", {}))[:80])

    print("\n=== a non-date column still uses the flat list ===")
    pop3, vals3 = open_popup(w, 1)
    check("a popup opens for Event ID", pop3 is not None)
    if pop3 is not None:
        check("Event ID has no tree", pop3._tree is None)
        eid_truth = collections.Counter(str(e.get("event_id", "")).lower()
                                        for e in evs)
        eid_truth.pop("", None)
        check("its values match the data",
              set(vals3 or {}) == set(eid_truth),
              f"{len(vals3 or {})} vs {len(eid_truth)}")
        top = eid_truth.most_common(1)[0][0]
        for x in pop3._checkboxes:
            x.setChecked(x.property("filter_value") == top)
        pop3._apply()
        pump(500)
        check("filtering Event ID from the header works",
              w._active_proxy.rowCount() == eid_truth[top],
              f"{w._active_proxy.rowCount()} vs {eid_truth[top]}")
        # The cleared timestamp filter must NOT have come back alongside it.
        _qf2 = w._active_proxy.get_quick_filters()
        check("only Event ID is filtered -- the cleared date filter stayed gone",
              {f.get("key") for f in _qf2} == {"event_id"},
              str(sorted({f.get("key") for f in _qf2})))
        w._clear_quick_filters()
        pump(200)

    w.close()
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
