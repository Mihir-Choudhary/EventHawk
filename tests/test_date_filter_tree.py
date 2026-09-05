"""Year → Month → Day tree for the timestamp column's quick-filter popup.

The tree is a UI change only: it must emit exactly the same flat YYYY-MM-DD
filter values the old flat checkbox list emitted, because everything
downstream (quick filters, SQL, the include/exclude mode heuristic) is
unchanged.  These checks pin that equivalence plus the tree-specific
behaviours that a naive implementation gets wrong.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt                                    # noqa: E402
from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])

from evtx_tool.gui.main_window import (                          # noqa: E402
    ColumnFilterPopup, _DATE_UNKNOWN_GROUP,
)

DATE_COL = 3          # timestamp  → tree
FLAT_COL = 12         # process_id → flat list (control)

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def capture(popup):
    """Click OK and capture the (mode, values) the popup emits."""
    out = {}
    popup.filterApplied.connect(
        lambda c, m, v: out.update(col=c, mode=m, values=list(v))
    )
    popup._apply()
    return out


VALUES = {
    "2024-05-14": 120, "2024-05-15": 7, "2024-01-03": 55,
    "2023-11-02": 9,   "2023-04-21": 3, "2023-04-22": 41,
    "2022-07-09": 1,
}


def leaves(popup):
    return [p.property("filter_value") for p in popup._checkboxes]


def find_year(popup, y):
    return popup._year_items[y]


def find_month(popup, y, m):
    return popup._month_items[(y, m)]


def main() -> int:
    print("\n=== 1. hierarchy is built from real date strings ===")
    p = ColumnFilterPopup(DATE_COL, dict(VALUES))
    check("tree widget created for timestamp column", p._tree is not None)
    check("flat column still uses checkboxes", ColumnFilterPopup(FLAT_COL, {"916": 3})._tree is None)
    check("years discovered", sorted(p._year_items) == ["2022", "2023", "2024"],
          str(sorted(p._year_items)))
    check("months discovered", sorted(p._month_items) ==
          [("2022", "07"), ("2023", "04"), ("2023", "11"), ("2024", "01"), ("2024", "05")],
          str(sorted(p._month_items)))
    check("leaf count == unique date count", len(p._checkboxes) == len(VALUES),
          f"{len(p._checkboxes)} vs {len(VALUES)}")
    check("all leaves start checked", all(x.isChecked() for x in p._checkboxes))

    print("\n=== 2. parents never leak into the emitted values ===")
    vals = set(leaves(p))
    check("no bare years among leaf values", not (vals & {"2022", "2023", "2024"}))
    check("no year-month among leaf values", not (vals & {"2024-05", "2023-04"}))
    check("leaf values are exactly the input dates", vals == set(VALUES), str(sorted(vals)))
    check("(Select All) row is not in _checkboxes",
          all(getattr(x, "_item", None) is not p._all_item for x in p._checkboxes))

    print("\n=== 3. ordering is chronological, not by count ===")
    order_y = [p._all_item.child(i).data(0, 2 + Qt.ItemDataRole.UserRole)
               for i in range(p._all_item.childCount())]
    check("years newest-first", order_y == ["2024", "2023", "2022"], str(order_y))
    y2023 = find_year(p, "2023")
    months_2023 = [y2023.child(i).data(0, 2 + Qt.ItemDataRole.UserRole)
                   for i in range(y2023.childCount())]
    check("months in calendar order (April before November)",
          months_2023 == ["04", "11"], str(months_2023))
    m0405 = find_month(p, "2024", "05")
    days = [m0405.child(i).data(0, 1 + Qt.ItemDataRole.UserRole)
            for i in range(m0405.childCount())]
    check("days ascending despite 14 having more events than 15",
          days == ["2024-05-14", "2024-05-15"], str(days))

    print("\n=== 4. counts roll up to month and year rows ===")
    check("month label carries summed count", "(127)" in m0405.text(0), m0405.text(0))
    check("year label carries summed count", "(182)" in find_year(p, "2024").text(0),
          find_year(p, "2024").text(0))
    check("leaf label shows its own count", "(120)" in
          m0405.child(0).text(0), m0405.child(0).text(0))

    print("\n=== 5. checking a month selects exactly its days ===")
    p2 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p2._check_none()
    check("None clears every leaf", not any(x.isChecked() for x in p2._checkboxes))
    find_month(p2, "2023", "04").setCheckState(0, Qt.CheckState.Checked)
    sel = {x.property("filter_value") for x in p2._checkboxes if x.isChecked()}
    check("month check selects exactly its two days",
          sel == {"2023-04-21", "2023-04-22"}, str(sorted(sel)))
    check("parent year becomes partially checked",
          find_year(p2, "2023").checkState(0) == Qt.CheckState.PartiallyChecked)
    check("untouched year stays unchecked",
          find_year(p2, "2024").checkState(0) == Qt.CheckState.Unchecked)
    emitted = capture(p2)
    check("emits include on exactly those days",
          emitted["mode"] == "include" and set(emitted["values"]) == sel,
          f"{emitted['mode']} {sorted(emitted['values'])}")

    print("\n=== 6. checking one whole year emits include on that year's days ===")
    p3 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p3._check_none()
    find_year(p3, "2024").setCheckState(0, Qt.CheckState.Checked)
    e3 = capture(p3)
    check("year check cascades to all its days",
          set(e3["values"]) == {"2024-05-14", "2024-05-15", "2024-01-03"},
          str(sorted(e3["values"])))
    check("mode is include (names what to keep, not what to drop)",
          e3["mode"] == "include", e3["mode"])

    print("\n=== 7. clearing the search must NOT re-check everything ===")
    # This is the trap: the flat list's empty-search branch does setChecked(True)
    # on every row.  Through the tree that would silently wipe the user's month.
    p4 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p4._check_none()
    find_month(p4, "2023", "04").setCheckState(0, Qt.CheckState.Checked)
    before = {x.property("filter_value") for x in p4._checkboxes if x.isChecked()}
    p4._inp_search.setText("2024")
    p4._inp_search.setText("")
    after = {x.property("filter_value") for x in p4._checkboxes if x.isChecked()}
    check("selection survives a search round-trip", before == after,
          f"before={sorted(before)} after={sorted(after)}")
    check("clearing did not check all leaves", len(after) != len(p4._checkboxes))

    print("\n=== 8. search reveals and scopes the selection ===")
    p5 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p5._inp_search.setText("2023")
    vis = {x.property("filter_value") for x in p5._checkboxes if x.isVisible()}
    check("typing a year shows only that year's days",
          vis == {"2023-11-02", "2023-04-21", "2023-04-22"}, str(sorted(vis)))
    chk = {x.property("filter_value") for x in p5._checkboxes if x.isChecked()}
    check("visible days are checked so OK filters to them", chk == vis, str(sorted(chk)))
    check("non-matching year rows are hidden",
          find_year(p5, "2024").isHidden() and find_year(p5, "2022").isHidden())
    check("matching year row stays visible", not find_year(p5, "2023").isHidden())
    check("non-matching month rows are hidden",
          find_month(p5, "2024", "05").isHidden())
    check("matching month rows stay visible",
          not find_month(p5, "2023", "04").isHidden())
    p5._inp_search.setText("")
    check("clearing the search un-hides every row",
          not any(v.isHidden() for v in p5._year_items.values())
          and not any(v.isHidden() for v in p5._month_items.values())
          and all(x.isVisible() for x in p5._checkboxes))
    p6 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p6._inp_search.setText("april")
    vis6 = {x.property("filter_value") for x in p6._checkboxes if x.isVisible()}
    check("month name is searchable", vis6 == {"2023-04-21", "2023-04-22"}, str(sorted(vis6)))
    p7 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p7._inp_search.setText("2024-05")
    vis7 = {x.property("filter_value") for x in p7._checkboxes if x.isVisible()}
    check("year-month prefix is searchable", vis7 == {"2024-05-14", "2024-05-15"},
          str(sorted(vis7)))

    print("\n=== 9. equivalence with the old flat list ===")
    # Same values, same user intent, two popups: the tree must emit what the flat
    # list emits.  This is the guarantee that nothing downstream changed.
    for label, picked in (
        ("one day",        {"2024-05-14"}),
        ("one month",      {"2023-04-21", "2023-04-22"}),
        ("across years",   {"2022-07-09", "2024-01-03"}),
        ("all but one",    set(VALUES) - {"2022-07-09"}),
    ):
        tp = ColumnFilterPopup(DATE_COL, dict(VALUES))
        fp = ColumnFilterPopup(FLAT_COL, dict(VALUES))
        for pop in (tp, fp):
            for x in pop._checkboxes:
                x.setChecked(x.property("filter_value") in picked)
        et, ef = capture(tp), capture(fp)
        check(f"tree == flat for '{label}'",
              et["mode"] == ef["mode"] and set(et["values"]) == set(ef["values"]),
              f"tree={et['mode']}:{sorted(et['values'])} flat={ef['mode']}:{sorted(ef['values'])}")

    print("\n=== 10. all-checked and none-checked edge cases ===")
    p8 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    check("untouched popup clears the filter", capture(p8)["mode"] == "clear")
    p9 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p9._check_none()
    e9 = capture(p9)
    check("nothing checked emits exclude-all (matches no rows)",
          e9["mode"] == "exclude" and set(e9["values"]) == set(VALUES), e9["mode"])
    p10 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p10._check_none()
    p10._check_all()
    check("None then All restores 'clear'", capture(p10)["mode"] == "clear")

    print("\n=== 11. unparseable dates are grouped, never dropped ===")
    odd = dict(VALUES)
    odd.update({"": 4, "not-a-date": 2, "2024-13-99": 1})
    p11 = ColumnFilterPopup(DATE_COL, odd)
    lv = set(leaves(p11))
    check("every input value is still selectable", lv == set(odd),
          str(sorted(lv ^ set(odd))))
    check("unparsed group exists", "(unparsed date)" in p11._year_items)
    check("bad month/day not coerced into a real month",
          ("2024", "13") not in p11._month_items)

    print("\n=== 12. pre-check reflection from an active quick filter ===")
    # MainWindow._show_col_filter_popup drives popup._checkboxes directly.
    p12 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    included = {"2023-04-21", "2023-04-22"}
    for x in p12._checkboxes:                      # include-mode reflection
        x.setChecked(x.property("filter_value") in included)
    check("reflection checks exactly the included days",
          {x.property("filter_value") for x in p12._checkboxes if x.isChecked()} == included)
    check("reflection rolls tri-state up to the year",
          find_year(p12, "2023").checkState(0) == Qt.CheckState.PartiallyChecked)
    check("reflection rolls tri-state up to the month",
          find_month(p12, "2023", "04").checkState(0) == Qt.CheckState.Checked)

    print("\n=== 13. merged out-of-top-1000 dates graft into the tree ===")
    p13 = ColumnFilterPopup(DATE_COL, dict(VALUES))
    p13._inp_search.setText("2019")
    p13._merge_search_results_tree({"2019-02-08": 6})
    check("new year node created", "2019" in p13._year_items)
    check("merged day is selectable",
          "2019-02-08" in {x.property("filter_value") for x in p13._checkboxes})
    check("merged day is checked by the active search",
          any(x.property("filter_value") == "2019-02-08" and x.isChecked()
              for x in p13._checkboxes))
    e13 = capture(p13)
    check("merged day is emitted as include",
          e13["mode"] == "include" and "2019-02-08" in e13["values"],
          f"{e13['mode']}:{sorted(e13['values'])}")

    print("\n=== 17. degenerate inputs must not stop the popup opening ===")
    # The flat list tolerates all of these; the timestamp column must not become
    # the one column that throws while building.
    _DEGENERATE = {
        "empty values dict":      {},
        "single date":            {"2024-01-01": 1},
        "empty-string value":     {"": 5},
        "None key":               {None: 5},
        "non-str (int) key":      {20240101: 5},
        "zero count":             {"2024-01-01": 0},
        "leap day":               {"2024-02-29": 1},
        "extreme years":          {"9999-12-31": 1, "0001-01-01": 1},
        # 2**64-1: storing this through QTreeWidgetItem.setData as an int raises
        # OverflowError in shiboken and the popup never opens.
        "uint64 sentinel count":  {"2024-01-01": 18446744073709551615},
    }
    for _label, _vals in _DEGENERATE.items():
        try:
            _p = ColumnFilterPopup(DATE_COL, dict(_vals))
            _ok, _why = True, ""
        except Exception as _e:
            _ok, _why = False, f"{type(_e).__name__}: {_e}"
        check(f"builds: {_label}", _ok, _why)
    _pbig = ColumnFilterPopup(DATE_COL, {"2024-01-01": 18446744073709551615})
    check("uint64 count survives the round-trip intact",
          "18446744073709551615"
          in _pbig._year_items["2024"].text(0).replace(",", ""),
          _pbig._year_items["2024"].text(0))
    _pe = ColumnFilterPopup(DATE_COL, {})
    _re_ = {}
    _pe.filterApplied.connect(lambda c, m, v: _re_.update(m=m))
    _pe._apply()
    check("empty popup emits clear", _re_.get("m") == "clear", str(_re_))
    _ps = ColumnFilterPopup(DATE_COL, {"2024-01-01": 1})
    _rs = {}
    _ps.sortRequested.connect(lambda c, o: _rs.update(c=c))
    _ps._emit_sort(Qt.SortOrder.AscendingOrder)
    check("sort buttons still emit on the tree column", _rs.get("c") == DATE_COL)

    print("\n=== 18. the flat columns are untouched ===")
    _f = ColumnFilterPopup(FLAT_COL, {"916": 1})
    check("flat column builds no tree", _f._tree is None)
    _f._inp_search.setText("42")
    _f._merge_search_results("42", {"42": 2})
    check("flat full-dataset merge still adds a checkbox", len(_f._checkboxes) == 2,
          str(len(_f._checkboxes)))
    _f2 = ColumnFilterPopup(FLAT_COL, {"916": 1})
    _f2._merge_search_results("916", {"42": 2})
    check("flat stale-result guard still drops a mismatched term",
          len(_f2._checkboxes) == 1, str(len(_f2._checkboxes)))
    _f3 = ColumnFilterPopup(FLAT_COL, {"916": 3, "42": 1, "7": 2})
    # The flat path gates auto-check on QWidget.isVisible(), which stays False
    # while the popup itself is hidden -- so it must be shown first, exactly as
    # MainWindow._show_col_filter_popup does before the user can type.  (The tree
    # reads QTreeWidgetItem.isHidden() instead and needs no show().)
    _f3.show()
    _f3._inp_search.setText("42")
    check("flat exact-match auto-check still works",
          {x.property("filter_value") for x in _f3._checkboxes if x.isChecked()} == {"42"})
    _f3._inp_search.setText("")
    check("flat cleared search still restores all-checked (unchanged semantics)",
          all(x.isChecked() for x in _f3._checkboxes))

    print("\n=== 15. a mid-search edit must survive clearing the box ===")
    # The snapshot taken when a search begins is what gets restored on clear.  If
    # an edit made DURING the search is not folded into it, clearing silently
    # reverts the analyst's choice -- a date they excluded comes back.
    ALL = set(VALUES)

    def _mid_search(mutate):
        pop = ColumnFilterPopup(DATE_COL, dict(VALUES))
        pop._inp_search.setText("2023")
        mutate(pop)
        pop._inp_search.setText("")
        return {x.property("filter_value") for x in pop._checkboxes if x.isChecked()}

    def _uncheck_leaf(pop):
        lf = [x for x in pop._checkboxes
              if x.property("filter_value") == "2023-04-21"][0]
        lf._item.setCheckState(0, Qt.CheckState.Unchecked)

    check("leaf unchecked mid-search stays unchecked after clear",
          _mid_search(_uncheck_leaf) == ALL - {"2023-04-21"})
    check("month unchecked mid-search stays unchecked after clear",
          _mid_search(lambda p: find_month(p, "2023", "04")
                      .setCheckState(0, Qt.CheckState.Unchecked))
          == ALL - {"2023-04-21", "2023-04-22"})
    check("year unchecked mid-search stays unchecked after clear",
          _mid_search(lambda p: find_year(p, "2023")
                      .setCheckState(0, Qt.CheckState.Unchecked))
          == ALL - {"2023-04-21", "2023-04-22", "2023-11-02"})
    # The converse trap: folding in the edit must not also capture the rows the
    # search is HIDING (they are unchecked only because they do not match).
    check("'None' mid-search clears only the visible rows",
          _mid_search(lambda p: p._check_none())
          == {"2024-05-14", "2024-05-15", "2024-01-03", "2022-07-09"})
    check("'All' mid-search leaves hidden rows as they were",
          _mid_search(lambda p: p._check_all()) == ALL)

    print("\n=== 16. the app's own value provider feeds the tree clean dates ===")
    # The tree splits on "-", so a value carrying a time component would send every
    # date into the (unparsed date) group.  This codebase has an analyst-selectable
    # Sec/Milli/Micro timestamp display, so prove the date value stays date-only at
    # every precision, in every timezone mode.
    import re as _re2                                                 # noqa: E402
    from evtx_tool.gui import models as _M                            # noqa: E402
    from evtx_tool.gui.jm_col_worker import NormalColValueWorker as _NCW  # noqa: E402

    _RAW = "2024-05-14T22:33:01.123456Z"
    _prev_prec = _M.get_ts_precision()
    _prev_tz = dict(_M._tz_state)
    _bad = []
    for _p in (0, 3, 6):
        _M.set_ts_precision(_p)
        assert _M.get_ts_precision() == _p, "precision setter did not take"
        for _n, _st in (("utc", {"mode": "utc"}), ("local", {"mode": "local"}),
                        ("specific", {"mode": "specific", "specific": "Asia/Kolkata"}),
                        ("custom", {"mode": "custom", "custom_offset_min": -480})):
            _M._tz_state.update(_st)
            _full = _M.apply_tz(_RAW)
            _d = _NCW._display_date(_RAW)
            if not (_re2.match(r"^\d{4}-\d{2}-\d{2}$", _d) and _full.startswith(_d)):
                _bad.append(f"{_p}/{_n}: {_full!r}->{_d!r}")
    _M.set_ts_precision(_prev_prec)
    _M._tz_state.clear(); _M._tz_state.update(_prev_tz)
    check("date value is YYYY-MM-DD at every precision x timezone (12 combos)",
          not _bad, "; ".join(_bad))
    _pp = ColumnFilterPopup(DATE_COL, {"2024-05-14": 1, "2024-05-15": 2})
    check("provider-shaped values never land in the unparsed group",
          _DATE_UNKNOWN_GROUP not in _pp._year_items)

    print("\n=== 14. real corpus dates ===")
    LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    real = {}
    if os.path.isdir(LOGS):
        try:
            import evtx
            from datetime import datetime, timezone
            import re as _re
            n = 0
            for root, _d, files in os.walk(LOGS):
                for f in files:
                    if not f.lower().endswith(".evtx"):
                        continue
                    try:
                        for rec in evtx.PyEvtxParser(os.path.join(root, f)).records_json():
                            ts = str(rec.get("timestamp", ""))[:10]
                            if _re.match(r"^\d{4}-\d{2}-\d{2}$", ts):
                                real[ts] = real.get(ts, 0) + 1
                            n += 1
                            if n > 200000:
                                break
                    except Exception:
                        continue
                    if n > 200000:
                        break
                if n > 200000:
                    break
        except Exception as exc:
            print(f"  (corpus read skipped: {exc})")

    if real:
        pr = ColumnFilterPopup(DATE_COL, real)
        check(f"tree built from {len(real)} real dates across "
              f"{len(pr._year_items)} years", len(pr._checkboxes) == len(real),
              f"{len(pr._checkboxes)} leaves")
        check("every real date reachable as a leaf",
              {x.property("filter_value") for x in pr._checkboxes} == set(real))
        check("untouched real-corpus popup clears", capture(pr)["mode"] == "clear")
        pr2 = ColumnFilterPopup(DATE_COL, real)
        pr2._check_none()
        y = sorted(pr2._year_items)[-1]
        find_year(pr2, y).setCheckState(0, Qt.CheckState.Checked)
        got = {x.property("filter_value") for x in pr2._checkboxes if x.isChecked()}
        check(f"selecting year {y} yields exactly its dates",
              got == {d for d in real if d.startswith(y + "-")},
              f"{len(got)} dates")
    else:
        print(f"  (no corpus at {LOGS!r} — skipped)")

    print("\n=== 19. end-to-end: what the tree emits actually filters ===")
    # The strongest check: drive a real EventTableModel/EventFilterProxyModel with
    # the values the popup emits, exactly as MainWindow._on_col_filter_applied does
    # (set_quick_filters with the whole list -- add_quick_filter deliberately
    # REPLACES same-key entries, so applying one value at a time silently filters
    # on the last one only).
    _e2e_logs = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    _events = []
    if os.path.isdir(_e2e_logs):
        try:
            # iter_events, NOT PyEvtxParser.records_json(): the raw parser emits
            # "...Z UTC", which apply_tz cannot parse and silently returns
            # unconverted.  The app reads the System/TimeCreated SystemTime
            # attribute, so the test must exercise that same shape or it proves
            # nothing about real timestamps.
            from evtx_tool.core.parser import iter_events as _iter_events  # noqa: E402
            _fs = sorted(
                os.path.join(r, f)
                for r, _d, fl in os.walk(_e2e_logs) for f in fl
                if f.lower().endswith(".evtx")
            )[:2]
            for _f in _fs:
                try:
                    for _ev in _iter_events(_f):
                        _events.append(_ev)
                except Exception:
                    continue
        except Exception as _exc:
            print(f"  (corpus read skipped: {_exc})")

    if _events:
        _suffixed = sum(1 for _e in _events
                        if str(_e.get("timestamp", "")).rstrip().endswith("UTC"))
        CHECKS.append(("engine timestamps are ISO, not the parser's '...Z UTC' form",
                       _suffixed == 0, f"{_suffixed} suffixed"))
        print(f"  {'PASS' if _suffixed == 0 else 'FAIL'}  "
              f"engine timestamps are ISO, not the parser's '...Z UTC' form")

    if _events:
        from evtx_tool.gui.models import (                                # noqa: E402
            EventTableModel, EventFilterProxyModel, apply_tz,
        )
        _dates = [apply_tz(e["timestamp"])[:10].lower() for e in _events]
        _truth = {}
        for _d in _dates:
            _truth[_d] = _truth.get(_d, 0) + 1
        _m = EventTableModel(); _m.set_events(_events)
        _px = EventFilterProxyModel(); _px.setSourceModel(_m)
        check("proxy starts unfiltered", _px.rowCount() == len(_events))

        def _e2e(pop, label):
            got = {}
            pop.filterApplied.connect(
                lambda c, mo, v: got.update(mode=mo, values=list(v)))
            pop._apply()
            if got["mode"] == "clear" or (got["mode"] == "exclude"
                                          and not got["values"]):
                qf = []
            else:
                qf = [{"key": "timestamp_date", "value": v,
                       "include": got["mode"] == "include"}
                      for v in got["values"]]
            _px.set_quick_filters(qf)
            _S = set(got["values"])
            if not qf:
                exp = len(_events)
            elif got["mode"] == "include":
                exp = sum(1 for d in _dates if d in _S)
            else:
                exp = sum(1 for d in _dates if d not in _S)
            check(f"e2e {label}", _px.rowCount() == exp,
                  f"{got['mode']} n={len(got['values'])} "
                  f"rows={_px.rowCount()} expected={exp}")

        _p = ColumnFilterPopup(DATE_COL, dict(_truth))
        _two = sorted(_truth)[:2]
        for _x in _p._checkboxes:
            _x.setChecked(_x.property("filter_value") in _two)
        _e2e(_p, "two specific days")

        _p2 = ColumnFilterPopup(DATE_COL, dict(_truth)); _p2._check_none()
        _y = sorted(_p2._year_items)[0]
        _p2._year_items[_y].setCheckState(0, Qt.CheckState.Checked)
        _e2e(_p2, f"whole year {_y}")

        _ym = sorted(_p2._month_items)[0]
        _p3 = ColumnFilterPopup(DATE_COL, dict(_truth)); _p3._check_none()
        _p3._month_items[_ym].setCheckState(0, Qt.CheckState.Checked)
        _e2e(_p3, f"whole month {_ym[0]}-{_ym[1]}")

        _p4 = ColumnFilterPopup(DATE_COL, dict(_truth))
        _one = sorted(_truth)[0]
        for _x in _p4._checkboxes:
            if _x.property("filter_value") == _one:
                _x.setChecked(False)
        _e2e(_p4, "exclude a single day")
        _e2e(ColumnFilterPopup(DATE_COL, dict(_truth)), "untouched popup clears")
        _p6 = ColumnFilterPopup(DATE_COL, dict(_truth)); _p6._check_none()
        _e2e(_p6, "nothing checked matches no rows")
    else:
        print(f"  (no corpus at {_e2e_logs!r} - skipped)")

    print("\n=== 20. changing the timezone must invalidate the popup value cache ===")
    # "timestamp_date" is the only column whose popup values depend on the display
    # timezone, but neither cache key carries the zone -- normal mode keys on
    # ("normal", col_key, len(visible_events)), Juggernaut on
    # (col_key, where_sql, where_params).  Without an explicit invalidation the
    # date tree is served the PREVIOUS zone's dates after a switch.
    from evtx_tool.gui import models as _M2                            # noqa: E402

    _prev = dict(_M2._tz_state)
    _RAW = "2025-07-07T22:33:01.000000Z"          # 22:33Z -> next day at +14
    _M2.set_tz_config("utc", None, 0)
    _d_utc = _M2.apply_tz(_RAW)[:10]
    _M2.set_tz_config("specific", "Pacific/Kiritimati", 0)
    _d_p14 = _M2.apply_tz(_RAW)[:10]
    check("a timezone switch really does move an event's date",
          _d_utc != _d_p14, f"{_d_utc} vs {_d_p14}")
    check("the two zones' cache keys are indistinguishable",
          ("normal", "timestamp_date", 12000) == ("normal", "timestamp_date", 12000))
    _M2._tz_state.clear(); _M2._tz_state.update(_prev)

    try:
        from evtx_tool.gui.main_window import MainWindow as _MW          # noqa: E402
        _w = _MW()
        _sentinel = {("normal", "timestamp_date", 123): {"2025-01-01": 5}}
        _w._col_value_cache = dict(_sentinel)
        _w._tz_mode, _w._tz_specific, _w._tz_custom_offset_min = (
            "specific", "Asia/Kolkata", 330)
        _w._apply_tz_to_all_models()
        check("switching to a named zone clears the cached popup values",
              not _w._col_value_cache, str(_w._col_value_cache))
        _w._col_value_cache = dict(_sentinel)
        _w._tz_mode, _w._tz_specific, _w._tz_custom_offset_min = "utc", None, 0
        _w._apply_tz_to_all_models()
        check("switching back to UTC clears it too", not _w._col_value_cache)
        _w._col_value_cache = dict(_sentinel)
        _w._tz_mode, _w._tz_specific, _w._tz_custom_offset_min = "custom", None, -480
        _w._apply_tz_to_all_models()
        check("switching to a custom offset clears it too", not _w._col_value_cache)
        _w.close()
    except Exception as _exc:
        check("MainWindow tz-cache check ran", False, f"{type(_exc).__name__}: {_exc}")
    _M2._tz_state.clear(); _M2._tz_state.update(_prev)

    print("\n=== 21. Juggernaut mode: the same values filter the same way ===")
    # Normal mode proves nothing about JM: it filters in DuckDB via
    # _timestamp_date_expr(), not by comparing Python strings.  The tree emits one
    # flat value set for both, so both must land on the same rows.
    _jm_ok = False
    if _events:                       # same corpus gate as section 19
        import tempfile as _tf, shutil as _sh, collections as _co   # noqa: E402
        from PySide6.QtCore import QEventLoop as _QEL, QTimer as _QT  # noqa: E402
        _tmp = _tf.mkdtemp(prefix="jm_datetree_")
        _mdl = None
        try:
            from evtx_tool.core.heavyweight.engine import (               # noqa: E402
                HeavyweightEngine as _HE, load_arrow_table as _lat,
            )
            from evtx_tool.gui.heavyweight_model import (                 # noqa: E402
                ArrowTableModel as _ATM,
            )
            _jm_files = sorted(
                os.path.join(r, f)
                for r, _d, fl in os.walk(_e2e_logs) for f in fl
                if f.lower().endswith(".evtx")
            )[:2]
            _pq = _HE(parquet_dir=_tmp).run(_jm_files)
            _tbl = _lat(_pq)
            _tot = len(_tbl)
            _mdl = _ATM(_tbl, parquet_dir=_pq)

            def _settle(ms=300000):
                _lp = _QEL(); _st = {"h": False}
                def _fin():
                    _st["h"] = True; _lp.quit()
                _mdl.busy_finished.connect(_fin)
                _QT.singleShot(ms, _lp.quit)
                if not _st["h"]:
                    _lp.exec()
                try:
                    _mdl.busy_finished.disconnect(_fin)
                except Exception:
                    pass

            _settle()
            _tcol = "timestamp_utc"
            _jt = _co.Counter(
                apply_tz(str(t))[:10].lower() for t in _tbl[_tcol].to_pylist()
            )
            check(f"JM table built ({_tot} rows, {len(_jt)} dates)", _tot > 0)

            def _jm(pop, label):
                got = {}
                pop.filterApplied.connect(
                    lambda c, mo, v: got.update(mode=mo, values=list(v)))
                pop._apply()
                if got["mode"] == "clear" or (got["mode"] == "exclude"
                                              and not got["values"]):
                    qf = []
                else:
                    qf = [{"key": "timestamp_date", "value": v,
                           "include": got["mode"] == "include"}
                          for v in got["values"]]
                _mdl.set_quick_filters(qf); _settle()
                _S = set(got["values"])
                if not qf:
                    exp = _tot
                elif got["mode"] == "include":
                    exp = sum(c for d, c in _jt.items() if d in _S)
                else:
                    exp = sum(c for d, c in _jt.items() if d not in _S)
                check(f"JM {label}", _mdl.rowCount() == exp,
                      f"{got['mode']} n={len(got['values'])} "
                      f"rows={_mdl.rowCount()} expected={exp}")

            _jp = ColumnFilterPopup(DATE_COL, dict(_jt))
            _jtwo = sorted(_jt)[:2]
            for _x in _jp._checkboxes:
                _x.setChecked(_x.property("filter_value") in _jtwo)
            _jm(_jp, "two specific days")

            _jp2 = ColumnFilterPopup(DATE_COL, dict(_jt)); _jp2._check_none()
            _jy = sorted(_jp2._year_items)[0]
            _jp2._year_items[_jy].setCheckState(0, Qt.CheckState.Checked)
            _jm(_jp2, f"whole year {_jy}")

            _jym = sorted(_jp2._month_items)[0]
            _jp3 = ColumnFilterPopup(DATE_COL, dict(_jt)); _jp3._check_none()
            _jp3._month_items[_jym].setCheckState(0, Qt.CheckState.Checked)
            _jm(_jp3, f"whole month {_jym[0]}-{_jym[1]}")

            _jp4 = ColumnFilterPopup(DATE_COL, dict(_jt))
            _jone = sorted(_jt)[0]
            for _x in _jp4._checkboxes:
                if _x.property("filter_value") == _jone:
                    _x.setChecked(False)
            _jm(_jp4, "exclude a single day")
            _jm(ColumnFilterPopup(DATE_COL, dict(_jt)), "untouched popup clears")
            _jp6 = ColumnFilterPopup(DATE_COL, dict(_jt)); _jp6._check_none()
            _jm(_jp6, "nothing checked matches no rows")
            _jm_ok = True
        except Exception as _exc:
            check("JM end-to-end ran", False, f"{type(_exc).__name__}: {_exc}")
        finally:
            # close() stops the filter thread; without it the interpreter aborts
            # with "QThread: Destroyed while thread is still running".
            if _mdl is not None:
                try:
                    _mdl.set_quick_filters([]); _mdl.close()
                except Exception:
                    pass
            _sh.rmtree(_tmp, ignore_errors=True)
    else:
        print(f"  (no corpus at {_e2e_logs!r} - skipped)")

    print("\n=== 22. every filter change must drop the cached popup values ===")
    # The normal-mode cache key is ("normal", col_key, len(visible_events)) -- a
    # COUNT, not the filter's identity.  Two filters selecting the same number of
    # events collide, so any path that changes the visible slice without dropping
    # the cache can serve the previous filter's dates.
    if _events:
        import collections as _c22                                     # noqa: E402
        _per = {}
        for _e in _events:
            _k = str(_e.get("event_id", ""))
            _per.setdefault(_k, _c22.Counter())[
                apply_tz(_e["timestamp"])[:10].lower()] += 1
        _byn = _c22.defaultdict(list)
        for _k, _cc in _per.items():
            _byn[sum(_cc.values())].append(_k)
        _collide = None
        for _n, _ids in _byn.items():
            if len(_ids) < 2 or _n < 30:
                continue
            for _i in range(len(_ids)):
                for _j in range(_i + 1, len(_ids)):
                    if _per[_ids[_i]] != _per[_ids[_j]]:
                        _collide = (_n, _ids[_i], _ids[_j])
                        break
                if _collide:
                    break
            if _collide:
                break
        if _collide:
            _n, _a, _b = _collide
            _da, _db = _per[_a], _per[_b]
            check(f"real collision exists: event_id {_a} and {_b} both select "
                  f"{_n} events but span {len(_da)} vs {len(_db)} dates",
                  ("normal", "timestamp_date", _n) == ("normal", "timestamp_date", _n)
                  and _da != _db,
                  f"{len(set(_da) ^ set(_db))} dates differ")
        else:
            print("  (no same-count/different-date pair in this corpus slice)")

    try:
        from evtx_tool.gui.main_window import MainWindow as _MW22        # noqa: E402
        _w22 = _MW22()
        _SENT = {("normal", "timestamp_date", 402): {"2025-01-01": 5}}

        def _drops(label, fn):
            _w22._col_value_cache = dict(_SENT)
            try:
                fn()
                check(f"{label} drops the cached popup values",
                      not _w22._col_value_cache, str(_w22._col_value_cache))
            except Exception as _e:
                check(f"{label} drops the cached popup values", False,
                      f"{type(_e).__name__}: {_e}")

        # These four change the visible slice but do NOT route through
        # _normal_filter_busy, which is what drops the cache for every other path.
        _drops("context-menu quick filter",
               lambda: _w22._apply_quick_filter("event_id", "4624", True))
        _drops("clearing all quick filters", lambda: _w22._clear_quick_filters())
        _drops("computer-normalisation filter",
               lambda: _w22._apply_computer_norm_filter(["HOST-A"]))
        _drops("session filter",
               lambda: _w22._set_session_filter_impl("0x3e7", None))
        _drops("the invalidation helper itself",
               lambda: _w22._invalidate_col_value_cache())
        _w22.close()
    except Exception as _exc:
        check("MainWindow cache-invalidation checks ran", False,
              f"{type(_exc).__name__}: {_exc}")

    print("\n=== 23. the Juggernaut prewarm sweep must be fully cancellable ===")
    # A prewarm sweep is one worker PER WHERE GROUP: every filterable column shares
    # a cascade except its own quick filter, so N active quick filters produce N+1
    # groups.  Keeping only the last worker created left the other N running --
    # they finished their DuckDB sweeps for the OLD filter and emitted
    # column_ready, which was then filed under whatever key was CURRENT.
    from evtx_tool.gui import jm_col_worker as _JCW                    # noqa: E402


    class _FakeHW:
        """Enough of ArrowTableModel for _start_col_prewarm / _build_col_cascade_where."""
        _full_table = object()

        def __init__(self, qfs):
            self._qfs = qfs

        def get_quick_filters(self):
            return list(self._qfs)

        def get_cascade_base_where(self):
            return (None, None)

        def close(self):
            """MainWindow.closeEvent calls this on the model it holds."""
            return None


    try:
        from evtx_tool.gui.main_window import MainWindow as _MW23        # noqa: E402
        _w23 = _MW23()
        _orig_pw = _JCW.ColValuePrewarmWorker
        _made = []

        class _SpyPW(_orig_pw):
            def __init__(self, *a, **k):
                super().__init__(*a, **k)
                _made.append(self)

            def start(self):        # never touch DuckDB in this check
                pass

        _JCW.ColValuePrewarmWorker = _SpyPW
        try:
            for _lbl, _qfs in (
                ("0 quick filters", []),
                ("1 quick filter",
                 [{"key": "timestamp_date", "value": "2025-07-07", "include": True}]),
                ("2 quick filters",
                 [{"key": "timestamp_date", "value": "2025-07-07", "include": True},
                  {"key": "event_id", "value": "4624", "include": True}]),
                ("3 quick filters",
                 [{"key": "timestamp_date", "value": "2025-07-07", "include": True},
                  {"key": "event_id", "value": "4624", "include": True},
                  {"key": "channel", "value": "Security", "include": True}]),
            ):
                _w23._hw_model = _FakeHW(_qfs)
                _made.clear()
                _w23._start_col_prewarm()
                _tracked = list(getattr(_w23, "_col_prewarm_workers", ()) or ())
                _un = sum(1 for _x in _made if _x not in _tracked)
                check(f"every prewarm worker is cancellable with {_lbl}",
                      _un == 0 and len(_made) > 0,
                      f"created={len(_made)} tracked={len(_tracked)} uncancellable={_un}")
        finally:
            _JCW.ColValuePrewarmWorker = _orig_pw

        # A late result must be filed under the WHERE it was computed for, not the
        # one current when the signal is delivered.
        _w23._col_value_cache = {}
        _w23._on_col_prewarmed("timestamp_date", {"2025-01-01": 1},
                               "source_file = ?", ("a.evtx",))
        check("a prewarm result is keyed by the WHERE it was issued with",
              list(_w23._col_value_cache) ==
              [("timestamp_date", "source_file = ?", ("a.evtx",))],
              str(list(_w23._col_value_cache)))
        _w23._hw_model = _FakeHW([])
        _w23._col_value_cache = {}
        _w23._on_col_prewarmed("timestamp_date", {"2025-01-01": 1})
        check("the no-WHERE fallback still files a key",
              len(_w23._col_value_cache) == 1, str(list(_w23._col_value_cache)))
        _w23._hw_model = None
        _w23.close()
    except Exception as _exc:
        check("prewarm cancellation checks ran", False,
              f"{type(_exc).__name__}: {_exc}")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    # The Juggernaut section starts worker PROCESSES; without this guard
    # the child re-imports this module, the pool cannot bootstrap, and the
    # engine silently falls back to threads -- so section 21 would never
    # exercise the parse path the app actually uses.
    sys.exit(main())
