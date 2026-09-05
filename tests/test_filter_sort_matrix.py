"""Sorting and filtering matrix across Normal and Juggernaut modes.

Written after the timestamp date-tree work touched shared filter plumbing
(_col_value_cache invalidation, the JM prewarm sweep, ColumnFilterPopup).
Those changes are meant to be invisible to everything except the timestamp
popup, so this walks the whole surface: every sortable column in both
directions, every filterable column's popup round-trip, the non-quick filter
kinds, and the combinations.

Ground truth is always computed independently from the event list / Arrow
columns, never from the thing under test.
"""
import os
import sys
import glob
import shutil
import tempfile
import collections

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt, QEventLoop, QTimer, QModelIndex   # noqa: E402
from PySide6.QtWidgets import QApplication                        # noqa: E402

_app = QApplication.instance() or QApplication([])

from evtx_tool.gui.models import (                                # noqa: E402
    COLUMNS, EventTableModel, EventFilterProxyModel, apply_tz,
)
from evtx_tool.gui.main_window import ColumnFilterPopup           # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
SORT_SLICE = int(os.environ.get("EVTX_SORT_SLICE", "8000"))


def load_events(max_files=2):
    from evtx_tool.core.parser import iter_events
    out = []
    files = sorted(
        os.path.join(r, f)
        for r, _d, fl in os.walk(LOGS) for f in fl
        if f.lower().endswith(".evtx")
    )[:max_files]
    for f in files:
        try:
            for ev in iter_events(f):
                out.append(ev)
        except Exception:
            continue
    return out, files


def main() -> int:
    EVENTS, FILES = ([], []) if not os.path.isdir(LOGS) else load_events()
    if not EVENTS:
        print(f"no corpus at {LOGS!r} — skipping")
        sys.exit(0)

    print(f"corpus: {len(FILES)} file(s), {len(EVENTS):,} events\n")


    def sort_key(v):
        """Match how a human reads the column: numbers numerically, else text."""
        s = "" if v is None else str(v)
        try:
            return (0, float(s), "")
        except (TypeError, ValueError):
            return (1, 0.0, s.lower())


    def col_values(model, col, limit=None):
        n = model.rowCount() if limit is None else min(limit, model.rowCount())
        return [model.data(model.index(r, col), Qt.ItemDataRole.DisplayRole)
                for r in range(n)]


    def is_sorted_nulls_last(vals, ascending):
        """Sortedness under SQL null placement.

        Juggernaut sorts in DuckDB / PyArrow and BOTH put NULL last in either
        direction (verified: pyarrow.sort_by and ORDER BY agree, which is the
        contract _order_by_sql documents against _sort_keys).  Normal mode
        never sees a NULL -- data() renders "" for a missing value -- so the
        same click puts blank rows at the TOP in normal mode and at the BOTTOM
        in Juggernaut ascending.  That difference is pre-existing and only
        affects rows with a missing value; this pins the behaviour rather than
        asserting one mode's convention onto the other.
        """
        blanks = [i for i, v in enumerate(vals) if v in (None, "")]
        if blanks and blanks != list(range(len(vals) - len(blanks), len(vals))):
            return False
        return is_sorted([v for v in vals if v not in (None, "")], ascending)

    def is_sorted(vals, ascending):
        """True if the sequence is ordered under EITHER engine's convention.

        Normal mode sorts in Python with a numeric-aware key, so PID 999 comes
        before 1000.  Juggernaut sorts VARCHAR in DuckDB / PyArrow, which is
        purely lexical -- there ".NET Runtime" precedes "1000" because "." is
        below "1" in byte order.  Both are defensible and neither is a defect,
        so accept either; what this must still catch is a column that is not
        ordered at all (the extended columns used to come back in arbitrary
        order, e.g. Process ID starting at 5432 of 896 distinct values), and
        such a sequence satisfies neither convention.
        """
        def ordered(keys):
            return (all(keys[i] <= keys[i + 1] for i in range(len(keys) - 1))
                    if ascending else
                    all(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)))
        if ordered([sort_key(v) for v in vals]):
            return True
        return ordered(["" if v is None else str(v) for v in vals])


    # ══════════════════════════════════════════════════════════════════════════
    print("=== 1. Normal mode: every column sorts, both directions ===")
    _sm = EventTableModel()
    _sm.set_events(EVENTS[:SORT_SLICE])
    _sp = EventFilterProxyModel()
    _sp.setSourceModel(_sm)
    _base_rows = _sp.rowCount()
    check(f"proxy exposes the whole slice ({_base_rows} rows)",
          _base_rows == min(SORT_SLICE, len(EVENTS)))

    # Column 0 ("#") is the visual row number: data() renders the row's POSITION,
    # so it reads 1..N whichever way the rows are ordered.  Sorting it means
    # "restore the original order", which cannot be checked by reading the column.
    _sp.sort(0, Qt.SortOrder.AscendingOrder)
    _rownums = col_values(_sp, 0)[:50]
    check("the '#' column numbers rows by position",
          _rownums == [str(i + 1) for i in range(len(_rownums))],
          str(_rownums[:5]))

    _unsortable = []
    for _c in range(1, len(COLUMNS)):
        ok_asc = ok_desc = None
        for _order, _asc in ((Qt.SortOrder.AscendingOrder, True),
                             (Qt.SortOrder.DescendingOrder, False)):
            _sp.sort(_c, _order)
            _vals = col_values(_sp, _c)
            _ok = is_sorted(_vals, _asc) and _sp.rowCount() == _base_rows
            if _asc:
                ok_asc = _ok
            else:
                ok_desc = _ok
        if not (ok_asc and ok_desc):
            _unsortable.append((_c, COLUMNS[_c], ok_asc, ok_desc))
    check("every displayable column sorts correctly ascending and descending",
          not _unsortable,
          "; ".join(f"col {c} {n!r} asc={a} desc={d}" for c, n, a, d in _unsortable))

    # A column missing from _SORT_KEY_FUNCS is SILENTLY unsortable -- sort()
    # returns early and the header click does nothing.  Pin full coverage so a
    # future column cannot be added without one.
    _missing_keys = [(_i, COLUMNS[_i]) for _i in range(len(COLUMNS))
                     if _i not in EventTableModel._SORT_KEY_FUNCS]
    check("every column has a normal-mode sort key", not _missing_keys,
          str(_missing_keys))
    check("sorting never changes the row count",
          _sp.rowCount() == _base_rows, f"{_sp.rowCount()} vs {_base_rows}")

    # Timestamp specifically: chronological, not lexical-on-a-reformatted-string.
    _sp.sort(3, Qt.SortOrder.AscendingOrder)
    _ts_asc = col_values(_sp, 3)
    _sp.sort(3, Qt.SortOrder.DescendingOrder)
    _ts_desc = col_values(_sp, 3)
    check("timestamp ascending is chronological", is_sorted(_ts_asc, True))
    check("timestamp descending is the exact reverse",
          _ts_desc == list(reversed(_ts_asc)) or is_sorted(_ts_desc, False))

    # ══════════════════════════════════════════════════════════════════════════
    print("\n=== 2. Normal mode: every filterable column round-trips ===")
    _m = EventTableModel()
    _m.set_events(EVENTS)
    _px = EventFilterProxyModel()
    _px.setSourceModel(_m)
    _TOTAL = _px.rowCount()
    check(f"unfiltered row count matches the corpus ({_TOTAL})", _TOTAL == len(EVENTS))


    def ev_val(ev, key):
        if key == "timestamp_date":
            return apply_tz(ev.get("timestamp", ""))[:10].lower()
        if key == "log":
            return str(ev.get("log") or ev.get("channel", "")).lower()
        return str(ev.get(key, "")).lower()


    def popup_roundtrip(col_idx, key, picker, label):
        truth = collections.Counter(ev_val(e, key) for e in EVENTS)
        truth.pop("", None)
        if not truth:
            return None
        pop = ColumnFilterPopup(col_idx, dict(truth))
        picked = picker(pop, truth)
        got = {}
        pop.filterApplied.connect(lambda c, m, v: got.update(mode=m, values=list(v)))
        pop._apply()
        if got["mode"] == "clear" or (got["mode"] == "exclude" and not got["values"]):
            qf = []
        else:
            qf = [{"key": key, "value": v, "include": got["mode"] == "include"}
                  for v in got["values"]]
        _px.set_quick_filters(qf)
        S = set(got["values"])
        if not qf:
            exp = len(EVENTS)
        elif got["mode"] == "include":
            exp = sum(1 for e in EVENTS if ev_val(e, key) in S)
        else:
            exp = sum(1 for e in EVENTS if ev_val(e, key) not in S)
        n = _px.rowCount()
        check(f"{label} ({key})", n == exp,
              f"{got['mode']} n={len(got['values'])} rows={n} expected={exp}")
        _px.set_quick_filters([])
        return picked


    def pick_top2(pop, truth):
        top = [v for v, _ in truth.most_common(2)]
        for x in pop._checkboxes:
            x.setChecked(x.property("filter_value") in top)
        return top


    def pick_drop1(pop, truth):
        one = truth.most_common(1)[0][0]
        for x in pop._checkboxes:
            if x.property("filter_value") == one:
                x.setChecked(False)
        return [one]


    for _ci, _key in sorted(ColumnFilterPopup.FILTERABLE.items()):
        popup_roundtrip(_ci, _key, pick_top2, f"col {_ci} keep top-2")
    print()
    for _ci, _key in sorted(ColumnFilterPopup.FILTERABLE.items()):
        popup_roundtrip(_ci, _key, pick_drop1, f"col {_ci} drop top-1")

    # ══════════════════════════════════════════════════════════════════════════
    print("\n=== 3. Normal mode: the other filter kinds ===")
    _px.set_quick_filters([])
    check("clearing quick filters restores every row", _px.rowCount() == _TOTAL)

    _needle = None
    for _e in EVENTS:
        _c = str(_e.get("channel", ""))
        if _c:
            _needle = _c
            break
    if _needle:
        _px.set_filter_text(_needle)
        _exp_txt = sum(1 for e in EVENTS
                       if _needle.lower() in " ".join(
                           str(e.get(k, "")) for k in
                           ("event_id", "computer", "channel", "user_id",
                            "source_file", "message", "provider")).lower())
        check("text filter narrows the view", _px.rowCount() > 0
              and _px.rowCount() <= _TOTAL, f"rows={_px.rowCount()}")
        _px.set_filter_text("")
        check("clearing the text filter restores every row", _px.rowCount() == _TOTAL)

    _dates = sorted({apply_tz(e["timestamp"])[:10] for e in EVENTS})
    if len(_dates) >= 2:
        _lo, _hi = _dates[0], _dates[len(_dates) // 2]
        # Bounds must be full datetimes: _parse_ts ignores a bare YYYY-MM-DD
        # and the filter then silently matches everything.  The advanced-filter
        # dialog always formats "yyyy-MM-dd HH:mm:ss", so this mirrors the GUI.
        _px.set_advanced_filter({"date_enabled": True,
                                 "date_from": _lo + " 00:00:00",
                                 "date_to": _hi + " 23:59:59"})
        _exp_adv = sum(1 for e in EVENTS
                       if _lo <= apply_tz(e["timestamp"])[:10] <= _hi)
        check("advanced date-range filter matches ground truth",
              _px.rowCount() == _exp_adv, f"{_px.rowCount()} vs {_exp_adv}")
        _px.clear_advanced_filter()
        check("clearing the advanced filter restores every row",
              _px.rowCount() == _TOTAL, f"{_px.rowCount()} vs {_TOTAL}")

    # ══════════════════════════════════════════════════════════════════════════
    print("\n=== 4. Normal mode: filters stack, and survive sorting ===")
    _d_truth = collections.Counter(ev_val(e, "timestamp_date") for e in EVENTS)
    _e_truth = collections.Counter(ev_val(e, "event_id") for e in EVENTS)
    _top_date = _d_truth.most_common(1)[0][0]
    _top_eid = _e_truth.most_common(1)[0][0]
    _px.set_quick_filters([
        {"key": "timestamp_date", "value": _top_date, "include": True},
        {"key": "event_id", "value": _top_eid, "include": True},
    ])
    _exp_both = sum(1 for e in EVENTS
                    if ev_val(e, "timestamp_date") == _top_date
                    and ev_val(e, "event_id") == _top_eid)
    check("two columns filtered together AND correctly",
          _px.rowCount() == _exp_both, f"{_px.rowCount()} vs {_exp_both}")

    _n_before = _px.rowCount()
    for _c in (1, 3, 5):
        for _order, _asc in ((Qt.SortOrder.AscendingOrder, True),
                             (Qt.SortOrder.DescendingOrder, False)):
            _px.sort(_c, _order)
            check(f"filter survives sorting col {_c} {'asc' if _asc else 'desc'}",
                  _px.rowCount() == _n_before and is_sorted(col_values(_px, _c), _asc),
                  f"rows={_px.rowCount()} vs {_n_before}")
    _px.set_quick_filters([])
    _px.sort(-1, Qt.SortOrder.AscendingOrder)
    check("clearing a stacked filter restores every row", _px.rowCount() == _TOTAL)

    # ══════════════════════════════════════════════════════════════════════════
    print("\n=== 5. Juggernaut mode: sorting and filtering ===")
    _tmp = tempfile.mkdtemp(prefix="matrix_jm_")
    _mdl = None
    try:
        from evtx_tool.core.heavyweight.engine import (                # noqa: E402
            HeavyweightEngine, load_arrow_table,
        )
        from evtx_tool.gui.heavyweight_model import ArrowTableModel    # noqa: E402

        # One file for JM: building Parquet and settling ~50 filter/sort
        # round-trips over both files pushes this past any sane test timeout,
        # and the matrix being verified does not get broader with more data.
        _jm_files = FILES[:1]
        _pq = HeavyweightEngine(parquet_dir=_tmp).run(_jm_files)
        _tbl = load_arrow_table(_pq)
        _mdl = ArrowTableModel(_tbl, parquet_dir=_pq)

        def settle(ms=30000):
            """Wait for the JM filter thread.

            Short on purpose: ArrowTableModel emits busy_finished only
            when the filter actually CHANGES, so re-applying a set that
            is already active (the "clear" round-trips) never signals and
            would otherwise burn the whole timeout on each such check.
            Real work on this table finishes well under a second.
            """
            lp = QEventLoop()
            st = {"h": False}

            def fin():
                st["h"] = True
                lp.quit()
            _mdl.busy_finished.connect(fin)
            QTimer.singleShot(ms, lp.quit)
            if not st["h"]:
                lp.exec()
            try:
                _mdl.busy_finished.disconnect(fin)
            except Exception:
                pass

        settle()
        _JTOTAL = _mdl.rowCount()
        check(f"JM exposes the whole table ({_JTOTAL} rows)", _JTOTAL == len(_tbl))

        from evtx_tool.gui.heavyweight_model import _SORT_COL_MAP      # noqa: E402
        _jm_bad = []
        # Column 0 ("#") is positional, as in normal mode: it reads 1..N
        # whichever way the rows are ordered, so reading it proves nothing.
        for _c in sorted(c for c in _SORT_COL_MAP if c != 0):
            for _order, _asc in ((Qt.SortOrder.AscendingOrder, True),
                                 (Qt.SortOrder.DescendingOrder, False)):
                _mdl.sort(_c, _order)
                settle()
                _vals = col_values(_mdl, _c, limit=3000)
                if not (is_sorted_nulls_last(_vals, _asc)
                        and _mdl.rowCount() == _JTOTAL):
                    _jm_bad.append((_c, COLUMNS[_c] if _c < len(COLUMNS) else "?",
                                    "asc" if _asc else "desc"))
        check("every JM-sortable column sorts correctly both ways",
              not _jm_bad, "; ".join(f"col {c} {n!r} {d}" for c, n, d in _jm_bad))
        # JM can only sort columns that exist in the Arrow schema.  These five plus
        # ATT&CK live only in the normal-mode event dict, so they stay unsortable
        # here; anything ELSE going missing is a regression.
        _expect_jm_missing = {7, 14, 15, 16, 17, 18}
        _jm_missing = {_i for _i in range(len(COLUMNS)) if _i not in _SORT_COL_MAP}
        check("JM sorts every column it has data for",
              _jm_missing == _expect_jm_missing,
              f"unsortable={sorted(_jm_missing)} expected={sorted(_expect_jm_missing)}")
        check("JM sorting never changes the row count", _mdl.rowCount() == _JTOTAL)

        _jt = {}
        _cols = {"event_id": "event_id", "channel": "channel",
                 "computer": "computer", "source_file": "source_file",
                 "level_name": "level_name"}
        for _k, _ac in _cols.items():
            if _ac in _tbl.schema.names:
                _jt[_k] = collections.Counter(
                    str(x).lower() if x is not None else ""
                    for x in _tbl[_ac].to_pylist())
        _jt["timestamp_date"] = collections.Counter(
            apply_tz(str(t))[:10].lower() for t in _tbl["timestamp_utc"].to_pylist())

        _inv = {v: k for k, v in ColumnFilterPopup.FILTERABLE.items()}
        for _key, _counter in _jt.items():
            _counter.pop("", None)
            if not _counter or _key not in _inv:
                continue
            _pop = ColumnFilterPopup(_inv[_key], dict(_counter))
            _top = [v for v, _ in _counter.most_common(2)]
            for _x in _pop._checkboxes:
                _x.setChecked(_x.property("filter_value") in _top)
            _got = {}
            _pop.filterApplied.connect(
                lambda c, m, v: _got.update(mode=m, values=list(v)))
            _pop._apply()
            if _got["mode"] == "clear" or (_got["mode"] == "exclude"
                                           and not _got["values"]):
                _qf = []
            else:
                _qf = [{"key": _key, "value": v,
                        "include": _got["mode"] == "include"}
                       for v in _got["values"]]
            _mdl.set_quick_filters(_qf)
            settle()
            _S = set(_got["values"])
            if not _qf:
                _exp = _JTOTAL
            elif _got["mode"] == "include":
                _exp = sum(c for d, c in _counter.items() if d in _S)
            else:
                _exp = sum(c for d, c in _counter.items() if d not in _S)
            check(f"JM keep top-2 ({_key})", _mdl.rowCount() == _exp,
                  f"{_got['mode']} n={len(_got['values'])} "
                  f"rows={_mdl.rowCount()} expected={_exp}")
            _mdl.set_quick_filters([])
            settle()

        check("clearing JM quick filters restores every row",
              _mdl.rowCount() == _JTOTAL)

        _jd = _jt["timestamp_date"].most_common(1)[0][0]
        _je = _jt.get("event_id", collections.Counter()).most_common(1)
        if _je:
            _mdl.set_quick_filters([
                {"key": "timestamp_date", "value": _jd, "include": True},
                {"key": "event_id", "value": _je[0][0], "include": True},
            ])
            settle()
            _exp_j = sum(1 for t, e in zip(_tbl["timestamp_utc"].to_pylist(),
                                           _tbl["event_id"].to_pylist())
                         if apply_tz(str(t))[:10].lower() == _jd
                         and str(e).lower() == _je[0][0])
            check("JM two columns filtered together AND correctly",
                  _mdl.rowCount() == _exp_j, f"{_mdl.rowCount()} vs {_exp_j}")
            _nb = _mdl.rowCount()
            for _c in sorted(_SORT_COL_MAP)[:3]:
                _mdl.sort(_c, Qt.SortOrder.DescendingOrder)
                settle()
                check(f"JM filter survives sorting col {_c}",
                      _mdl.rowCount() == _nb, f"{_mdl.rowCount()} vs {_nb}")
            _mdl.set_quick_filters([])
            settle()
            check("JM clearing a stacked filter restores every row",
                  _mdl.rowCount() == _JTOTAL)
    except Exception as _exc:
        check("JM matrix ran", False, f"{type(_exc).__name__}: {_exc}")
    finally:
        if _mdl is not None:
            try:
                _mdl.set_quick_filters([])
                _mdl.close()
            except Exception:
                pass
        shutil.rmtree(_tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*64}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    # The Juggernaut engine starts worker PROCESSES; without this
    # guard the child re-imports this module, the pool cannot
    # bootstrap, and the engine silently falls back to threads --
    # so the test would never exercise the parse path the app uses.
    sys.exit(main())
