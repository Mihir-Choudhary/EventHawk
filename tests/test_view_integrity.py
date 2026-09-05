"""View integrity: sorting must not change WHAT you see, only the order.

Guards the sort-key work directly.  EventTableModel.sort() physically reorders
_events, _search_cache and _adv_search_cache together; giving 12 more columns a
sort key means that reorder now runs in many more situations.  If those lists
ever drift apart, a text search after sorting would quietly return the wrong
rows -- evidence hidden with nothing on screen to say so.

Also covers the export "view" scope (what an analyst believes they exported)
and separate-tabs isolation.
"""
import os
import sys
import glob
import collections

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt                                     # noqa: E402
from PySide6.QtWidgets import QApplication, QTableView            # noqa: E402

_app = QApplication.instance() or QApplication([])

from evtx_tool.gui.models import (                                # noqa: E402
    COLUMNS, EventTableModel, EventFilterProxyModel, apply_tz,
)

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    if not os.path.isdir(LOGS):
        print(f"no corpus at {LOGS!r} — skipping")
        return 0
    from evtx_tool.core.parser import iter_events
    files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:2]
    per = {}
    for f in files:
        per[f] = [e for e in iter_events(f)][:6000]
    evs = [e for v in per.values() for e in v]
    if not evs:
        print("no events — skipping")
        return 0
    print(f"corpus: {len(files)} file(s), {len(evs):,} events\n")

    m = EventTableModel(); m.set_events(evs)
    px = EventFilterProxyModel(); px.setSourceModel(m)
    TOTAL = px.rowCount()

    def ident(ev):
        """Identity that survives reordering."""
        return (str(ev.get("source_file", "")), ev.get("record_id"))

    def matched(needle, col, order):
        px.set_filter_text("")
        px.sort(col, order)
        px.set_filter_text(needle)
        s = {ident(px.get_source_event(r)) for r in range(px.rowCount())}
        n = px.rowCount()
        px.set_filter_text("")
        return s, n

    print("=== 1. a text search returns the same rows under every sort ===")
    # Includes all 12 columns that only became sortable with the sort-key work.
    COLS = [1, 2, 3, 4, 5, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 21]
    # Only needles that select a PROPER subset are worth checking: one that
    # matches every row (or none) is sort-invariant no matter what is broken.
    needles = []
    for k in ("provider", "channel", "computer", "event_id"):
        for cand, _n in collections.Counter(
                str(e.get(k, "")) for e in evs).most_common(6):
            if not cand or len(cand) < 3 or cand in needles:
                continue
            _s, _n2 = matched(cand, 3, Qt.SortOrder.AscendingOrder)
            if 0 < _n2 < TOTAL:
                needles.append(cand)
                break
    check("found needles that select a proper subset", len(needles) >= 2,
          str(needles))
    for needle in needles:
        ref, refn = matched(needle, 3, Qt.SortOrder.AscendingOrder)
        bad = []
        for c in COLS:
            for o, nm in ((Qt.SortOrder.AscendingOrder, "asc"),
                          (Qt.SortOrder.DescendingOrder, "desc")):
                s, n = matched(needle, c, o)
                if s != ref or n != refn:
                    bad.append(f"{COLUMNS[c]}/{nm}: {n} vs {refn}, {len(s ^ ref)} differ")
        check(f"'{needle}' matches the same {refn} rows across {2*len(COLS)} sorts",
              not bad, "; ".join(bad[:3]))

    print("\n=== 2. sorting never adds or drops rows ===")
    bad = []
    for c in COLS:
        for o in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
            px.sort(c, o)
            if px.rowCount() != TOTAL:
                bad.append(f"{COLUMNS[c]}: {px.rowCount()}")
    check(f"row count stays {TOTAL} across every sort", not bad, "; ".join(bad[:3]))
    # and with a filter on
    dcount = collections.Counter(apply_tz(e["timestamp"])[:10].lower() for e in evs)
    top_d = dcount.most_common(1)[0][0]
    px.set_quick_filters([{"key": "timestamp_date", "value": top_d, "include": True}])
    n_filtered = px.rowCount()
    bad = []
    for c in COLS:
        for o in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
            px.sort(c, o)
            if px.rowCount() != n_filtered:
                bad.append(f"{COLUMNS[c]}: {px.rowCount()}")
    check(f"a filtered view stays {n_filtered} rows across every sort",
          not bad, "; ".join(bad[:3]))

    print("\n=== 3. the export 'view' scope is exactly what is on screen ===")
    # Mirrors _on_export_clicked's scope=="view" collection.
    px.sort(12, Qt.SortOrder.AscendingOrder)          # a newly-sortable column
    visible = {ident(px.get_source_event(r)) for r in range(px.rowCount())}
    exported = [ev for i in range(px.rowCount())
                if (ev := px.get_source_event(i)) is not None]
    check("export collects one event per visible row",
          len(exported) == px.rowCount(), f"{len(exported)} vs {px.rowCount()}")
    check("export collects exactly the visible rows",
          {ident(e) for e in exported} == visible)
    check("every exported row satisfies the active filter",
          all(apply_tz(e["timestamp"])[:10].lower() == top_d for e in exported))
    px.set_quick_filters([])
    check("clearing restores the full table", px.rowCount() == TOTAL)

    print("\n=== 4. bookmarks follow the event, not the row position ===")
    # Sorting physically reorders the event list, so anything keyed by row
    # index would break the moment a column became sortable.  Bookmarks use a
    # (source_file, record_id) composite key; this proves it holds across every
    # newly-sortable column.
    def bkey(e):
        return (str(e.get("source_file", "")), int(e.get("record_id") or -1))

    marks = frozenset(bkey(evs[i]) for i in range(0, len(evs), max(1, len(evs) // 50)))
    m.set_bookmark_highlights(marks)
    bad_f, bad_h = [], []
    for c in COLS:
        for o, nm in ((Qt.SortOrder.AscendingOrder, "asc"),
                      (Qt.SortOrder.DescendingOrder, "desc")):
            px.clear_bookmark_filter()
            px.sort(c, o)
            px.set_bookmark_filter(marks)
            got = {bkey(px.get_source_event(r)) for r in range(px.rowCount())}
            if got != marks:
                bad_f.append(f"{COLUMNS[c]}/{nm}: {len(got ^ marks)} differ")
            px.clear_bookmark_filter()
            starred = set()
            for r in range(px.rowCount()):
                v = px.data(px.index(r, 0), Qt.ItemDataRole.DisplayRole)
                if v and str(v).startswith("\u2605"):
                    starred.add(bkey(px.get_source_event(r)))
            if starred and starred != marks:
                bad_h.append(f"{COLUMNS[c]}/{nm}: {len(starred)}")
    check(f"the bookmark filter returns exactly the {len(marks)} bookmarks "
          f"after each of {2*len(COLS)} sorts", not bad_f, "; ".join(bad_f[:3]))
    check("the bookmark star stays on the same events after every sort",
          not bad_h, "; ".join(bad_h[:3]))
    # The bookmark filter is Layer 0a in _filterAcceptsRow_impl and returns
    # unconditionally, exactly like the IOC pivot below it: it is a PIVOT view,
    # not a stacking filter.  Pinned so the intent is not "fixed" by mistake.
    px.set_bookmark_filter(marks)
    px.set_quick_filters([{"key": "timestamp_date", "value": top_d, "include": True}])
    check("the bookmark pivot deliberately overrides other filters",
          px.rowCount() == len(marks), f"{px.rowCount()} vs {len(marks)}")
    px.set_quick_filters([])
    px.clear_bookmark_filter()
    m.set_bookmark_highlights(frozenset())
    check("clearing the pivot restores the table", px.rowCount() == TOTAL)

    print("\n=== 5. separate-tabs mode keeps tabs independent ===")
    try:
        from evtx_tool.gui.main_window import MainWindow, FileTabState  # noqa: E402
        w = MainWindow()
        w._events = evs
        w._event_model.set_events(evs)
        w._view_mode = "separate"
        for fp, fevs in per.items():
            tm = EventTableModel(); tm.set_events(fevs)
            tp = EventFilterProxyModel(); tp.setSourceModel(tm)
            w._file_tabs[fp] = FileTabState(
                filepath=fp, display_name=os.path.basename(fp), events=fevs,
                search_cache=[], model=tm, proxy=tp, table=QTableView())
        fps = list(per)
        d = collections.Counter(
            apply_tz(e["timestamp"])[:10].lower() for e in per[fps[0]]
        ).most_common(1)[0][0]
        w._file_tabs[fps[0]].proxy.set_quick_filters(
            [{"key": "timestamp_date", "value": d, "include": True}])
        w._col_filters[3] = ("include", [d])
        expA = sum(1 for e in per[fps[0]]
                   if apply_tz(e["timestamp"])[:10].lower() == d)
        check("filtering one tab filters that tab",
              w._file_tabs[fps[0]].proxy.rowCount() == expA,
              f"{w._file_tabs[fps[0]].proxy.rowCount()} vs {expA}")
        check("filtering one tab leaves the other alone",
              w._file_tabs[fps[1]].proxy.rowCount() == len(per[fps[1]]),
              f"{w._file_tabs[fps[1]].proxy.rowCount()} vs {len(per[fps[1]])}")
        w._col_value_cache = {("normal", "timestamp_date", 1): {"x": 1}}
        w._clear_quick_filters()
        check("clearing restores every tab",
              all(w._file_tabs[f].proxy.rowCount() == len(per[f]) for f in fps))
        check("clearing empties every tab's quick filters",
              all(not s.proxy.get_quick_filters() for s in w._file_tabs.values()))
        check("clearing drops the column-filter bookkeeping", not w._col_filters)
        check("clearing drops the cached popup values", not w._col_value_cache)
        w._view_mode = "merged"
        w._file_tabs.clear()
        w.close()
    except Exception as exc:
        check("separate-tabs checks ran", False, f"{type(exc).__name__}: {exc}")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
