"""JM sort/filter: correctness + GUI-thread responsiveness.

Sorting used to run on the GUI thread in TWO places -- sort() on a header
click, and _on_filter_done after EVERY filter change. Both blocked the UI.
These checks assert the sort is correct AND that the call returns to the event
loop essentially instantly.

Run: QT_QPA_PLATFORM=offscreen python tests/test_jm_sort_perf.py [logs_dir]
"""
import os, sys, glob, time, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import Qt, QEventLoop, QTimer
app = QApplication.instance() or QApplication([])

from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
from evtx_tool.gui.heavyweight_model import ArrowTableModel, _FilterThread

LOGS = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"

res = []
def check(name, ok, detail=""):
    res.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

def settle(model, timeout_ms=120_000):
    """Pump the event loop until the filter thread delivers a result."""
    loop = QEventLoop()
    done = {"hit": False}
    def _fin():
        done["hit"] = True
        loop.quit()
    model.busy_finished.connect(_fin)
    QTimer.singleShot(timeout_ms, loop.quit)
    if not done["hit"]:
        loop.exec()
    try:
        model.busy_finished.disconnect(_fin)
    except Exception:
        pass

files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
if not files:
    print(f"no .evtx under {LOGS} — skipping")
    sys.exit(0)
print(f"building parquet from {len(files)} files ...")

tmp = tempfile.mkdtemp(prefix="jm_sort_")
try:
    pq_dir = HeavyweightEngine(parquet_dir=tmp).run(files)
    table  = load_arrow_table(pq_dir)
    print(f"arrow table: {len(table):,} rows")

    model = ArrowTableModel(table, parquet_dir=pq_dir)
    settle(model)
    total = model.rowCount()
    check("model populated", total > 0, f"{total:,} rows")
    check("initial view is the whole table", total == len(table),
          f"{total} vs {len(table)}")

    # ── sort() must not block the GUI thread ──────────────────────────────
    from evtx_tool.gui.models import COL_EID, COL_TS, COL_COMPUTER, COL_CHANNEL
    timings = {}
    for col, label in ((COL_EID, "event_id"), (COL_COMPUTER, "computer"),
                       (COL_TS, "timestamp_utc")):
        for order in (Qt.SortOrder.DescendingOrder, Qt.SortOrder.AscendingOrder):
            t0 = time.perf_counter()
            model.sort(col, order)
            blocked = (time.perf_counter() - t0) * 1000    # GUI thread time
            settle(model)
            timings[f"{label}/{'asc' if order == Qt.SortOrder.AscendingOrder else 'desc'}"] = blocked
    worst = max(timings.values())
    for k, v in timings.items():
        print(f"      sort {k:<24} GUI-thread block: {v:7.2f} ms")
    check("sort() returns to the event loop in <50ms (was a full-table sort)",
          worst < 50.0, f"worst {worst:.2f} ms")
    check("row count preserved across sorts", model.rowCount() == total,
          f"{model.rowCount()} vs {total}")

    # ── correctness: ordering actually applied ────────────────────────────
    def col_vals(name, n=4000):
        t = model._display_table
        n = min(n, len(t))
        return t[name].slice(0, n).to_pylist()

    model.sort(COL_EID, Qt.SortOrder.AscendingOrder);  settle(model)
    asc = [v for v in col_vals("event_id") if v is not None]
    check("ascending sort is ordered", asc == sorted(asc),
          f"first 5 {asc[:5]}")
    model.sort(COL_EID, Qt.SortOrder.DescendingOrder); settle(model)
    desc = [v for v in col_vals("event_id") if v is not None]
    check("descending sort is ordered", desc == sorted(desc, reverse=True),
          f"first 5 {desc[:5]}")

    # ── dictionary-encoded string columns must actually sort ─────────────
    # Arrow's sort_by RAISES on dictionary columns (every string column here is
    # dictionary-encoded).  The old code logged the failure and returned the
    # table UNSORTED, so sorting the grid by Computer silently showed unordered
    # rows.  Ordering now goes through DuckDB.
    for col, name in ((COL_CHANNEL, "channel"), (COL_COMPUTER, "computer")):
        model.sort(col, Qt.SortOrder.AscendingOrder); settle(model)
        vals = [v for v in col_vals(name, 50000) if v is not None]
        check(f"{name} (dictionary-encoded) sorts ascending",
              vals == sorted(vals), f"{len(set(vals))} distinct, first {vals[:2]}")
        model.sort(col, Qt.SortOrder.DescendingOrder); settle(model)
        vals = [v for v in col_vals(name, 50000) if v is not None]
        check(f"{name} (dictionary-encoded) sorts descending",
              vals == sorted(vals, reverse=True), f"{len(set(vals))} distinct, first {vals[:2]}")

    # ── forensic tiebreaker: equal timestamps ordered by record_id ────────
    model.sort(COL_TS, Qt.SortOrder.AscendingOrder); settle(model)
    t = model._display_table
    ts = t["timestamp_utc"].slice(0, 20000).to_pylist()
    rid = t["record_id"].slice(0, 20000).to_pylist()
    viol = [i for i in range(1, len(ts))
            if ts[i] == ts[i-1] and rid[i] is not None and rid[i-1] is not None
            and rid[i] < rid[i-1]]
    ties = sum(1 for i in range(1, len(ts)) if ts[i] == ts[i-1])
    check("record_id tiebreaker holds on equal timestamps",
          not viol, f"{len(viol)} violations across {ties} ties")

    # ── filter still correct, and also off the GUI thread ─────────────────
    eid = max(set(asc), key=asc.count)
    t0 = time.perf_counter()
    model.apply_filter({"event_ids": [eid]})
    blocked = (time.perf_counter() - t0) * 1000
    settle(model)
    got = model.rowCount()
    expected = sum(1 for v in table["event_id"].to_pylist() if v == eid)
    check("filter result is exact", got == expected, f"{got} vs {expected} for EID {eid}")
    check("apply_filter() does not block the GUI thread", blocked < 50.0,
          f"{blocked:.2f} ms")

    # sorting a filtered view keeps the filter
    model.sort(COL_TS, Qt.SortOrder.DescendingOrder); settle(model)
    check("sort preserves the active filter", model.rowCount() == expected,
          f"{model.rowCount()} vs {expected}")

    # ── re-sorting must not re-run the filter ─────────────────────────────
    thr = model._filter_thread
    before = thr._last_fkey
    model.sort(COL_EID, Qt.SortOrder.AscendingOrder); settle(model)
    check("sort-only change reuses the cached filter (no re-filter)",
          thr._last_fkey == before,
          "unchanged" if thr._last_fkey == before else "filter key CHANGED — refiltered")

    model.clear_filter(); settle(model)
    check("clear_filter restores the full table", model.rowCount() == total,
          f"{model.rowCount()} vs {total}")

    # ── per-file tab path: a model with a fixed pre-filter ───────────────
    # Per-file tabs construct ArrowTableModel with fixed_where="source_file = ?"
    # and share the same full_table. The unified metadata path changed how that
    # filter combines with ORDER BY, so exercise it directly.
    src_files = sorted({v for v in table["source_file"].to_pylist() if v})
    if src_files:
        pick = src_files[len(src_files) // 2]
        fm = ArrowTableModel(table, parquet_dir=pq_dir,
                             fixed_where="source_file = ?", fixed_params=[pick])
        settle(fm)
        want = sum(1 for v in table["source_file"].to_pylist() if v == pick)
        check("per-file tab shows exactly that file's rows",
              fm.rowCount() == want, f"{fm.rowCount()} vs {want}")
        fm.sort(COL_TS, Qt.SortOrder.DescendingOrder); settle(fm)
        check("per-file tab keeps its fixed filter after sorting",
              fm.rowCount() == want, f"{fm.rowCount()} vs {want}")
        ts_desc = fm._display_table["timestamp_utc"].slice(0, 5000).to_pylist()
        check("per-file tab sorts correctly",
              ts_desc == sorted(ts_desc, reverse=True), f"first {ts_desc[:1]}")
        only = {v for v in fm._display_table["source_file"].to_pylist()}
        check("per-file tab never leaks another file's rows",
              only == {pick}, f"{len(only)} distinct source_files")
        fm._filter_thread.stop()

    model._filter_thread.stop()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\n" + "=" * 60)
bad = [n for n, ok in res if not ok]
print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
for n in bad:
    print("  FAILED:", n)
sys.stdout.flush()
sys.exit(1 if bad else 0)
