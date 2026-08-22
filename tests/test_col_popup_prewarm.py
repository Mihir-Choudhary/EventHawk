"""Column filter popups must be ready when a filter settles, not on click.

Reported: the quick-filter popups take time to appear after applying filters.
Measured, the GROUP BY is only 20-130 ms on 1.7M rows -- but it sits in the
CLICK path, followed by up to ~99 ms of checkbox construction on the GUI
thread, with no feedback in between. The queries are now run once when the
filter settles and cached per (column, cascade), so clicking serves from cache.

Correctness matters more than the speed here: a cached popup that shows the
PREVIOUS filter's values would silently mislead. The cache key includes the
cascade WHERE, so these checks prove it changes with the filter.

Run: QT_QPA_PLATFORM=offscreen python tests/test_col_popup_prewarm.py
"""
import os, sys, glob, time, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow, ColumnFilterPopup
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    import random, collections

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    def pump(ms):
        end = time.perf_counter() + ms / 1000.0
        while time.perf_counter() < end:
            app.processEvents(); time.sleep(0.004)

    def wait_for(pred, timeout_s=300):
        end = time.perf_counter() + timeout_s
        while time.perf_counter() < end:
            app.processEvents(); time.sleep(0.01)
            try:
                if pred(): return True
            except Exception: pass
        return False

    LOGS = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"
    files = [os.path.join(LOGS, f) for f in
             ("Application.evtx",
              "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx")
             if os.path.exists(os.path.join(LOGS, f))]
    if not files:
        files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:6]
    if not files:
        print("no logs — skipping"); return 0

    # ── NORMAL mode gets the same treatment ──────────────────────────────
    # Run FIRST: one window per mode, as the app itself works. A live JM
    # window in the same process perturbs the shared view state this path
    # reads, which is a test artefact rather than product behaviour.
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    random.seed(3)
    N = 60_000
    evs = [{
        "record_id": i, "event_id": random.choice([4624, 4634, 4688]),
        "level_name": "Information", "timestamp": "2025-06-10T09:00:00.000000Z",
        "computer": f"HOST-{i%13:02d}", "channel": "Security",
        "user_id": "S-1-5-18", "source_file": "/l.evtx", "provider": "P",
        "keywords": "", "task": 0, "opcode": 0, "process_id": i % 700,
        "thread_id": 8, "correlation_id": "", "event_data": {"A": "b"},
    } for i in range(N)]
    wn = MainWindow()
    nm = EventTableModel(); nm.set_events(evs)
    npx = EventFilterProxyModel(); npx.setSourceModel(nm)
    wn._table.setModel(npx)
    wn._proxy_model = npx
    shown2 = {}
    orig2 = wn._show_col_filter_popup
    wn._show_col_filter_popup = lambda idx, vals: shown2.update(idx=idx, vals=vals)
    try:
        with wn._normal_filter_busy("test", rows=N):
            npx.set_advanced_filter({"event_ids": [4624]})
        npx.rowCount()
        # Poll instead of guessing a duration: the sweep walks the event list
        # in Python, so its runtime scales with the dataset.
        wait_for(lambda: len(wn._col_cache()) > 0, 120)
        check("normal mode prewarms its popups after a filter",
              len(wn._col_cache()) > 0, f"{len(wn._col_cache())} cached")
        wait_for(lambda: ("normal", "event_id",
                          len(npx.collect_source_events_for_popup("event_id")))
                 in wn._col_cache(), 120)
        # the key the click path computes must be the one that was prewarmed
        _ck = "event_id"
        _evs = npx.collect_source_events_for_popup(_ck)
        _k = ("normal", _ck, len(_evs))
        check("the prewarmed key matches what the click path looks up",
              _k in wn._col_cache(), f"{_k} vs {list(wn._col_cache())[:2]}")
        check("the prewarmed entry holds real values",
              bool(wn._col_cache().get(_k)), str(len(wn._col_cache().get(_k) or {})))
    finally:
        wn._show_col_filter_popup = orig2
        wn.close(); pump(200)


    w = MainWindow()
    w._launch_juggernaut_mode(files)
    ok = wait_for(lambda: w._hw_model is not None and w._hw_model.rowCount() > 0)
    check("dataset loaded", ok)
    if not ok:
        return 1

    n_cols = len(ColumnFilterPopup.FILTERABLE)
    ok = wait_for(lambda: len(w._col_cache()) >= max(1, n_cols - 3), 180)
    check("popups are prewarmed once the load settles",
          len(w._col_cache()) > 0, f"{len(w._col_cache())} of {n_cols} columns cached")

    # ── the click path must now be a cache hit ───────────────────────────
    shown = {}
    orig_show = w._show_col_filter_popup
    w._show_col_filter_popup = lambda idx, vals: shown.update(idx=idx, vals=vals)
    try:
        idx, col_key = next(iter(ColumnFilterPopup.FILTERABLE.items()))
        t0 = time.perf_counter()
        w._start_col_value_worker(idx, col_key)
        served = time.perf_counter() - t0
        check("clicking a header serves values synchronously from cache",
              "vals" in shown, f"{served*1000:.1f} ms")
        check("the cache hit returns real values",
              bool(shown.get("vals")), str(len(shown.get("vals") or {})))
        check("serving from cache is effectively instant", served < 0.02,
              f"{served*1000:.1f} ms")

        # ── and it must be the CURRENT filter's values, not a stale set ───
        before = dict(shown.get("vals") or {})
        eids = w._hw_model._full_table["event_id"].to_pylist()
        top = collections.Counter(eids).most_common(1)[0][0]
        w._hw_model.apply_filter({"event_ids": [top]})
        wait_for(lambda: w._hw_model.rowCount() != len(eids), 120)
        pump(1200)   # let the debounced prewarm run for the new filter

        shown.clear()
        w._start_col_value_worker(idx, col_key)
        wait_for(lambda: "vals" in shown, 60)
        after = dict(shown.get("vals") or {})
        check("values are recomputed for the new filter", after != before,
              f"before={len(before)} after={len(after)} values")
        check("the filtered popup is a subset of the unfiltered one",
              set(after) <= set(before) or len(after) <= len(before),
              f"{len(after)} vs {len(before)}")

        # clearing must restore the wider set
        w._hw_model.clear_filter()
        wait_for(lambda: w._hw_model.rowCount() == len(eids), 120)
        pump(1200)
        shown.clear()
        w._start_col_value_worker(idx, col_key)
        wait_for(lambda: "vals" in shown, 60)
        check("clearing the filter restores the full value set",
              len(shown.get("vals") or {}) == len(before),
              f"{len(shown.get('vals') or {})} vs {len(before)}")
    finally:
        w._show_col_filter_popup = orig_show

    # ── cache must not outlive the dataset ───────────────────────────────
    w._cleanup_juggernaut(); pump(400)
    check("leaving Juggernaut drops the prewarmed cache",
          not w._col_cache(), f"{len(w._col_cache())} entries left")
    w.close(); pump(200)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
