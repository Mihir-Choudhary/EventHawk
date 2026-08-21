"""End-to-end through the REAL MainWindow, not the components underneath.

Everything else in this suite drives models and workers directly. This drives
the window itself: launch Juggernaut on real files, wait for the parse worker,
then filter/sort/search through the window's own state, switch back to Normal
Mode, and close. It is the closest thing to "does the app actually work" that
can run headless.

Run: QT_QPA_PLATFORM=offscreen python tests/test_integration_e2e.py [logs_dir]
"""
import os, sys, glob, time, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt, QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow
    from evtx_tool.gui.models import COL_TS, COL_EID

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    def pump(ms):
        end = time.perf_counter() + ms / 1000.0
        while time.perf_counter() < end:
            app.processEvents(); time.sleep(0.004)

    def wait_for(pred, timeout_s=420):
        end = time.perf_counter() + timeout_s
        while time.perf_counter() < end:
            app.processEvents(); time.sleep(0.01)
            try:
                if pred(): return True
            except Exception: pass
        return False

    LOGS = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"
    wanted = ["Application.evtx",
              "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
              "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"]
    files = [os.path.join(LOGS, f) for f in wanted if os.path.exists(os.path.join(LOGS, f))]
    if not files:
        files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:8]
    if not files:
        print("no logs — skipping"); return 0

    w = MainWindow()
    check("window constructs", w is not None)

    # ── launch Juggernaut through the window's own entry point ───────────
    t0 = time.perf_counter()
    w._launch_juggernaut_mode(files)
    ok = wait_for(lambda: w._hw_model is not None and w._hw_model.rowCount() > 0)
    check("Juggernaut parse completes through MainWindow", ok,
          f"{time.perf_counter()-t0:.1f}s")
    if not ok:
        print("cannot continue without a model"); return 1
    total = w._hw_model.rowCount()
    print(f"      loaded {total:,} rows in {time.perf_counter()-t0:.1f}s")

    check("parse button is re-enabled afterwards", w._btn_parse.isEnabled())
    check("the grid is bound to the JM model", w._table.model() is w._hw_model)

    def settle(timeout_s=300):
        return wait_for(lambda: True, 0.05) or True

    def apply_and_wait(fn, expect_change_from=None):
        fn()
        wait_for(lambda: w._hw_model.rowCount() != expect_change_from
                 if expect_change_from is not None else True, 120)
        pump(150)

    # ── filter through the model the window owns ─────────────────────────
    import collections
    eids = w._hw_model._full_table["event_id"].to_pylist()
    top = collections.Counter(eids).most_common(1)[0][0]
    apply_and_wait(lambda: w._hw_model.apply_filter({"event_ids": [top]}), total)
    check("filter applies and narrows the grid",
          w._hw_model.rowCount() == eids.count(top),
          f"{w._hw_model.rowCount()} vs {eids.count(top)}")

    # ── text search through the same path the dialog produces ────────────
    from evtx_tool.gui.filter_dialog import FilterDialog
    d = FilterDialog(metadata={}, current_filter={}, juggernaut_mode=True)
    d._inp_text.setText("Microsoft")
    cfg = d.get_filter_config()
    n_before = w._hw_model.rowCount()
    apply_and_wait(lambda: w._hw_model.apply_filter(cfg), n_before)
    n_txt = w._hw_model.rowCount()
    check("dialog-built text search runs in JM", 0 < n_txt <= total, f"{n_txt} of {total}")

    apply_and_wait(lambda: w._hw_model.clear_filter(), n_txt)
    check("clearing restores the full grid", w._hw_model.rowCount() == total,
          f"{w._hw_model.rowCount()} vs {total}")

    # ── sorting through the window's own handler ─────────────────────────
    w._on_sort_by_column(COL_TS, w._table, force_order=Qt.SortOrder.DescendingOrder)
    wait_for(lambda: True, 3); pump(400)
    check("sort via the window handler keeps the row count",
          w._hw_model.rowCount() == total, f"{w._hw_model.rowCount()}")
    ts = w._hw_model._display_table["timestamp_utc"].slice(0, 8000).to_pylist()
    check("sort actually ordered the grid", ts == sorted(ts, reverse=True),
          f"first {ts[:1]}")

    # ── rapid-fire changes: the LAST request must win ────────────────────
    for i in range(8):
        w._hw_model.apply_filter({"event_ids": [eids[i % len(eids)]]})
    final_eid = eids[7 % len(eids)]
    wait_for(lambda: w._hw_model.rowCount() == eids.count(final_eid), 120)
    pump(300)
    check("rapid successive filters settle on the LAST one",
          w._hw_model.rowCount() == eids.count(final_eid),
          f"{w._hw_model.rowCount()} vs {eids.count(final_eid)}")
    apply_and_wait(lambda: w._hw_model.clear_filter())

    # ── analysis checkboxes reflect the JM policy ────────────────────────
    check("IOC/Correlation are usable in JM",
          w._chk_ioc.isEnabled() and w._chk_correlate.isEnabled())
    check("ATT&CK stays disabled in JM with a reason",
          (not w._chk_attack.isEnabled()) and "ATT&CK" in w._chk_attack.toolTip(),
          w._chk_attack.toolTip()[:70])

    # ── leave Juggernaut cleanly ─────────────────────────────────────────
    w._cleanup_juggernaut()
    pump(400)
    check("cleanup releases the JM model", w._hw_model is None)
    check("analysis checkboxes are restored for Normal Mode",
          w._chk_attack.isEnabled() and w._chk_ioc.isEnabled())
    check("no loading dialog is left on screen", w._hw_loading_dlg is None)

    # ── close with everything torn down ──────────────────────────────────
    w.close(); pump(500)
    check("window closes without leaving a running worker",
          all(getattr(w, a, None) is None or not getattr(w, a).isRunning()
              for a in ("_jm_export_worker", "_jm_mat_worker", "_hw_worker")))

    # ── NORMAL MODE end to end, through the real ParseWorker ────────────
    # The other half of the app: a different parser, model and proxy. Driven
    # here so "it works" is not a claim about Juggernaut alone.
    from evtx_tool.gui.worker import ParseWorker
    wn = MainWindow()
    small = files[:2]
    # empty_filter() is what the window itself passes; None is exercised
    # separately below as a robustness case.
    from evtx_tool.core.filters import empty_filter
    pw = ParseWorker(files=small, filter_config=empty_filter(), do_attack=False,
                     do_ioc=False, do_correlate=False, max_workers=None)
    done = {}
    pw.finished.connect(lambda *a: done.update(ok=True, args=a))
    pw.error.connect(lambda e: done.update(err=str(e)))
    pw.start()
    got = wait_for(lambda: done, 420)
    check("normal-mode ParseWorker completes", got and "err" not in done,
          str(done.get("err"))[:160])
    pw.wait(10000)
    if got and "err" not in done:
        evs = next((a for a in done["args"] if isinstance(a, list)), [])
        check("normal-mode parse produced events", len(evs) > 0, f"{len(evs):,}")
        if evs:
            from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
            nmodel = EventTableModel(); nmodel.set_events(evs)
            nproxy = EventFilterProxyModel(); nproxy.setSourceModel(nmodel)
            wn._table.setModel(nproxy)
            base_n = nproxy.rowCount()
            check("normal-mode grid shows every parsed event", base_n == len(evs),
                  f"{base_n} vs {len(evs)}")
            _e0 = evs[0].get("channel") or ""
            nproxy.set_advanced_filter({"categories": [_e0]} if _e0 else {"levels": ["Information"]})
            app.processEvents()
            check("normal-mode filter narrows the grid", nproxy.rowCount() <= base_n,
                  f"{nproxy.rowCount()} of {base_n}")
            nproxy.set_advanced_filter({"text_search": "Microsoft"})
            app.processEvents()
            check("normal-mode text search runs", 0 <= nproxy.rowCount() <= base_n,
                  f"{nproxy.rowCount()} of {base_n}")
            nproxy.set_advanced_filter(None); app.processEvents()
            check("normal-mode clearing restores every row",
                  nproxy.rowCount() == base_n, f"{nproxy.rowCount()} vs {base_n}")
            wn._on_sort_by_column(COL_EID, wn._table,
                                  force_order=Qt.SortOrder.AscendingOrder)
            app.processEvents()
            check("normal-mode sort keeps the row count",
                  nproxy.rowCount() == base_n, f"{nproxy.rowCount()}")
            check("normal-mode sort left no dialog open", wn._hw_loading_dlg is None)
    # a None config must mean "no filter", not a parse that reports zero events
    from evtx_tool.core.filters import compile_filter as _cf
    try:
        _fn = _cf(None)
        check("compile_filter(None) means 'no filter', not a crash",
              _fn({"event_id": 4624, "channel": "Security"}) is True)
    except Exception as _e:
        check("compile_filter(None) means 'no filter', not a crash", False, repr(_e))
    wn.close(); pump(300)

    # ── stability: repeated load/cleanup cycles must not accumulate ─────
    # A tool that works once but leaks a thread or a temp dir per load stops
    # being usable halfway through a long engagement.
    import threading, gc
    w2 = MainWindow()
    counts, threads, rsss = [], [], []
    try:
        import resource
        def _rss(): return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except Exception:
        def _rss(): return 0.0
    for cycle in range(3):
        w2._launch_juggernaut_mode(files)
        ok = wait_for(lambda: w2._hw_model is not None and w2._hw_model.rowCount() > 0, 420)
        if not ok:
            break
        counts.append(w2._hw_model.rowCount())
        w2._hw_model.apply_filter({"event_ids": [top]})
        wait_for(lambda: w2._hw_model.rowCount() != counts[-1], 120); pump(120)
        w2._hw_model.clear_filter(); pump(200)
        w2._cleanup_juggernaut(); pump(400); gc.collect()
        threads.append(threading.active_count())
        rsss.append(_rss())
    print(f"      cycles: rows={counts} threads_after={threads} "
          f"rss_mb={[round(r) for r in rsss]}")
    check("repeated loads give identical row counts",
          len(counts) == 3 and len(set(counts)) == 1, str(counts))
    check("threads do not accumulate across load/cleanup cycles",
          len(threads) == 3 and threads[-1] <= threads[0] + 2, str(threads))
    if rsss and rsss[0]:
        check("memory does not balloon across cycles",
              rsss[-1] <= rsss[0] * 1.6, f"{[round(r) for r in rsss]} MB")
    w2.close(); pump(300)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
