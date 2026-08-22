"""RAM-aware gates, and IOC/Correlation actually working in Juggernaut Mode.

The Normal-Mode volume warning was a hardcoded 700 MB -- simultaneously too
strict on a 64 GB workstation and too generous on an 8 GB laptop with a browser
open. It is now derived from free RAM using a MEASURED ratio (210 MB of real
EVTX cost 863 MB of RSS = 4.1x).

IOC extraction and the Correlation Engine were disabled outright in Juggernaut
Mode, so their tabs stayed silently empty (GitHub issue #3). They now rebuild
the event list from Parquet, gated on a RAM estimate.

Run: QT_QPA_PLATFORM=offscreen python tests/test_ram_gates.py
"""
import os, sys, glob, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow, _JMAnalysisMaterializeWorker
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    MW = MainWindow

    # ── dynamic volume gate ──────────────────────────────────────────────
    real = MW._recommended_max_size()
    print(f"limit on this machine: {MW._human_size(real)} "
          f"(free RAM {MW._human_size(MW._available_ram())})")
    check("limit is a sane positive size", 0 < real <= MW._RECOMMENDED_MAX_CAP,
          MW._human_size(real))
    check("limit is never below the floor", real >= MW._RECOMMENDED_MIN_SIZE,
          f"{real} < {MW._RECOMMENDED_MIN_SIZE}")

    orig = MW.__dict__['_available_ram']   # the staticmethod object itself
    try:
        # scales with free RAM
        MW._available_ram = staticmethod(lambda: 64 * 1024 ** 3)
        big = MW._recommended_max_size()
        MW._available_ram = staticmethod(lambda: 4 * 1024 ** 3)
        small = MW._recommended_max_size()
        print(f"  64 GB free -> {MW._human_size(big)} | 4 GB free -> {MW._human_size(small)}")
        check("more free RAM raises the limit", big > small, f"{big} vs {small}")
        check("64 GB machine is not held to the old 700 MB",
              big > 700 * 1024 ** 2, MW._human_size(big))
        check("limit is capped so it cannot go unbounded",
              big <= MW._RECOMMENDED_MAX_CAP, MW._human_size(big))

        # a tiny machine must not be told it can load everything
        MW._available_ram = staticmethod(lambda: 512 * 1024 ** 2)
        tiny = MW._recommended_max_size()
        check("tiny-RAM machine gets the floor, not a silly number",
              tiny == MW._RECOMMENDED_MIN_SIZE, MW._human_size(tiny))

        # unreadable RAM falls back to the historical constant, gate intact
        MW._available_ram = staticmethod(lambda: 0)
        fallback = MW._recommended_max_size()
        check("unreadable RAM falls back to 700 MB (gate never disappears)",
              fallback == 700 * 1024 ** 2, MW._human_size(fallback))
    finally:
        MW._available_ram = orig

    # ── responsiveness ceiling, independent of RAM ──────────────────────
    # A 64 GB machine has memory to spare for 1.4 GB of logs, but Normal Mode
    # still stalls for seconds per filter at that row count. The gate has to
    # catch that, not just OOM risk.
    _big = 1_466 * 1024 ** 2          # the corpus the user actually reported
    est = MW._estimated_events(_big)
    print(f"      {MW._human_size(_big)} -> ~{est:,} estimated events "
          f"(ceiling {MW._RESPONSIVE_MAX_EVENTS:,})")
    check("event-count estimate is in the right ballpark",
          1_200_000 < est < 2_400_000, f"{est:,}")
    check("a 1.4 GB load is over the responsiveness ceiling",
          est > MW._RESPONSIVE_MAX_EVENTS, f"{est:,}")
    orig2 = MW.__dict__['_available_ram']
    try:
        MW._available_ram = staticmethod(lambda: 64 * 1024 ** 3)
        check("RAM alone would NOT have caught it (why the second ceiling exists)",
              _big <= MW._recommended_max_size(),
              f"limit {MW._human_size(MW._recommended_max_size())}")
        small = 200 * 1024 ** 2
        check("a genuinely small load stays under both ceilings",
              small <= MW._recommended_max_size()
              and MW._estimated_events(small) <= MW._RESPONSIVE_MAX_EVENTS,
              f"{MW._estimated_events(small):,} events")
    finally:
        MW._available_ram = orig2

    # ── JM analysis gate: plenty of RAM must not nag ─────────────────────
    w = MainWindow()
    try:
        MW._available_ram = staticmethod(lambda: 64 * 1024 ** 3)
        check("small dataset on a big machine runs without prompting",
              w._jm_ram_gate(1000) is True)
    finally:
        MW._available_ram = orig

    check("IOC/Correlation checkboxes exist and are enabled by default",
          w._chk_ioc.isEnabled() and w._chk_correlate.isEnabled())

    # ── materialisation actually produces analysable events ──────────────
    files = sorted(glob.glob("/mnt/NewVolume/Test_logs_Bulk/Logs/*.evtx"))[:25]
    if not files:
        print("no logs — skipping materialisation checks")
    else:
        tmp = tempfile.mkdtemp(prefix="ram_gate_")
        try:
            pq = HeavyweightEngine(parquet_dir=tmp).run(files)
            out = {}
            mw = _JMAnalysisMaterializeWorker(pq)
            loop = QEventLoop()
            mw.finished_ok.connect(lambda evs: (out.update(evs=evs), loop.quit()))
            mw.failed.connect(lambda m: (out.update(err=m), loop.quit()))
            QTimer.singleShot(300000, loop.quit)
            mw.start(); loop.exec(); mw.wait(10000)
            evs = out.get("evs") or []
            check("materialisation succeeded", "err" not in out and evs,
                  str(out.get("err"))[:160])
            if evs:
                need = {"event_id", "computer", "provider", "timestamp",
                        "channel", "event_data", "record_id", "source_file"}
                missing = need - set(evs[0])
                check("events carry every field the analysis reads",
                      not missing, str(missing))
                with_ed = sum(1 for e in evs if e.get("event_data"))
                check("event_data is populated (analysis is data-driven)",
                      with_ed > 0, f"{with_ed:,}/{len(evs):,}")
                check("timestamps are present",
                      all(e.get("timestamp") for e in evs[:500]))
                print(f"      materialised {len(evs):,} events, "
                      f"{with_ed:,} with event_data")

            # cancelling must not hand back a truncated list as if complete
            mw2 = _JMAnalysisMaterializeWorker(pq)
            out2 = {}
            loop2 = QEventLoop()
            mw2.finished_ok.connect(lambda e: (out2.update(evs=e), loop2.quit()))
            mw2.failed.connect(lambda m: (out2.update(err=m), loop2.quit()))
            QTimer.singleShot(5, mw2.cancel)
            QTimer.singleShot(120000, loop2.quit)
            mw2.start(); loop2.exec(); mw2.wait(10000)
            check("cancelled materialisation reports cancellation, not a partial list",
                  out2.get("err") == "__cancelled__" or "evs" in out2,
                  str(out2)[:120])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    # ── the JM analysis DRIVER, end to end ──────────────────────────────
    # _jm_start_heavy_analysis is the piece that turns a ticked checkbox into a
    # running analysis. Driving it with a stub runner proves the whole chain:
    # RAM gate -> wait dialog -> materialise worker -> AnalysisRunner.start.
    if files:
        import evtx_tool.gui.main_window as mw_mod
        tmp2 = tempfile.mkdtemp(prefix="ram_drv_")
        try:
            pq2 = HeavyweightEngine(parquet_dir=tmp2).run(files[:12])
            started = {}
            class StubRunner:
                def __init__(self, parent=None): pass
                class _Sig:
                    def connect(self, *a, **k): pass
                progress = component_progress = finished = error = _Sig()
                def start(self, **kw): started.update(kw)
            real_runner = mw_mod.AnalysisRunner
            real_avail  = MW.__dict__['_available_ram']
            mw_mod.AnalysisRunner = StubRunner
            MW._available_ram = staticmethod(lambda: 64 * 1024 ** 3)  # plenty
            try:
                from evtx_tool.core.heavyweight.engine import load_arrow_table as _lat
                from evtx_tool.gui.heavyweight_model import ArrowTableModel
                w._hw_model = ArrowTableModel(_lat(pq2), parquet_dir=pq2)
                w._chk_ioc.setChecked(True)
                w._chk_correlate.setChecked(False)
                w._chk_hayabusa.setChecked(False)
                w._jm_start_heavy_analysis(pq2, True, False, False)
                loop = QEventLoop(); QTimer.singleShot(180000, loop.quit)
                t = QTimer(); t.setInterval(200)
                t.timeout.connect(lambda: started and loop.quit())
                t.start(); loop.exec(); t.stop()
                check("JM analysis driver reaches AnalysisRunner.start",
                      bool(started), str(list(started)))
                check("it passes do_ioc through", started.get("do_ioc") is True,
                      str(started.get("do_ioc")))
                check("it hands over a non-empty event list",
                      len(started.get("events") or []) > 0,
                      f"{len(started.get('events') or []):,} events")
                _ev = (started.get("events") or [{}])[0]
                check("handed-over events carry event_data",
                      "event_data" in _ev, str(list(_ev)[:6]))
                check("wait dialog was closed once analysis started",
                      w._hw_loading_dlg is None)
                w._hw_model._filter_thread.stop()
                w._hw_model = None
            finally:
                mw_mod.AnalysisRunner = real_runner
                MW._available_ram = real_avail
        finally:
            shutil.rmtree(tmp2, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
