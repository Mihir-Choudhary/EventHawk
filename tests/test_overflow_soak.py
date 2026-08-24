"""Stability soak: repeated materialize + teardown cycles on the BITS logs.

The reported crash was an OverflowError storm that ended in
"Segmentation fault". The storm is reproduced and fixed (see
test_overflow_realdata.py). This suite exists for the other half of the
question -- "make sure no such errors occur" -- by hammering the same code
path repeatedly, including cancelling a worker mid-flight and tearing the
session down, which is what an analyst does when they hit X or re-parse.

Run it as a SUBPROCESS and check the returncode: an in-process segfault kills
the runner silently, so the exit status is the signal that matters
(-11 = SIGSEGV, -6 = SIGABRT).

Run: QT_QPA_PLATFORM=offscreen python tests/test_overflow_soak.py [CYCLES] [LOGS_DIR]
"""
import os, sys, glob, json, tempfile, shutil, warnings, threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SENTINEL = 18446744073709551615


def main() -> int:
    warns, errs = [], []
    warnings.simplefilter("always")
    warnings.showwarning = lambda m, c, f, l, file=None, line=None: warns.append(f"{c.__name__}: {m}")
    _oh = sys.excepthook
    def _hook(et, ev, tb):
        errs.append(f"{et.__name__}: {ev}"); _oh(et, ev, tb)
    sys.excepthook = _hook
    threading.excepthook = lambda a: errs.append(f"[thread] {a.exc_type.__name__}: {a.exc_value}")

    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt, QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.gui.main_window import _JMAnalysisMaterializeWorker, MainWindow

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    CYCLES = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    LOGS   = sys.argv[2] if len(sys.argv) > 2 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    files  = sorted(glob.glob(os.path.join(LOGS, "*Bits-Client*.evtx")))
    if not files:
        print(f"no BITS logs under {LOGS} — skipping"); return 0

    tmp = tempfile.mkdtemp(prefix="ovf_soak_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        print(f"{len(files)} file(s) -> parquet; {CYCLES} cycles\n")

        # ── A. run the worker to completion, repeatedly ──────────────────
        counts = []
        for i in range(CYCLES):
            w = _JMAnalysisMaterializeWorker(pq, limit=0)
            got = []
            w.finished_ok.connect(lambda e: got.append(e), Qt.QueuedConnection)
            loop = QEventLoop(); w.finished.connect(loop.quit)
            QTimer.singleShot(600_000, loop.quit)
            w.start(); loop.exec()
            for _ in range(20):
                app.processEvents()
            w.wait(30_000)
            n = sum(1 for e in (got[0] if got else [])
                    for v in (e.get("event_data") or {}).values() if v == SENTINEL)
            counts.append(n)
        check(f"{CYCLES} full materialize cycles all delivered", len(counts) == CYCLES)
        check("every cycle carried the identical sentinel count (no drift)",
              len(set(counts)) == 1 and counts[0] > 0, f"counts={counts}")

        # ── B. cancel mid-flight and tear down, repeatedly ───────────────
        win = MainWindow()
        try:
            for i in range(CYCLES):
                w = _JMAnalysisMaterializeWorker(pq, limit=0, parent=win)
                win._jm_mat_worker = w
                w.start()
                for _ in range(6):                    # let it get into the fetch loop
                    app.processEvents()
                win._cleanup_juggernaut()             # cancel + disconnect + rmtree path
                for _ in range(10):
                    app.processEvents()
            check(f"{CYCLES} cancel-mid-flight + teardown cycles survived", True)
            check("teardown always cleared the worker reference",
                  getattr(win, "_jm_mat_worker", None) is None)
        finally:
            win.close()
            for _ in range(20):
                app.processEvents()

        # ── C. nothing accumulated ───────────────────────────────────────
        ov_w = [w for w in warns if "shiboken" in w.lower() or "overflow" in w.lower()]
        ov_e = [e for e in errs if "Overflow" in e or "SystemError" in e]
        check("no shiboken/overflow warning across the whole soak",
              not ov_w, f"{len(ov_w)}: {ov_w[:2]}")
        check("no OverflowError / SystemError across the whole soak",
              not ov_e, f"{len(ov_e)}: {ov_e[:2]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
