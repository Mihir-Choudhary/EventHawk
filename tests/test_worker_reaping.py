"""Background workers must be FREED, not just forgotten.

Every one of these workers is constructed with ``parent=self``, so C++ owns it:
dropping the Python reference does not delete it. The tracking lists pruned
themselves but nothing ever destroyed the objects, so each column popup, WiFi
fetch, Remote-Assistance fetch and computer-normalisation run left a QThread
parented to the MainWindow for the rest of the session -- each still pinning
the data it fetched (the visible-events list, or the Arrow table), which also
kept the previous dataset from being freed. Measured before the fix: 12 column
workers and 10+10 dialog workers still parented.

TWO traps this test exists to hold down, both of which caught me:

1. ``finished.connect(worker.deleteLater)`` DOES NOT WORK here. Every one of
   these classes declares its own ``finished`` signal carrying results
   (``Signal(object, bool)``, ``Signal(dict)``), which SHADOWS
   ``QThread.finished``. Python resolves to the custom signal, and that is
   only emitted on the SUCCESS path -- an error emits ``fetch_error``/
   ``failed`` and returns. So the deleteLater never fires precisely when
   something has already gone wrong. Reaping by liveness is signal-independent.

2. ``QApplication.processEvents()`` DOES NOT deliver DeferredDelete events.
   A test that pumps processEvents and counts children will report the leak as
   unfixed even when it is fixed. A real QEventLoop must be entered -- which is
   what the running application does.

Run: QT_QPA_PLATFORM=offscreen python tests/test_worker_reaping.py
"""
import os, sys, gc

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QThread, QEventLoop, QTimer, Signal
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.jm_col_worker import NormalColValueWorker

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    win = mw.MainWindow()

    def settle(ms=80):
        loop = QEventLoop(); QTimer.singleShot(ms, loop.quit); loop.exec(); gc.collect()

    def count(cls_name):
        return sum(1 for c in win.findChildren(QThread)
                   if type(c).__name__ == cls_name)

    try:
        # ── the shadowing that makes the naive fix wrong ─────────────────
        shadowed = []
        for cname in ("_WifiJMFetchWorker", "_RemoteAssistJMFetchWorker",
                      "_ComputerNormJMWorker"):
            cls = getattr(mw, cname, None)
            if cls is None:
                continue
            mo = cls.staticMetaObject
            sigs = [bytes(mo.method(i).methodSignature()).decode()
                    for i in range(mo.methodCount())]
            fin = [s for s in sigs if s.startswith("finished")]
            if len(fin) > 1:
                shadowed.append(f"{cname}: {fin}")
        check("these classes really do shadow QThread.finished (trap 1 is real)",
              len(shadowed) >= 2, "; ".join(shadowed[:2]))

        # ── ERROR path: the case the naive fix silently missed ───────────
        for _ in range(8):
            w = mw._RemoteAssistJMFetchWorker("/nonexistent/parquet", parent=win)
            win._ra_jm_workers = win._reap_finished_workers(
                getattr(win, "_ra_jm_workers", []))
            win._ra_jm_workers.append(w)
            w.start(); w.wait(5000)
        settle()
        ra = count("_RemoteAssistJMFetchWorker")
        check("failed fetch workers are reaped (custom `finished` never fires)",
              ra <= 1, f"{ra} still parented after 8 failed runs (expected <= 1)")

        for _ in range(8):
            w = mw._ComputerNormJMWorker("/nonexistent/parquet", parent=win)
            win._computer_norm_jm_workers = win._reap_finished_workers(
                getattr(win, "_computer_norm_jm_workers", []))
            win._computer_norm_jm_workers.append(w)
            w.start(); w.wait(5000)
        settle()
        cn = count("_ComputerNormJMWorker")
        check("failed computer-normalisation workers are reaped",
              cn <= 1, f"{cn} still parented after 8 failed runs")

        # ── SUCCESS path: column workers with real data ──────────────────
        events = [{"record_id": i, "event_id": 4624, "computer": f"H{i % 40}",
                   "event_data": {}} for i in range(4_000)]
        for _ in range(8):
            w = NormalColValueWorker(list(events), "computer", parent=win)
            w.start(); win._track_col_worker(w); w.wait(10_000)
        settle()
        cw = count("NormalColValueWorker")
        check("succeeded column workers are reaped",
              cw <= 1, f"{cw} still parented after 8 popups")

        # ── the reaper must never drop a RUNNING worker ──────────────────
        class Slow(QThread):
            finished = Signal(object)      # shadows QThread.finished, as the real ones do
            def run(self): self.msleep(1500)
        slow = Slow(parent=win); slow.start()
        kept = win._reap_finished_workers([slow])
        check("a still-running worker is kept, not deleted",
              kept == [slow] and slow.isRunning())
        slow.wait(5000)

        # ── reaping twice must not touch aalready-deleted object ──────────────
        done = Slow(parent=win); done.start(); done.wait(5000)
        win._reap_finished_workers([done])
        settle()
        try:
            again = win._reap_finished_workers([done])   # same, now-reaped worker
            check("re-reaping an already-deleted worker is safe", again == [])
        except RuntimeError as exc:
            check("re-reaping an already-deleted worker is safe", False, repr(exc))

        check("_thread_running() treats a reaped worker as not running",
              win._thread_running(done) is False)
    finally:
        win.close()
        settle()

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
