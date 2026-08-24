"""Tearing down Juggernaut must stop the Parquet-backed workers.

_cleanup_juggernaut() gives _col_value_workers a disconnect-cancel-wait so a
late emit cannot land in torn-down state -- but originally skipped
_jm_mat_worker and _jm_export_worker, which only closeEvent() handled.

That asymmetry mattered because _cleanup_juggernaut also runs on "start a new
parse" and "clear results", and it rmtree's the Parquet directory both
workers read.  The forensic hazard is the materialize worker: a late
finished_ok starts a full AnalysisRunner over events rebuilt from the OLD
dataset, so the IOC / Correlation tabs can show findings from the previous
set of logs while a different set is loaded.

Run: QT_QPA_PLATFORM=offscreen python tests/test_jm_teardown.py
"""
import os, sys, time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtCore import QThread, Signal, Qt
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    class FakeParquetWorker(QThread):
        """Same interface as the real workers: cancel() + result signals."""
        progress    = Signal(int, int)
        finished_ok = Signal(object)
        failed      = Signal(str)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._cancel = False
            self.cancel_called = False
            self.emitted_after_cancel = False

        def cancel(self):
            self.cancel_called = True
            self._cancel = True

        def run(self):
            # Mimic the real fetch loop: spin until cancelled, then try to
            # deliver anyway -- exactly the late emit we must not receive.
            deadline = time.time() + 10
            while not self._cancel and time.time() < deadline:
                self.msleep(10)
            self.emitted_after_cancel = True
            if self._cancel:
                # Mirrors the real workers: a cancelled run reports via failed.
                self.failed.emit("__cancelled__")
            self.finished_ok.emit([{"event_id": 4624}])

    w = MainWindow()
    try:
        # The two workers are treated DIFFERENTLY on purpose:
        #
        #   _jm_mat_worker    finished_ok must be silenced -- it would start a
        #                     full AnalysisRunner over events rebuilt from the
        #                     dataset being discarded, so IOC / Correlation
        #                     results could be attributed to the wrong logs.
        #
        #   _jm_export_worker keeps its signals -- cancelling deletes the
        #                     partial file, and the analyst must still be told
        #                     ("Export was cancelled and the partial file was
        #                     deleted").  Silencing it would delete their
        #                     export with no notification.
        for attr, expect_delivery in (("_jm_mat_worker", False),
                                      ("_jm_export_worker", True)):
            got_ok, got_failed = [], []
            wk = FakeParquetWorker(parent=w)
            wk.finished_ok.connect(lambda v: got_ok.append(v), Qt.QueuedConnection)
            wk.failed.connect(lambda m: got_failed.append(m), Qt.QueuedConnection)
            setattr(w, attr, wk)
            wk.start()
            for _ in range(30):                 # let it actually get going
                app.processEvents(); time.sleep(0.005)
            check(f"{attr}: worker is running before cleanup", wk.isRunning())

            t0 = time.perf_counter()
            w._cleanup_juggernaut()
            elapsed = (time.perf_counter() - t0) * 1000

            check(f"{attr}: cleanup called cancel()", wk.cancel_called)
            check(f"{attr}: reference cleared", getattr(w, attr, None) is None)
            # This runs on the GUI thread from the X button and from "new
            # parse", so it must not freeze the window for seconds.
            check(f"{attr}: cleanup did not block the GUI thread",
                  elapsed < 1500, f"took {elapsed:.0f} ms (budget 500 ms + slack)")

            for _ in range(40):
                app.processEvents(); time.sleep(0.005)
            check(f"{attr}: worker really did emit after cancel (test is valid)",
                  wk.emitted_after_cancel)

            if expect_delivery:
                check(f"{attr}: cancellation IS still reported to the analyst",
                      bool(got_failed) or bool(got_ok),
                      "no signal reached a handler -- a cancelled export would "
                      "delete the partial file silently")
            else:
                check(f"{attr}: late finished_ok did NOT reach a handler",
                      not got_ok,
                      f"received {len(got_ok)} late payload(s) -- stale-dataset "
                      f"analysis would have started")
                check(f"{attr}: failed IS kept so cancellation still reports",
                      bool(got_failed), "failed was silenced too")

        # Cleanup must stay safe when there is nothing to stop.
        try:
            w._cleanup_juggernaut()
            w._cleanup_juggernaut()
            check("cleanup is idempotent with no workers present", True)
        except Exception as exc:
            check("cleanup is idempotent with no workers present", False, repr(exc))
    finally:
        w.close()

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
