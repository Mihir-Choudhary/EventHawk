"""A long operation must show a wait dialog, not a frozen window.

Reported: "for more evtx it is hanging". Two distinct causes:
  1. Normal-mode sorting runs inline on the GUI thread and had NO indicator.
  2. Juggernaut's overlay is timer-driven; if it never actually appears the
     window looks hung even though the work is on a worker.

These checks assert the dialog is really shown/hidden, not merely that a
signal is connected.

Run: QT_QPA_PLATFORM=offscreen python tests/test_busy_feedback.py
"""
import os, sys, time, random

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt, QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    def pump(ms):
        end = time.perf_counter() + ms / 1000.0
        while time.perf_counter() < end:
            app.processEvents()
            time.sleep(0.005)

    w = MainWindow()

    # ── Juggernaut overlay: timer-driven, must actually appear ───────────
    w._on_hw_filter_busy_started()
    pump(300)                                   # longer than the 150 ms delay
    check("JM busy overlay appears for a slow operation",
          w._hw_loading_dlg is not None)
    w._on_hw_filter_busy_finished()
    app.processEvents()
    check("JM busy overlay closes when the operation finishes",
          w._hw_loading_dlg is None)

    # a fast operation must NOT flash a dialog
    w._on_hw_filter_busy_started()
    pump(40)
    w._on_hw_filter_busy_finished()
    pump(250)
    check("fast operation does not flash a dialog",
          w._hw_loading_dlg is None)

    # ── Normal-mode sorting: was inline with no feedback at all ──────────
    shown = []
    orig_show = w._show_hw_loading_dialog
    def spy(heading="", detail="", **kw):
        shown.append((heading, detail))
        return orig_show(heading=heading, detail=detail, **kw)
    w._show_hw_loading_dialog = spy

    N = 60_000
    random.seed(4)
    events = [{
        "record_id": i, "event_id": 4624, "level_name": "Information",
        "timestamp": f"2025-06-10T09:00:{i%60:02d}.000000Z",
        "computer": f"HOST-{i%17:02d}", "channel": "Security",
        "user_id": "S-1-5-18", "source_file": "/l.evtx", "provider": "P",
        "keywords": "", "task": 0, "opcode": 0, "process_id": 4,
        "thread_id": 8, "correlation_id": "", "event_data": {"A": "b"},
    } for i in range(N)]
    m = EventTableModel(); m.set_events(events)
    proxy = EventFilterProxyModel(); proxy.setSourceModel(m)

    shown.clear()
    w._sort_with_feedback(proxy, 4, Qt.SortOrder.AscendingOrder)
    check("normal-mode sort shows a wait dialog", bool(shown), str(shown[:1]))
    check("the dialog says it is sorting",
          shown and "Sorting" in shown[0][0], str(shown[:1]))
    check("dialog is closed again afterwards", w._hw_loading_dlg is None)

    # small dataset must stay silent
    m_small = EventTableModel(); m_small.set_events(events[:500])
    proxy_small = EventFilterProxyModel(); proxy_small.setSourceModel(m_small)
    shown.clear()
    w._sort_with_feedback(proxy_small, 4, Qt.SortOrder.AscendingOrder)
    check("small dataset sorts without a dialog", not shown, str(shown[:1]))

    # ── An async (Juggernaut) model must NOT be wrapped ──────────────────
    class FakeAsync:
        busy_started = object()          # presence is the async marker
        def __init__(self): self.sorted = None
        def rowCount(self): return 5_000_000
        def sort(self, c, o): self.sorted = (c, o)
    fake = FakeAsync()
    shown.clear()
    w._sort_with_feedback(fake, 3, Qt.SortOrder.DescendingOrder)
    check("async model sorts without a synchronous dialog", not shown)
    check("async model still receives the sort call",
          fake.sorted == (3, Qt.SortOrder.DescendingOrder), str(fake.sorted))

    w._show_hw_loading_dialog = orig_show

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
