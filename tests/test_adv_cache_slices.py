"""The advanced-search haystack builds in short time slices, not 1 s chunks.

A fixed 20,000-event chunk (~50 us an event) froze the window ~1 s per chunk,
about 23 times in a row after loading 460k events.  Each slice must now stop
after a few milliseconds and the build must still complete, with the same
result as building it in one go.

Run: QT_QPA_PLATFORM=offscreen python tests/test_adv_cache_slices.py
"""
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.models import EventTableModel
    evs = [{"event_id": 4624, "timestamp": f"2025-06-29T12:00:{i % 60:02d}.000000Z", "computer": "WS1",
            "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "level_name": "Information",
            "record_id": i, "source_file": "Security.evtx", "event_data": {"TargetUserName": f"user{i}"}}
           for i in range(3000)]
    m = EventTableModel()
    m.set_events(evs)
    expected = [EventTableModel.build_adv_search_str(e).lower() for e in evs]

    real = EventTableModel.build_adv_search_str

    def slow(ev):                      # ~0.5 ms an event: a fixed chunk would be ~10 s
        t = time.perf_counter()
        while time.perf_counter() - t < 0.0005:
            pass
        return real(ev)
    m.build_adv_search_str = slow
    slices = []
    orig_step = m._adv_cache_step

    def timed_step():
        t = time.perf_counter()
        orig_step()
        slices.append((time.perf_counter() - t) * 1000)
    m._adv_cache_step = timed_step
    m.start_adv_cache_build()
    m._adv_build_timer.timeout.disconnect()
    m._adv_build_timer.timeout.connect(timed_step)
    end = time.time() + 30
    while m._adv_search_cache is None and time.time() < end:
        app.processEvents()
    check("the build completes", m._adv_search_cache is not None, f"{len(slices)} slices")
    check("no slice runs much past its budget (8 ms)", slices and max(slices) < 40,
          f"longest {max(slices):.1f} ms over {len(slices)} slices" if slices else "no slices")
    check("the result is the same as a one-go build", m._adv_search_cache == expected)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
