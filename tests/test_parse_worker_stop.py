"""Normal mode: STOP really stops the parse, and a stopped parse says it is incomplete.

Gemini audit 1-02 / 12-01 (High): ParseWorker.request_stop() called
self._engine.stop_event.set() -- an attribute that does not exist -- inside
"except AttributeError: pass", so the engine never got the stop and parsed
every file.  A stop before the engine existed was lost too, and
ProcessingEngine.run() cleared a stop that came before it.  The stopped
result was emitted unsorted with an empty search cache, and nothing told the
examiner that the loaded events were only part of the evidence.

Expected:
- a stop during the parse stops the engine (fewer files parsed than given);
- a stop before the parse starts parses nothing;
- ProcessingEngine.stop() before run() is honoured;
- a stopped parse carries a warning (not benign) that names how many files
  were read, and its events are sorted with a search cache of the same length.

Real logs (read in place): needs EVTX_TEST_LOGS_ONLINE.
"""
import glob
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run_worker(app, files, stop_when):
    """stop_when: 'before' | 'progress' | None.  Returns (worker, payload, seconds)."""
    from evtx_tool.core.filters import empty_filter
    from evtx_tool.gui.worker import ParseWorker
    w = ParseWorker(files=files, filter_config=empty_filter(), do_attack=False, max_workers=2)
    box = {}
    w.finished.connect(lambda *a: box.setdefault("fin", a))
    w.error.connect(lambda m: box.setdefault("err", m))
    if stop_when == "progress":
        from PySide6.QtCore import Qt
        # Direct: runs in the worker thread as each file completes, so the stop
        # lands mid-parse however fast the machine is.
        w.progress.connect(lambda s: w.request_stop() if s.get("done_files", 0) >= 2 else None,
                           Qt.DirectConnection)
    if stop_when == "before":
        w.request_stop()
    t0 = time.monotonic()
    w.start()
    while not w.wait(50):
        app.processEvents()
    app.processEvents()
    return w, box, time.monotonic() - t0


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    files = sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True), key=os.path.getsize)
    files = [f for f in files if os.path.getsize(f) > 70_000][:60]
    print(f"{len(files)} files")
    from PySide6.QtCore import QCoreApplication
    app = QCoreApplication.instance() or QCoreApplication([])

    w, box, secs = run_worker(app, files, "progress")
    st = w._engine.state
    check("a stop during the parse stops the engine early", st.done_files < len(files),
          f"done {st.done_files} of {len(files)} in {secs:.1f}s")
    fin = box.get("fin")
    evs, cache = (fin[0], fin[4]) if fin else ([], [])
    ts = [e.get("timestamp", "") or "" for e in evs]
    check("the stopped result is sorted by time", ts == sorted(ts), f"{len(evs)} events")
    check("the stopped result has a search cache for every event", len(cache) == len(evs),
          f"{len(cache)} vs {len(evs)}")
    benign = set(w.parse_benign_warnings)
    loud = [x for x in w.parse_warnings if x not in benign]
    check("a stopped parse carries a warning that the results are incomplete",
          any("stopped" in x.lower() and str(len(files)) in x for x in loud), str(loud[:2]))

    w2, box2, _ = run_worker(app, files, "before")
    st2 = w2._engine.state if w2._engine is not None else None
    n2 = len(box2["fin"][0]) if box2.get("fin") else 0
    check("a stop before the parse starts parses nothing", (st2 is None or st2.done_files == 0) and n2 == 0,
          f"done {st2.done_files if st2 else None}, events {n2}")

    from evtx_tool.core.engine import ProcessingEngine
    from evtx_tool.core.filters import empty_filter
    eng = ProcessingEngine(max_workers=2)
    eng.stop()
    out = eng.run(files[:5], empty_filter())
    check("ProcessingEngine.stop() before run() is honoured", eng.state.done_files == 0 and not out,
          f"done {eng.state.done_files}, events {len(out)}")

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
