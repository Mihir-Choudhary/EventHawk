"""Juggernaut: a worker that dies mid-parse ends the parse with an error, not a hang.

Gemini audit 2-07 (High): HeavyweightEngine.run() waited for one DONE message
per task and, on an empty queue, just waited again.  A worker process that
died (crash, OOM kill) before sending DONE left it waiting forever.

Expected: when every worker has ended and tasks are still unreported, run()
returns; the file whose task was lost carries an error in last_parse_stats
naming it as not fully read; the other files are read in full.

The death is simulated in the thread fallback (multiprocessing made
unavailable): one worker takes a task and returns without a DONE.  Real logs
read in place (needs EVTX_TEST_LOGS_ONLINE).
"""
import glob
import os
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    files = sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True), key=os.path.getsize)
    files = [f for f in files if os.path.getsize(f) > 70_000][:6]
    import multiprocessing
    multiprocessing.get_all_start_methods = lambda: []      # force the thread fallback
    from evtx_tool.core.heavyweight import engine as H
    real_loop = H._hw_worker_loop
    died = {}
    lock = threading.Lock()

    def loop(in_q, out_q, stop_event):
        with lock:
            first = not died
            if first:
                died["yes"] = True
        if first:
            task = in_q.get()
            died["file"] = task.get("original_file") or task.get("filepath")
            return                                   # "dies": no DONE for this task
        return real_loop(in_q, out_q, stop_event)
    H._hw_worker_loop = loop

    d = tempfile.mkdtemp(prefix="jmdeath_")
    eng = H.HeavyweightEngine(parquet_dir=d)
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("r", eng.run(files, None)), daemon=True)
    t.start()
    t.join(120)
    hung = t.is_alive()
    if hung:
        eng.stop()
        t.join(30)
    check("run() returns when a worker died with a task", not hung)
    st = eng.last_parse_stats or {}
    lost = died.get("file")
    v = st.get(lost, {}) if lost else {}
    err = v.get("stream_error") or v.get("open_error") or ""
    check("the lost file carries an error saying it was not fully read", bool(err), repr(err)[:160])
    others = [f for f in files if f != lost]
    full = [f for f in others if st.get(f, {}).get("rows", 0) > 0 and not st.get(f, {}).get("stream_error")]
    check("every other file is read", len(full) == len(others), f"{len(full)} of {len(others)}")
    shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
