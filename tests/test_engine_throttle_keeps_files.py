"""CPU throttling in Normal mode never cancels a file that was already handed to the workers.

Gemini audit 1-01 (Critical): when the CPU monitor reported sustained load,
ProcessingEngine._run_pool shut its process pool down with
cancel_futures=True (cancelling files already submitted) and started a smaller
one; when the load dropped it raised the worker count without a new pool, so
the next spike cancelled again.  Files were lost or the parse hung.

Expected: with the load flapping on and off throughout the parse, every file
is parsed: the same files, the same number of events as an unthrottled run,
no failed files, no errors, and the parse finishes.

Real logs (read in place, not copied): needs EVTX_TEST_LOGS_ONLINE; the CPU
readings are scripted (ResourceMonitor.is_throttling replaced), the parse,
the pool and the files are real.
"""
import glob
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
HUNG = False


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run(files, flapping, timeout=600):
    from evtx_tool.core.engine import ProcessingEngine
    eng = ProcessingEngine(max_workers=4, cpu_limit=85.0)
    if flapping:
        calls = [0]

        def is_throttling():
            calls[0] += 1
            return (calls[0] // 3) % 2 == 0     # on for 3 checks, off for 3, ...
        eng._monitor.is_throttling = is_throttling
    eng._monitor.has_memory_pressure = lambda: False
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("ev", eng.run(files, None)), daemon=True)
    t.start()
    t.join(timeout)
    hung = t.is_alive()
    global HUNG
    HUNG = HUNG or hung
    if hung:
        eng.stop() if hasattr(eng, "stop") else None
    ev = box.get("ev") or []
    st = eng.state
    return {"hung": hung, "n": len(ev), "files": {e.get("source_file") for e in ev},
            "failed": st.failed_files, "done": st.done_files, "errors": list(st.errors)}


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    files = sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True), key=os.path.getsize)
    files = [f for f in files if os.path.getsize(f) > 70_000][:40]   # 40 small, non-empty logs
    print(f"{len(files)} files")
    base = run(files, flapping=False)
    print("unthrottled:", {k: v for k, v in base.items() if k != "files"} | {"files": len(base["files"])})
    thr = run(files, flapping=True, timeout=max(120, 0))
    print("flapping:   ", {k: v for k, v in thr.items() if k not in ("files", "errors")}
          | {"files": len(thr["files"]), "errors": thr["errors"][:2]})
    check("unthrottled run is clean (the reference)", not base["hung"] and base["failed"] == 0 and base["n"] > 0)
    check("with the CPU load flapping, the parse finishes", not thr["hung"])
    check("with the CPU load flapping, no file fails", thr["failed"] == 0 and not thr["errors"],
          f"{thr['failed']} failed; {thr['errors'][:2]}")
    check("with the CPU load flapping, every file is parsed", thr["done"] == len(files) and thr["files"] == base["files"],
          f"done {thr['done']} of {len(files)}; files with events {len(thr['files'])} vs {len(base['files'])}")
    check("with the CPU load flapping, the same number of events", thr["n"] == base["n"], f"{thr['n']} vs {base['n']}")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    code = main()
    sys.stdout.flush()
    if HUNG:
        os._exit(code)     # a hung pool must not keep the process alive
    sys.exit(code)         # otherwise exit normally: the pool shuts its workers down
