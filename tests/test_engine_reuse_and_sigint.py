"""ProcessingEngine leaves Ctrl+C alone outside run(), and can be run twice.

Gemini audit 1-07 (High): the constructor replaced the process's SIGINT handler
for good (Ctrl+C never raised KeyboardInterrupt again in that process), a second
run() raised "threads can only be started once" and left is_running=True, and
errors from the first run stayed in state for the second.

Gemini audit 1-11 (Medium), same test: a file that failed to open was
counted in done_files twice, so progress passed 100%.

Expected: constructing an engine does not change the SIGINT handler, and it is
the caller's handler again after run(); a second run() parses the same events;
an error from run 1 is not reported by run 2; is_running is False after each.
Real logs read in place (needs EVTX_TEST_LOGS_ONLINE) plus one synthetic
not-an-EVTX file.
"""
import glob
import os
import signal
import sys
import tempfile

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
    bad = os.path.join(tempfile.mkdtemp(prefix="reuse_"), "not_a_log.evtx")
    with open(bad, "wb") as fh:
        fh.write(b"NOT AN EVTX FILE" * 64)

    from evtx_tool.core.engine import ProcessingEngine
    from evtx_tool.core.filters import empty_filter

    def mine(sig, frame):
        pass
    signal.signal(signal.SIGINT, mine)
    eng = ProcessingEngine(max_workers=2)
    check("constructing an engine leaves the SIGINT handler alone", signal.getsignal(signal.SIGINT) is mine,
          str(signal.getsignal(signal.SIGINT)))
    r1 = eng.run(files + [bad], empty_filter())
    n1, e1 = len(r1), list(eng.state.errors)
    check("the caller's SIGINT handler is back after run()", signal.getsignal(signal.SIGINT) is mine)
    check("run 1 reports the unreadable file", eng.state.failed_files >= 1 or e1, f"errors {len(e1)}")
    check("is_running is False after run 1", eng.state.is_running is False)
    # Gemini audit 1-11: a file that fails to open was counted done twice.
    check("each file is counted done once (a failed file too)", eng.state.done_files == len(files) + 1,
          f"done {eng.state.done_files} of {len(files) + 1}")
    try:
        r2 = eng.run(files, empty_filter())
        err = ""
    except Exception as e:
        r2, err = [], repr(e)
    check("a second run() works and parses the same events", len(r2) > 0 and len(r2) == n1, f"{len(r2)} vs {n1} {err}")
    check("run 2 does not repeat run 1's errors", not eng.state.errors and eng.state.failed_files == 0,
          f"{eng.state.errors[:1]} failed={eng.state.failed_files}")
    check("is_running is False after run 2", eng.state.is_running is False)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
