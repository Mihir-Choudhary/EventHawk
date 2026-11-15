"""One undecodable record never costs the records after it, and is counted once.

Gemini audit 1-03 / 2-01 (High): pyevtx-rs records_json() yields a RuntimeError
OBJECT (not a raised exception) for a record it cannot decode -- its own stub
says so.  parser.iter_events crashed on it (AttributeError in its except),
Juggernaut's _process aborted the whole stream on it, and salvage_records_json
dropped the rest of that 64 KiB chunk.  Normal mode counted it twice: once as
skipped and again as missing_vs_expected.

Expected, on a real log where one record is replaced by a RuntimeError item:
every other record is read (Normal worker, Juggernaut worker, iter_events,
salvage), and the lost record is reported once, not twice.

Real log read in place (needs EVTX_TEST_LOGS_ONLINE); the parser is the real
one, wrapped so one record comes back as a RuntimeError object.
"""
import glob
import os
import queue
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
BAD_AT = 5           # 0-based position of the record turned into an error
POISON = [0]         # how many more parsers get the error (salvage opens one per chunk)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def install_wrapper():
    import evtx
    real = evtx.PyEvtxParser

    class Wrapped:
        def __init__(self, path):
            self._p = real(path)

        def records_json(self):
            bad = POISON[0] > 0
            POISON[0] -= 1
            for i, rec in enumerate(self._p.records_json()):
                yield RuntimeError("synthetic decode failure") if (bad and i == BAD_AT) else rec

        def records(self):
            return self._p.records()

        def __getattr__(self, n):
            return getattr(self._p, n)
    evtx.PyEvtxParser = Wrapped
    import evtx_tool.core.parser as P
    P._RustParser = Wrapped
    return real


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    import evtx
    files = sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True), key=os.path.getsize)
    path = None
    for f in files:
        if os.path.getsize(f) > 70_000:
            n = sum(1 for r in evtx.PyEvtxParser(f).records_json() if not isinstance(r, Exception))
            if 20 <= n <= 60_000:
                path, truth = f, n
                break
    print(f"log with {truth} records; record #{BAD_AT + 1} becomes a RuntimeError item")
    install_wrapper()

    from evtx_tool.core.engine import _worker_parse_file
    from evtx_tool.core.filters import empty_filter
    POISON[0] = 1
    try:
        r = _worker_parse_file({"filepath": path, "filter_config": empty_filter()})
    except Exception as e:
        r = {"error": repr(e)}
    got = len(r.get("events", []))
    lost = r.get("skipped_records", 0) + r.get("missing_vs_expected", 0)
    check("Normal worker reads every other record", got == truth - 1, f"{got} of {truth - 1}; {r.get('error', '')}")
    check("Normal worker reports the lost record once, not twice", lost == 1,
          f"skipped {r.get('skipped_records')} + missing {r.get('missing_vs_expected')}")

    from evtx_tool.core.heavyweight.engine import _hw_worker_stream
    POISON[0] = 1
    q = queue.Queue()
    try:
        _hw_worker_stream({"filepath": path, "filter_config": None}, q, threading.Event())
    except Exception as e:
        print("JM worker raised", repr(e))
    rows, done = 0, {}
    while not q.empty():
        kind, _src, payload = q.get()
        if kind == "TUPLES":
            rows += len(payload)
        elif kind == "DONE":
            done = payload
    check("Juggernaut worker reads every other record", rows == truth - 1, f"{rows} of {truth - 1}")
    check("Juggernaut worker does not abort the stream on it", not done.get("stream_error"),
          str(done.get("stream_error")))
    jlost = done.get("json_errors", 0) + done.get("missing_vs_expected", 0)
    check("Juggernaut worker reports the lost record once", jlost == 1,
          f"json_errors {done.get('json_errors')} + missing {done.get('missing_vs_expected')}")

    import evtx_tool.core.parser as P
    POISON[0] = 1
    try:
        n_it = sum(1 for _ in P.iter_events(path))
        err = ""
    except Exception as e:
        n_it, err = -1, repr(e)
    check("iter_events skips it and reads every other record", n_it == truth - 1, f"{n_it}; {err}")

    from evtx_tool.core.chunk_salvage import salvage_records_json
    POISON[0] = 1
    gen = salvage_records_json(path)
    recs = []
    while True:
        try:
            rec = next(gen)
        except StopIteration as s:
            stats = s.value or {}
            break
        recs.append(rec)
    ok = [x for x in recs if not isinstance(x, Exception)]
    check("salvage keeps the rest of the chunk", len(ok) == truth - 1 and len(recs) == len(ok),
          f"{len(ok)} of {truth - 1}; stats {stats}")
    check("salvage counts the unreadable record", stats.get("records_unreadable", 0) >= 1, str(stats))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
