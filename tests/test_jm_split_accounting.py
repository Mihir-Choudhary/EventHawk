"""Juggernaut: a record silently skipped in a split (>64 MB) log is still reported.

Gemini audit 2-02 / 2-09 (High): _hw_worker_stream computed missing_vs_expected
only when the task was not a split shard, on the belief that a shard carries
the whole file's ranges.  It does not: expected_ranges() reads the chunk
headers IN the file it is given, which for a shard are only that shard's
chunks.  So on every log over 64 MB a silently skipped record went
unreported.  Also: a split that fell back to the whole file was still
marked is_split; a filter that could not be compiled let every event through.

Expected:
- on the real >64 MB log, split for real, every shard read pristine reports
  0 missing and the shards together hold every record the log has;
- with one record silently skipped in one shard, that shard reports 1 missing;
- a file with a trailing partial chunk is reported (no parser reads that
  chunk, so splitting loses nothing more; see test_truncation_partial_chunk);
- a filter that cannot be compiled yields no rows and an error, not all rows.

Real log read in place (needs EVTX_TEST_LOGS or _ONLINE with a log over 64 MB); shards
are written to a temp folder and deleted.
"""
import glob
import os
import queue
import shutil
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
DROP = [None]   # (shard path, position) of a record to skip silently


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def install_wrapper():
    import evtx
    real = evtx.PyEvtxParser

    class Wrapped:
        def __init__(self, path):
            self._path, self._p = path, real(path)

        def records_json(self):
            for i, rec in enumerate(self._p.records_json()):
                if DROP[0] and DROP[0] == (self._path, i):
                    continue          # silently skipped: no error, no item
                yield rec

        def __getattr__(self, n):
            return getattr(self._p, n)
    evtx.PyEvtxParser = Wrapped


def run_shard(path, fc=None):
    from evtx_tool.core.heavyweight.engine import _hw_worker_stream
    q = queue.Queue()
    _hw_worker_stream({"filepath": path, "filter_config": fc, "is_split": True,
                       "original_file": "orig.evtx"}, q, threading.Event())
    rows, done = 0, {}
    while not q.empty():
        kind, _s, payload = q.get()
        if kind == "TUPLES":
            rows += len(payload)
        elif kind == "DONE":
            done = payload
    return rows, done


def main() -> int:
    c = []
    for var in ("EVTX_TEST_LOGS", "EVTX_TEST_LOGS_ONLINE"):
        root = os.environ.get(var)
        if root and os.path.isdir(root):
            c += [f for f in glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True)
                  if os.path.getsize(f) > 64 * 1024 * 1024]
    big = min(c, key=os.path.getsize) if c else None
    if not big:
        print("SKIP: no log over 64 MB under EVTX_TEST_LOGS / EVTX_TEST_LOGS_ONLINE")
        return 0
    import evtx
    truth = sum(1 for r in evtx.PyEvtxParser(big).records_json() if not isinstance(r, Exception))
    print(f"log of {os.path.getsize(big) // 2**20} MB, {truth} records")
    install_wrapper()
    from evtx_tool.core.heavyweight import engine as H
    tmp = tempfile.mkdtemp(prefix="jmsplit_")
    try:
        subs = H._split_evtx(big, 4, tmp)
        check("the log is split into shards", len(subs) == 4, str(len(subs)))
        tot = miss = 0
        for s in subs:
            r, d = run_shard(s)
            tot += r
            miss += d.get("missing_vs_expected", 0)
        check("pristine shards report 0 missing", miss == 0, str(miss))
        check("the shards together hold every record", tot == truth, f"{tot} vs {truth}")
        DROP[0] = (subs[1], 100)
        r, d = run_shard(subs[1])
        DROP[0] = None
        check("a record skipped silently in a shard is reported missing", d.get("missing_vs_expected", 0) == 1,
              f"missing {d.get('missing_vs_expected')}, rows {r}")
        r, d = run_shard(subs[0], {"computers": [12345]})
        check("a filter that cannot be compiled gives no rows and an error",
              r == 0 and any(d.get(k) for k in ("open_error", "stream_error", "filter_error")),
              f"rows {r}; {d}")

        part = os.path.join(tmp, "partial.evtx")
        with open(part, "wb") as fh:
            fh.write(b"ElfFile\x00".ljust(4096, b"\x00"))
            for _ in range(16):
                fh.write(b"ElfChnk\x00".ljust(65536, b"\x00"))
            fh.write(b"ElfChnk\x00".ljust(32768, b"\x00"))
        from evtx_tool.core.parser import check_evtx_truncation
        w = check_evtx_truncation(part)
        check("a file with a trailing partial chunk is reported as truncated", bool(w), repr(w))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
