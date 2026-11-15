"""Juggernaut: a stop that comes before the parse starts is not lost.

Gemini audit 2-08 (Medium): HeavyweightParseWorker.run() had no stop check
before it built and ran the engine, and HeavyweightEngine.run() cleared its
stop flag at the start, so a stop() made first was wiped and every file was
parsed.  Splitting big logs up front had no stop check either.

Expected: a worker stopped before start emits cancelled, not finished, and
parses nothing; an engine stopped before run() parses nothing; the same
engine then runs normally (the flag is cleared when a run ends).
Real logs read in place (needs EVTX_TEST_LOGS_ONLINE).
"""
import glob
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rows(d):
    import duckdb
    fs = glob.glob(os.path.join(d, "*.parquet"))
    if not fs:
        return 0
    return duckdb.sql(f"select count(*) from read_parquet({[f.replace(chr(92), '/') for f in fs]})").fetchone()[0]


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    files = sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True), key=os.path.getsize)
    files = [f for f in files if os.path.getsize(f) > 70_000][:4]
    from PySide6.QtCore import QCoreApplication
    app = QCoreApplication.instance() or QCoreApplication([])
    from evtx_tool.gui.heavyweight_worker import HeavyweightParseWorker
    w = HeavyweightParseWorker(files=files, filter_config=None)
    box = {}
    w.finished.connect(lambda r: box.setdefault("finished", r))
    w.cancelled.connect(lambda: box.setdefault("cancelled", True))
    w.request_stop()
    w.start()
    while not w.wait(50):
        app.processEvents()
    app.processEvents()
    fin = box.get("finished")
    n = rows(fin) if fin else 0
    check("a worker stopped before start emits cancelled", box.get("cancelled") and not fin,
          f"cancelled={box.get('cancelled')} finished={bool(fin)} rows={n}")
    if fin:
        shutil.rmtree(fin, ignore_errors=True)

    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    d = tempfile.mkdtemp(prefix="jmstop_")
    eng = HeavyweightEngine(parquet_dir=d)
    eng.stop()
    eng.run(files, None)
    check("an engine stopped before run() parses nothing", rows(d) == 0, f"{rows(d)} rows")
    shutil.rmtree(d, ignore_errors=True)
    d = tempfile.mkdtemp(prefix="jmstop2_")
    eng._parquet_dir = d
    eng.run(files, None)
    check("the same engine then runs normally", rows(d) > 0, f"{rows(d)} rows")
    shutil.rmtree(d, ignore_errors=True)
    k = sum(ok for _, ok, _ in CHECKS)
    print(f"{k}/{len(CHECKS)} checks passed")
    return 0 if k == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
