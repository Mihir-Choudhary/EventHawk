"""Juggernaut's Event Detail shows the same System fields and decodings as Normal mode.

Gemini audit 2-04 (Medium): ArrowTableModel.get_event() left out
event_source_name, provider_guid, qualifiers and version -- all stored in the
Parquet shards -- and never ran the SemanticNormalizer, so the detail pane had
no logon_type_desc / keywords_desc, which Normal mode shows.

Expected, on a real log parsed in both modes: for the same record, the
Juggernaut detail dict has provider_guid, event_source_name, qualifiers and
version equal to Normal mode's, and every *_desc key Normal mode has.
Real log read in place (needs EVTX_TEST_LOGS_ONLINE; a Security log with 4624).
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


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    from evtx_tool.core.engine import _worker_parse_file
    from evtx_tool.core.filters import empty_filter
    from evtx_tool.analysis.normalizer import SemanticNormalizer
    cand = sorted((f for f in glob.glob(os.path.join(root, "**", "Security.evtx"), recursive=True)),
                  key=os.path.getsize)
    path, nev = None, None
    for f in cand:
        evs = _worker_parse_file({"filepath": f, "filter_config": empty_filter()})["events"]
        hit = [e for e in evs if e["event_id"] == 4624]
        if hit:
            path, nev = f, hit[0]
            break
    if not path:
        print("SKIP: no Security log with a 4624")
        return 0
    SemanticNormalizer.get().enrich(nev)
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    d = tempfile.mkdtemp(prefix="jmdetail_")
    try:
        HeavyweightEngine(parquet_dir=d).run([path], None)
        from evtx_tool.core.heavyweight.engine import load_arrow_table
        m = ArrowTableModel(load_arrow_table(d), parquet_dir=d)
        import time
        t0 = time.monotonic()
        while m.rowCount() == 0 and time.monotonic() - t0 < 60:
            app.processEvents()
            time.sleep(0.05)
        row = None
        for r in range(m.rowCount()):
            ev = m.get_event(r)
            if ev and ev.get("record_id") == nev["record_id"]:
                row = ev
                break
        check("the record is found in Juggernaut mode", row is not None)
        row = row or {}
        for k in ("provider_guid", "event_source_name", "qualifiers", "version"):
            check(f"{k} matches Normal mode", row.get(k) == nev.get(k), f"{row.get(k)!r} vs {nev.get(k)!r}")
        descs = sorted(k for k in nev if k.endswith("_desc"))
        missing = [k for k in descs if row.get(k) != nev.get(k)]
        check("every *_desc decoding Normal mode shows is there and equal", descs and not missing,
              f"{len(descs)} in Normal; differing {missing[:4]}")
        if hasattr(m, "close"):
            m.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
