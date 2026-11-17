"""Juggernaut works when the session folder's path contains an apostrophe (Gemini 13-01).

A Windows user named O'Brien has %TEMP% under C:\\Users\\O'Brien. Several Juggernaut
queries pasted shard paths into SQL without doubling the quote (or pasted the
text of a Python list, which switches to double quotes, a DuckDB identifier),
so the query failed: exports and the analysis rebuild could not run.

Expected: with every shard under a folder whose name has an apostrophe, the
Juggernaut export writes all four formats with every event's EventData, and the
rebuild of whole events for IOC/correlation returns every event.
Synthetic data only.
"""
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    import test_around_pivot as T
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    base = tempfile.mkdtemp(prefix="jm_q_")
    tmp = os.path.join(base, "O'Brien's case")
    os.makedirs(tmp)
    try:
        evs = T.dataset()
        n_data = sum(1 for e in evs if e.get("event_data"))
        table = T.write_jm(evs, tmp)
        model = ArrowTableModel(table, parquet_dir=tmp)
        shards = list(model._get_shard_paths())
        model.close()
        check("setup: every shard path has an apostrophe", shards and all("'" in s for s in shards), f"{len(shards)} shards")
        for ext in ("csv", "json", "xml", "html"):
            out = os.path.join(base, f"out.{ext}")
            w = mw._JMExportWorker(table, shards, "1=1", [], "timestamp_utc ASC, source_file ASC, record_id ASC", out, ext, 10 ** 9)
            errs, oks = [], []
            w.failed.connect(errs.append)
            w.finished_ok.connect(lambda n, p: oks.append(n))
            w.run()
            check(f"{ext}: export succeeds", not errs and oks and os.path.exists(out), str(errs)[:200])
        if os.path.exists(os.path.join(base, "out.json")):
            jd = json.load(open(os.path.join(base, "out.json"), encoding="utf-8"))
            check("json: every event with EventData carries it", sum(1 for e in jd if e.get("event_data")) == n_data)
        w = mw._JMAnalysisMaterializeWorker(tmp)
        got, errs = [], []
        w.finished_ok.connect(got.append)
        for sig in ("failed", "error"):
            if hasattr(w, sig):
                getattr(w, sig).connect(errs.append)
        w.run()
        rows = got[0] if got else []
        check("analysis rebuild returns every event", len(rows) == len(evs), f"{len(rows)} of {len(evs)}; errors {str(errs)[:200]}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
