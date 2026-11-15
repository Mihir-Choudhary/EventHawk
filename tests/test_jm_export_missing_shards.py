"""A Juggernaut export fails loudly when the event data cannot be read; it never goes out without it.

Gemini audit 6-02 (Critical): in Juggernaut Mode the EventData lives in the
Parquet shards, not in the in-memory table.  When the shards could not be read
(cleaned from %TEMP%, removed by another session, the manifest unreadable):
- HTML / XML caught the error, logged a warning and wrote every event with
  empty EventData, then reported success;
- CSV / JSON (found while fixing this) did the same when the shard list was
  empty, and any single event missing from the shards went out empty too;
- HTML / XML skipped an event whose EventData JSON could not be read.

Expected, all four formats: intact shards export with every event's data; no
shards, a missing shard file, or an event missing from the shards -> the export
fails (failed signal), and no file is left at the destination.
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
FMTS = ("csv", "json", "xml", "html")


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run_export(table, shards, path, ext):
    import evtx_tool.gui.main_window as mw
    w = mw._JMExportWorker(table, shards, "1=1", [], "timestamp_utc ASC, source_file ASC, record_id ASC",
                           path, ext, 10 ** 9)
    errs, oks = [], []
    w.failed.connect(errs.append)
    w.finished_ok.connect(lambda n, p: oks.append(n))
    w.run()
    return errs, oks


def main() -> int:
    import pyarrow.parquet as pq
    import test_around_pivot as T
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    tmp = tempfile.mkdtemp(prefix="jm_miss_")
    try:
        evs = T.dataset()
        n_with_data = sum(1 for e in evs if e.get("event_data"))
        table = T.write_jm(evs, tmp)
        model = ArrowTableModel(table, parquet_dir=tmp)
        shards = list(model._get_shard_paths())
        model.close()
        print(f"{len(evs)} events, {n_with_data} with EventData, {len(shards)} shard(s)")

        # intact
        for ext in FMTS:
            out = os.path.join(tmp, f"ok.{ext}")
            errs, oks = run_export(table, shards, out, ext)
            check(f"{ext}: intact shards export", not errs and oks and os.path.exists(out), str(errs))
        jd = json.load(open(os.path.join(tmp, "ok.json"), encoding="utf-8"))
        check("json: every event that has EventData carries it", sum(1 for e in jd if e.get("event_data")) == n_with_data,
              f"{sum(1 for e in jd if e.get('event_data'))} of {n_with_data}")

        # one event missing from the shards
        cut_dir = os.path.join(tmp, "cut")
        os.makedirs(cut_dir)
        cut_shards = []
        dropped = False
        for i, s in enumerate(shards):
            t = pq.read_table(s)
            if not dropped and t.num_rows:
                t = t.slice(1)
                dropped = True
            p = os.path.join(cut_dir, f"s{i}.parquet")
            pq.write_table(t, p)
            cut_shards.append(p)

        cases = (("no shard list (manifest unreadable)", []),
                 ("a shard file that is gone", [os.path.join(tmp, "gone", "shard_0000.parquet")]),
                 ("an event missing from the shards", cut_shards))
        for label, sh in cases:
            for ext in FMTS:
                out = os.path.join(tmp, f"bad_{ext}_{len(sh)}_{label[:6].replace(' ', '_')}.{ext}")
                errs, oks = run_export(table, sh, out, ext)
                check(f"{ext}: {label} -> the export fails and leaves no file",
                      errs and not oks and not os.path.exists(out),
                      f"failed={errs[:1]} ok={oks} file={os.path.exists(out)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
