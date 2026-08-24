"""JM export: correctness off the GUI thread, and cancel leaves no partial file.

The export used to run inline on the GUI thread with no progress and no
cancel, freezing the window for its whole duration. These checks assert the
worker produces the same rows, in the right order, and that a cancelled export
deletes its partial file rather than leaving a truncated one that could be
mistaken for the complete evidence set.

Run: QT_QPA_PLATFORM=offscreen python tests/test_jm_export.py [logs_dir]
"""
import os, sys, csv, glob, json, time, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QEventLoop, QTimer
app = QApplication.instance() or QApplication([])

from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
from evtx_tool.gui.main_window import _JMExportWorker

# Guarded: the engine parses in worker processes, and an unguarded
# module body would be re-imported by each child.
def main() -> int:
    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    def run_worker(w, timeout_ms=600_000, cancel_after_ms=None):
        """Drive a worker to completion on the event loop; return (ok, payload)."""
        loop = QEventLoop()
        out = {}
        w.finished_ok.connect(lambda n, p: (out.update(ok=True, n=n, path=p), loop.quit()))
        w.failed.connect(lambda m: (out.update(ok=False, msg=m), loop.quit()))
        QTimer.singleShot(timeout_ms, loop.quit)
        if cancel_after_ms is not None:
            QTimer.singleShot(cancel_after_ms, w.cancel)
        w.start()
        loop.exec()
        w.wait(10_000)
        return out

    files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
    if not files:
        print(f"no .evtx under {LOGS} — skipping")
        return 0
    print(f"building parquet from {len(files)} files ...")

    tmp = tempfile.mkdtemp(prefix="jm_export_")
    try:
        pq_dir = HeavyweightEngine(parquet_dir=tmp).run(files)
        table  = load_arrow_table(pq_dir)
        total  = len(table)
        print(f"arrow table: {total:,} rows")

        import json as _json
        shards = _json.load(open(os.path.join(pq_dir, "parquet_manifest.json")))
        order  = "timestamp_utc ASC, source_file ASC, record_id ASC"

        # ── CSV export must be complete and ordered ──────────────────────────
        out_csv = os.path.join(tmp, "out.csv")
        t0 = time.perf_counter()
        w = _JMExportWorker(table, shards, "1=1", [], order, out_csv, "csv", total)
        r = run_worker(w)
        elapsed = time.perf_counter() - t0
        check("CSV export completes", r.get("ok"), str(r.get("msg"))[:200])
        if r.get("ok"):
            print(f"      exported {r['n']:,} rows in {elapsed:.1f}s")
            check("CSV row count equals the table", r["n"] == total, f"{r['n']} vs {total}")
            with open(out_csv, newline="", encoding="utf-8") as fh:
                rd = csv.reader(fh)
                hdr = next(rd)
                body_n = sum(1 for _ in rd)
            check("CSV file holds every row", body_n == total, f"{body_n} vs {total}")
            check("CSV carries event_data_json (EventData not dropped)",
                  "event_data_json" in hdr, str(hdr[:6]))
            # ordering
            ts_i = hdr.index("timestamp_utc")
            with open(out_csv, newline="", encoding="utf-8") as fh:
                rd = csv.reader(fh); next(rd)
                ts = [row[ts_i] for _, row in zip(range(20000), rd)]
            check("CSV rows are in the requested order", ts == sorted(ts),
                  f"first {ts[:1]}")

        # ── cancel must leave NO partial file ────────────────────────────────
        out_cancel = os.path.join(tmp, "cancelled.csv")
        w2 = _JMExportWorker(table, shards, "1=1", [], order, out_cancel, "csv", total)
        r2 = run_worker(w2, cancel_after_ms=150)
        check("cancelled export reports cancellation",
              (not r2.get("ok")) and r2.get("msg") == "__cancelled__", str(r2))
        check("cancelled export leaves NO partial file on disk",
              not os.path.exists(out_cancel),
              "partial file still present" if os.path.exists(out_cancel) else "removed")

        # ── JSON export is valid JSON ────────────────────────────────────────
        out_json = os.path.join(tmp, "out.json")
        w3 = _JMExportWorker(table, shards, "event_id = 4624", [], order,
                             out_json, "json", total)
        r3 = run_worker(w3)
        check("JSON export completes", r3.get("ok"), str(r3.get("msg"))[:200])
        if r3.get("ok"):
            with open(out_json, encoding="utf-8") as fh:
                data = json.load(fh)          # raises if malformed
            expected = sum(1 for v in table["event_id"].to_pylist() if v == 4624)
            check("JSON is well-formed and filtered exactly",
                  len(data) == expected == r3["n"],
                  f"file={len(data)} worker={r3['n']} expected={expected}")

        # ── a failing export must not leave a file behind ────────────────────
        out_bad = os.path.join(tmp, "bad.csv")
        w4 = _JMExportWorker(table, shards, "this_column_does_not_exist = 1", [],
                             order, out_bad, "csv", total)
        r4 = run_worker(w4)
        check("invalid filter fails loudly rather than writing a bad file",
              (not r4.get("ok")) and r4.get("msg") != "__cancelled__", str(r4)[:160])
        check("failed export leaves no file", not os.path.exists(out_bad))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0

if __name__ == "__main__":
    sys.exit(main())
