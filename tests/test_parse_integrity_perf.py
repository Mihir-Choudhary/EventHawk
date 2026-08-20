"""Heavyweight parse: no record is lost by the process pool, and it is faster.

The parse stage requested cpu-1 workers and got the throughput of one, because
pyevtx-rs holds the GIL. It now runs on processes. This is the core parse path
of a forensic tool that has already had two silent record-loss bugs, so these
checks are COUNTS FIRST and speed second: every source file must yield exactly
the number of records the raw parser sees.

NOTE the __main__ guard: with the "spawn" start method a child re-imports
__main__, so an unguarded script re-runs itself in every worker.

Run: python tests/test_parse_integrity_perf.py [logs_dir] [file_limit]
"""
import os, sys, glob, json, time, shutil, tempfile, collections

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    import evtx
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table

    LOGS  = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"
    LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 else 0

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
    if LIMIT:
        files = files[:LIMIT]
    if not files:
        print("no logs — skipping")
        return 0

    # ── ground truth straight from the parser, per file ──────────────────
    truth = {}
    t0 = time.perf_counter()
    for f in files:
        n = 0
        try:
            for _ in evtx.PyEvtxParser(f).records_json():
                n += 1
        except Exception:
            n = -1                    # unreadable: engine may legitimately skip
        truth[f] = n
    truth_time = time.perf_counter() - t0
    readable = {f: n for f, n in truth.items() if n >= 0}
    print(f"{len(files)} files, ground truth {sum(readable.values()):,} records "
          f"(single-threaded reference parse {truth_time:.1f}s)")

    tmp = tempfile.mkdtemp(prefix="parse_integ_")
    try:
        eng = HeavyweightEngine(parquet_dir=tmp)
        t0 = time.perf_counter()
        pq = eng.run(files)
        wall = time.perf_counter() - t0
        table = load_arrow_table(pq)
        print(f"engine.run(): {wall:.1f}s for {len(table):,} rows "
              f"({len(table)/wall:,.0f} rows/s)")

        check("engine produced rows", len(table) > 0, f"{len(table):,}")
        check("TOTAL record count matches ground truth",
              len(table) == sum(readable.values()),
              f"engine {len(table):,} vs truth {sum(readable.values()):,}")

        got = collections.Counter(table["source_file"].to_pylist())
        missing = {f: (n, got.get(f, 0)) for f, n in readable.items()
                   if got.get(f, 0) != n}
        check("EVERY source file yields exactly its own record count",
              not missing,
              "\n      ".join(f"{os.path.basename(f)}: truth {a} got {b}"
                              for f, (a, b) in list(missing.items())[:8]))
        check("no rows attributed to a file that was not loaded",
              not (set(got) - set(files)), str(list(set(got) - set(files))[:3]))

        stats_path = os.path.join(pq, "parse_stats.json")
        if os.path.exists(stats_path):
            st = json.load(open(stats_path))
            rows_claimed = sum(v.get("rows", 0) for v in st.values())
            check("parse_stats rows agree with the Parquet contents",
                  rows_claimed == len(table), f"{rows_claimed:,} vs {len(table):,}")
            errs = {k: v for k, v in st.items()
                    if v.get("open_error") or v.get("stream_error")}
            check("no worker crashed or failed to open a readable file",
                  not errs, "; ".join(list(errs)[:3]))
            check("parse_stats covers every file", len(st) >= len(readable),
                  f"{len(st)} entries for {len(readable)} files")
        else:
            check("parse_stats.json written", False, "missing")

        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        check("all manifest shards exist",
              all(os.path.exists(p) for p in shards), f"{len(shards)} shards")

        print(f"\n      reference single-thread parse : {truth_time:6.1f}s")
        print(f"      full engine.run()             : {wall:6.1f}s")
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
