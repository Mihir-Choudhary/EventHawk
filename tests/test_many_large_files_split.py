"""64+ files, every one over the 64 MB split threshold, in a single parse.

The shard-collision bug (fixed 2026-07-12) came from naming sub-files
`_hw_split_{i}_{pid}` — identical for every source file in a run, so file N's
shards overwrote file N-1's before any worker read them. The fix adds a
per-file tag. This is the stress case for that tag: 66 files split ~12 ways
each is ~800 shards live in one temp directory at once, since ALL splitting
happens up front in the task-build loop before any worker starts.

What could still go wrong at this scale, and is checked here:
  * two shards claiming the same path (the original bug, at 66x the pressure)
  * a file's events attributed to a different file
  * records dropped when the task count greatly exceeds the worker count
  * the temp directory or file-descriptor budget giving out

Content must be distinguishable per file or contamination is invisible, so the
fixtures cycle four different channels and vary their record counts.

Fixtures total several GB. They are built under --work (default a scratch dir
on the largest volume, NOT /tmp) and TMPDIR is pointed there too, because the
engine writes its shards to TMPDIR.

Run: QT_QPA_PLATFORM=offscreen python tests/test_many_large_files_split.py \\
         [LOGS_DIR] [N_FILES] [WORK_DIR]
"""
import os, sys, glob, json, struct, binascii, shutil, collections, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HDR_BLOCK, CHUNK = 4096, 65536
MB = 1024 * 1024
THRESHOLD_MB = 64


def build_big(src: str, dst: str, reps: int) -> None:
    with open(src, "rb") as f:
        raw = f.read()
    hdr, body = bytearray(raw[:HDR_BLOCK]), raw[HDR_BLOCK:]
    n = len(body) // CHUNK
    body = body[:n * CHUNK]
    tot = n * reps
    struct.pack_into("<Q", hdr, 0x08, 0)
    struct.pack_into("<Q", hdr, 0x10, tot - 1)
    struct.pack_into("<H", hdr, 0x2A, tot & 0xFFFF)
    struct.pack_into("<I", hdr, 0x7C, binascii.crc32(bytes(hdr[:120])) & 0xFFFFFFFF)
    with open(dst, "wb") as o:
        o.write(hdr)
        for _ in range(reps):
            o.write(body)


def main() -> int:
    import evtx as _evtx
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    import duckdb

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    N = int(sys.argv[2]) if len(sys.argv) > 2 else 66
    WORK_BASE = sys.argv[3] if len(sys.argv) > 3 else None

    names = ["Security.evtx", "Application.evtx", "System.evtx",
             "Microsoft-Windows-Ntfs%4Operational.evtx"]
    srcs = [os.path.join(LOGS, n) for n in names if os.path.exists(os.path.join(LOGS, n))]
    if not srcs:
        srcs = sorted(glob.glob(os.path.join(LOGS, "*.evtx")), key=os.path.getsize)[-4:]
    if not srcs:
        print(f"no logs under {LOGS} — skipping"); return 0

    if WORK_BASE is None:
        for cand in (os.environ.get("EVTX_TEST_WORKDIR", ""),
                     os.path.expanduser("~"), tempfile.gettempdir()):
            if not cand:
                continue
            try:
                st = os.statvfs(cand)
                if st.f_bavail * st.f_frsize > 40 * 1024 * MB:
                    WORK_BASE = cand; break
            except OSError:
                continue
        WORK_BASE = WORK_BASE or tempfile.gettempdir()

    # Fixtures are several GB and the splitter writes shards of the same total
    # size again, so budget ~2.5x. Skip loudly rather than fail on ENOSPC --
    # a disk-space failure here says nothing about the code under test.
    _need_gb = max(8, N * 0.22)
    try:
        _st = os.statvfs(WORK_BASE)
        _free_gb = _st.f_bavail * _st.f_frsize / (1024 ** 3)
    except OSError:
        _free_gb = 0.0
    if _free_gb < _need_gb:
        print(f"SKIP: {WORK_BASE} has {_free_gb:.1f} GB free, this needs about "
              f"{_need_gb:.0f} GB for {N} files plus their shards.\n"
              f"      Re-run with fewer files or another volume:\n"
              f"      python tests/test_many_large_files_split.py <LOGS> 16 /path/with/space")
        print("RESULT: 0/0 passed (skipped)")
        return 0

    work = tempfile.mkdtemp(prefix="manybig_", dir=WORK_BASE)
    # The engine writes shards to TMPDIR; keep them off a small /tmp.
    old_tmp = os.environ.get("TMPDIR")
    os.environ["TMPDIR"] = work
    tempfile.tempdir = work

    # multiprocessing also puts its pymp-* dir under TMPDIR and removes it in an
    # atexit finalizer.  Deleting `work` in a finally: block pulls that dir out
    # from under it and prints a FileNotFoundError traceback after a PASSING
    # run -- alarming and untrue.  atexit is LIFO and multiprocessing registers
    # its finalizer when the first process is created (later than this line),
    # so registering here means it cleans up first and this runs last.
    import atexit
    atexit.register(shutil.rmtree, work, ignore_errors=True)

    try:
        # ── ground truth per SOURCE (cheap: replication is byte-exact) ────
        base = {}
        for s in srcs:
            chans, n_rec = collections.Counter(), 0
            for rec in _evtx.PyEvtxParser(s).records_json():
                n_rec += 1
                try:
                    d = json.loads(rec["data"])
                    chans[(d.get("Event", {}).get("System", {}) or {}).get("Channel", "")] += 1
                except Exception:
                    chans[""] += 1
            base[s] = (n_rec, chans, os.path.getsize(s))

        truth, paths = {}, []
        for i in range(N):
            s = srcs[i % len(srcs)]
            n_rec, chans, sz = base[s]
            # smallest reps that clears the threshold, +1 every 3rd file so
            # counts differ between files sharing a channel
            reps = max(2, -(-(THRESHOLD_MB * MB + MB) // sz)) + (i % 3)
            d = os.path.join(work, f"host{i:03d}")
            os.makedirs(d, exist_ok=True)
            out = os.path.join(d, os.path.basename(s))
            build_big(s, out, reps)
            truth[out] = {"n": n_rec * reps,
                          "chans": collections.Counter({k: v * reps for k, v in chans.items()})}
            paths.append(out)

        total_mb = sum(os.path.getsize(p) for p in paths) / MB
        under = [p for p in paths if os.path.getsize(p) <= THRESHOLD_MB * MB]
        print(f"  {len(paths)} files, {total_mb/1024:.1f} GB total, "
              f"{min(os.path.getsize(p) for p in paths)/MB:.0f}–"
              f"{max(os.path.getsize(p) for p in paths)/MB:.0f} MB each\n")
        check(f"built {N} files and EVERY one exceeds the {THRESHOLD_MB} MB threshold",
              len(paths) == N and not under,
              f"{len(under)} file(s) under threshold would not be split at all")
        check("counts differ between files sharing a channel (contamination visible)",
              len({t["n"] for t in truth.values()}) >= len(srcs) * 2,
              f"{len({t['n'] for t in truth.values()})} distinct expected counts")

        # ── the real parse ────────────────────────────────────────────────
        eng = HeavyweightEngine(parquet_dir=os.path.join(work, "pq"))
        pq = eng.run(paths)
        stats = dict(getattr(eng, "last_parse_stats", {}) or {})
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        con = duckdb.connect()
        q = "[" + ", ".join(f"'{s}'" for s in shards) + "]"
        rows = con.execute(f"SELECT source_file, channel, COUNT(*) "
                           f"FROM parquet_scan({q}) GROUP BY 1,2").fetchall()
        con.close()

        got_n, got_ch = collections.Counter(), collections.defaultdict(collections.Counter)
        for sf, ch, n in rows:
            got_n[sf] += n
            got_ch[sf][ch or ""] += n

        want_total = sum(t["n"] for t in truth.values())
        check("every source file is present in the output",
              len(got_n) == N, f"{len(got_n)} of {N} source_file value(s)")
        check("total records match exactly (nothing lost across ~800 shards)",
              sum(got_n.values()) == want_total,
              f"{sum(got_n.values()):,} parsed vs {want_total:,} expected")

        bad = []
        for p, t in truth.items():
            key = next((k for k in got_n if os.path.realpath(k) == os.path.realpath(p)), None)
            if key is None:
                bad.append(f"{os.path.basename(os.path.dirname(p))}: missing")
            elif got_n[key] != t["n"]:
                bad.append(f"{os.path.basename(os.path.dirname(p))}: "
                           f"{got_n[key]:,} vs {t['n']:,}")
        check("every file reports its OWN record count",
              not bad, "; ".join(bad[:3]) or f"{N}/{N} exact")

        bad_ch = []
        for p, t in truth.items():
            key = next((k for k in got_ch if os.path.realpath(k) == os.path.realpath(p)), None)
            if key and dict(got_ch[key]) != dict(t["chans"]):
                bad_ch.append(os.path.basename(os.path.dirname(p)))
        check("no cross-contamination between any of the files",
              not bad_ch, f"{len(bad_ch)} contaminated: {bad_ch[:3]}")

        problems = [f"{os.path.basename(os.path.dirname(k))}: "
                    f"{ {x: v.get(x) for x in ('stream_error','open_error','missing_vs_expected') if v.get(x)} }"
                    for k, v in stats.items()
                    if not k.startswith("__")
                    and (v.get("stream_error") or v.get("open_error")
                         or v.get("missing_vs_expected"))]
        check("no file reported a parse problem",
              not problems, "; ".join(problems[:3]))

        unbalanced = [k for k, v in stats.items() if not k.startswith("__")
                      and v.get("iterated", 0) != (v.get("json_errors", 0)
                      + v.get("extract_errors", 0) + v.get("filtered", 0) + v.get("rows", 0))]
        check("per-file counters balance for all of them",
              not unbalanced, f"{len(unbalanced)} unbalanced")

        leftover = glob.glob(os.path.join(work, "**", "_hw_split_*.evtx"), recursive=True)
        check("all shard temp files were cleaned up",
              not leftover, f"{len(leftover)} shard(s) left behind")
    finally:
        if old_tmp is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old_tmp
        tempfile.tempdir = None
        # `work` is removed by the atexit hook above, after multiprocessing has
        # cleaned its own temp dir inside it.

    print("\n" + "=" * 60)
    bad_l = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad_l)}/{len(res)} passed")
    for n in bad_l:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad_l else 0


if __name__ == "__main__":
    sys.exit(main())
