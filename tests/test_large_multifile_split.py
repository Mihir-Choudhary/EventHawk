"""Multiple EVTX files >64 MB must all parse, completely and to the right file.

Juggernaut splits any file over 64 MB into per-worker shards (`_split_evtx`).
Two silent record-loss bugs lived there, and neither raised an error --
every write and every parse succeeded, the data was just wrong:

  Bug 1 -- 3968-byte truncation. Chunk 0 starts at the end of the 4096-byte
      header BLOCK, not the 128-byte header STRUCT. Seeking by 128 shifted
      every shard's data window and truncated its last chunk, silently
      dropping those records.

  Bug 2 -- shard-name collision. Shards were named `_hw_split_{i}_{pid}`,
      identical for every source file in a run (same index range, same PID).
      All splitting happens up front, before any worker reads, so file N's
      shards OVERWROTE file N-1's. Parsing several big files together showed
      only the LAST file's events, attributed to all the filenames.

Bug 2 is the one an analyst would never catch: the row counts look plausible
and the filenames look right; the evidence underneath belongs to another host.

No >64 MB file exists in the sample corpus, so fixtures are BUILT here by
replicating a real file's 64 KB chunks. Replication is byte-exact, which makes
ground truth exact too: records == original x reps.

Run: QT_QPA_PLATFORM=offscreen python tests/test_large_multifile_split.py [LOGS_DIR]
"""
import os, sys, glob, json, struct, binascii, tempfile, shutil, collections

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HDR_BLOCK, CHUNK = 4096, 65536
H_OLDEST, H_CURRENT, H_COUNT, H_CRC = 0x08, 0x10, 0x2A, 0x7C
MB = 1024 * 1024


def build_big(src_path: str, dst_path: str, reps: int) -> int:
    """Replicate src's chunks `reps` times into a valid EVTX. Returns chunk count."""
    with open(src_path, "rb") as f:
        raw = f.read()
    hdr, body = bytearray(raw[:HDR_BLOCK]), raw[HDR_BLOCK:]
    n_src = len(body) // CHUNK
    body = body[:n_src * CHUNK]
    total = n_src * reps
    struct.pack_into("<Q", hdr, H_OLDEST, 0)
    struct.pack_into("<Q", hdr, H_CURRENT, total - 1)
    struct.pack_into("<H", hdr, H_COUNT, total & 0xFFFF)
    struct.pack_into("<I", hdr, H_CRC, binascii.crc32(bytes(hdr[:120])) & 0xFFFFFFFF)
    with open(dst_path, "wb") as o:
        o.write(hdr)
        for _ in range(reps):
            o.write(body)
    return total


def main() -> int:
    import evtx as _evtx
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, _split_evtx
    import duckdb

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    # Four DIFFERENT channels: identical content would make a cross-file
    # collision invisible, which is the whole point of the test.
    plan = [("Security.evtx", 4), ("Application.evtx", 4),
            ("System.evtx", 4), ("Microsoft-Windows-Ntfs%4Operational.evtx", 3)]
    sources = [(os.path.join(LOGS, n), r) for n, r in plan
               if os.path.exists(os.path.join(LOGS, n))]
    if len(sources) < 2:
        print(f"need >=2 source logs under {LOGS} — skipping"); return 0

    work = tempfile.mkdtemp(prefix="bigsplit_")
    try:
        # ── ground truth from the ORIGINALS (cheap; replication is exact) ──
        truth = {}                       # big path -> {"n": int, "chans": Counter}
        big_files = []
        for src, reps in sources:
            chans = collections.Counter()
            n_src = 0
            for rec in _evtx.PyEvtxParser(src).records_json():
                n_src += 1
                try:
                    d = json.loads(rec["data"])
                    chans[(d.get("Event", {}).get("System", {}) or {}).get("Channel", "")] += 1
                except Exception:
                    chans[""] += 1
            big = os.path.join(work, "Big_" + os.path.basename(src))
            build_big(src, big, reps)
            truth[big] = {"n": n_src * reps,
                          "chans": collections.Counter({k: v * reps for k, v in chans.items()})}
            big_files.append(big)
            print(f"  {os.path.basename(big):34} {os.path.getsize(big)/MB:6.1f} MB  "
                  f"{n_src * reps:>8,} records expected")
        print()

        check("every fixture is over the 64 MB split threshold",
              all(os.path.getsize(p) > 64 * MB for p in big_files),
              ", ".join(f"{os.path.getsize(p)/MB:.0f}MB" for p in big_files))
        check("fixtures come from >=2 distinct channels (collision is detectable)",
              len({tuple(sorted(t["chans"])) for t in truth.values()}) > 1)

        # ── 1. shard names are unique per source file ─────────────────────
        sd = os.path.join(work, "shards"); os.makedirs(sd, exist_ok=True)
        made = {}
        for idx, p in enumerate(big_files):
            made[p] = _split_evtx(p, 8, sd, tag=str(idx))
        flat = [s for v in made.values() for s in v]
        check("splitting produced shards for every big file",
              all(len(v) > 1 for v in made.values()),
              {os.path.basename(k): len(v) for k, v in made.items()})
        check("no shard path is reused across source files (Bug 2 guard)",
              len(flat) == len(set(flat)),
              f"{len(flat)} shards, {len(set(flat))} unique -- a repeat means one "
              f"file's data overwrites another's")

        # ── 2. splitting loses no records (Bug 1 guard) ───────────────────
        for p in big_files[:2]:                      # 2 is enough; each is ~80 MB
            got = sum(sum(1 for _ in _evtx.PyEvtxParser(s).records_json())
                      for s in made[p])
            want = truth[p]["n"]
            check(f"8-way split of {os.path.basename(p)} loses no records",
                  got == want, f"{got:,} across shards vs {want:,} in the file")

        # ── 3. THE REPORTED SCENARIO: all the big files, one parse ────────
        outdir = os.path.join(work, "pq")
        pq = HeavyweightEngine(parquet_dir=outdir).run(big_files)
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        q = "[" + ", ".join(f"'{s}'" for s in shards) + "]"
        con = duckdb.connect()
        rows = con.execute(
            f"SELECT source_file, channel, COUNT(*) FROM parquet_scan({q}) "
            f"GROUP BY 1, 2").fetchall()
        con.close()

        got_n = collections.Counter()
        got_ch = collections.defaultdict(collections.Counter)
        for sf, ch, n in rows:
            got_n[sf] += n
            got_ch[sf][ch or ""] += n

        want_total = sum(t["n"] for t in truth.values())
        check("total rows equal the sum of all files (nothing lost)",
              sum(got_n.values()) == want_total,
              f"{sum(got_n.values()):,} parsed vs {want_total:,} expected")

        # Attribution is keyed on the full path the engine stores.
        norm = {}
        for sf, n in got_n.items():
            norm[os.path.realpath(sf)] = n
        per_ok, per_bad = 0, []
        for p, t in truth.items():
            g = norm.get(os.path.realpath(p), 0)
            if g == t["n"]:
                per_ok += 1
            else:
                per_bad.append(f"{os.path.basename(p)}: got {g:,} want {t['n']:,}")
        check("every file reports its OWN record count",
              per_ok == len(truth) and not per_bad,
              "; ".join(per_bad) or f"{per_ok}/{len(truth)} exact")

        # The decisive one: pre-fix, every file carried the LAST file's events.
        ch_bad = []
        for p, t in truth.items():
            key = next((k for k in got_ch if os.path.realpath(k) == os.path.realpath(p)), None)
            if key is None:
                ch_bad.append(f"{os.path.basename(p)}: absent from output"); continue
            if dict(got_ch[key]) != dict(t["chans"]):
                ch_bad.append(f"{os.path.basename(p)}: channels "
                              f"{dict(got_ch[key])} != {dict(t['chans'])}")
        check("every file's CHANNEL breakdown is its own (no cross-contamination)",
              not ch_bad, "; ".join(ch_bad[:2]))

        check("no source file collapsed or vanished",
              len(got_n) == len(truth),
              f"{len(got_n)} source_file value(s) for {len(truth)} input file(s)")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
