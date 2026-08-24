"""A damaged chunk must cost you that chunk — not the file, and not the shard.

pyevtx-rs aborts the whole parse on a bad chunk header: one corrupted 64 KB
chunk in a 100 MB Security.evtx makes ALL 193,435 records unreachable through
a plain parse. Two mechanisms claw that back:

  splitting        -- a >64 MB file is cut into shards, so an abort kills only
                      the shard holding the bad chunk (~1/8 of the file);
  chunk salvage    -- each chunk is isolated into its own single-chunk file and
                      parsed alone, so only the genuinely broken chunk is lost.

Salvage used to be gated OFF for shards, on the reasoning that splitting
already isolates damage. Measured, that left 8% of the file on the floor:

    plain pyevtx            0 records   (aborts outright)
    split, no salvage     177,983       15,452 lost  (8.0%)
    split + salvage       193,342           93 lost  (0.05%)

The 93 are the records inside the destroyed chunk. Everything else is intact
evidence that was being discarded.

Run: QT_QPA_PLATFORM=offscreen python tests/test_corrupt_chunk_recovery.py [LOGS_DIR]
"""
import os, sys, glob, json, struct, binascii, tempfile, shutil

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HDR_BLOCK, CHUNK = 4096, 65536


def build_big(src: str, dst: str, reps: int) -> int:
    raw = open(src, "rb").read()
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
    return tot


def main() -> int:
    import evtx as _evtx
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    import duckdb

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    src = os.path.join(LOGS, "Application.evtx")
    if not os.path.exists(src):
        cand = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
        if not cand:
            print(f"no logs under {LOGS} — skipping"); return 0
        src = cand[0]

    work = tempfile.mkdtemp(prefix="corrupt_")
    try:
        big = os.path.join(work, "BigSecurity.evtx")
        tot = build_big(src, big, 5)
        intact = sum(1 for _ in _evtx.PyEvtxParser(big).records_json())
        size_mb = os.path.getsize(big) / 1048576
        print(f"  {size_mb:.0f} MB, {tot} chunks, {intact:,} records intact\n")
        check("fixture is over the 64 MB split threshold", size_mb > 64,
              f"{size_mb:.0f} MB")

        # Corrupt one chunk early in shard 3 of 8 -> maximises what that shard loses.
        bad = int(tot * 3 / 8) + 2
        with open(big, "r+b") as f:
            f.seek(HDR_BLOCK + bad * CHUNK)
            f.write(b"XXXXXXXX")            # destroy the ElfChnk magic

        plain_aborts = False
        try:
            plain = sum(1 for _ in _evtx.PyEvtxParser(big).records_json())
        except Exception:
            plain, plain_aborts = 0, True
        check("a plain parse cannot read this file at all (test is meaningful)",
              plain_aborts or plain < intact * 0.5,
              f"plain pyevtx yields {plain:,} of {intact:,}"
              + (" — aborts outright" if plain_aborts else ""))

        eng = HeavyweightEngine(parquet_dir=os.path.join(work, "pq"))
        pq = eng.run([big])
        st = (getattr(eng, "last_parse_stats", {}) or {}).get(big, {})
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        con = duckdb.connect()
        got = con.execute("SELECT COUNT(*) FROM parquet_scan([" +
                          ", ".join(f"'{s}'" for s in shards) + "])").fetchone()[0] if shards else 0
        con.close()

        lost = intact - got
        pct = 100.0 * lost / intact if intact else 0.0
        check("the engine recovers far more than a plain parse",
              got > plain, f"engine {got:,} vs plain {plain:,}")
        check("chunk salvage actually ran on the split shard",
              st.get("salvaged", 0) > 0,
              f"salvaged={st.get('salvaged', 0):,} — 0 means salvage was skipped "
              f"for the shard and a whole shard was thrown away")
        check("at least 99% of intact records are recovered",
              pct <= 1.0, f"{got:,} of {intact:,} recovered, {lost:,} lost ({pct:.2f}%)")
        check("loss is confined to roughly one chunk, not one shard",
              lost < (intact / tot) * 5,
              f"{lost:,} lost; one chunk holds about {intact // tot:,} records")

        # Recovery must never be silent, and never invent records.
        check("the damage is still reported, not hidden by a good recovery",
              bool(st.get("stream_error")) or bool(st.get("missing_vs_expected")),
              f"stream_error={str(st.get('stream_error'))[:60]!r}")
        check("salvage does not duplicate records",
              got <= intact, f"{got:,} recovered vs {intact:,} intact — "
                             f"more than intact would mean double-counted evidence")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 60)
    bad_l = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad_l)}/{len(res)} passed")
    for n in bad_l:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad_l else 0


if __name__ == "__main__":
    sys.exit(main())
