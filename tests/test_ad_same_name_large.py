"""Several >100 MB files that are ALL named Security.evtx (the AD-server case).

Real scenario: Security.evtx pulled from every domain controller in a forest.
Every file has the SAME basename, the SAME channel and the SAME event types --
only the host and the contents differ, and each is well over 64 MB so every one
of them goes through the splitter.

This is strictly harder than test_large_multifile_split.py, which used four
DIFFERENT basenames from four DIFFERENT channels. Neither of those
discriminators exists here: if attribution broke, a channel comparison would
see "Security" on both sides and report success.

Two separate properties are checked, because they can fail independently:

  DATA      -- each file's events stay attributed to that file. The engine
               stores the FULL path, so DC01/Security.evtx and
               DC02/Security.evtx must never merge.
  DISPLAY   -- the analyst can TELL THEM APART in the UI. Correct data behind
               three tabs all labelled "Security.evtx" is still unusable: you
               cannot say which DC an event came from.

Fixtures are built by replicating a real EVTX's 64 KB chunks (byte-exact, so
ground truth is exact). Each "DC" is built from a different source channel:
identical content would make cross-contamination undetectable, which is the
whole reason this test exists.

Run: QT_QPA_PLATFORM=offscreen python tests/test_ad_same_name_large.py [LOGS_DIR]
"""
import os, sys, json, struct, binascii, tempfile, shutil, collections

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HDR_BLOCK, CHUNK = 4096, 65536
H_OLDEST, H_CURRENT, H_COUNT, H_CRC = 0x08, 0x10, 0x2A, 0x7C
MB = 1024 * 1024


def build_big(src_path: str, dst_path: str, reps: int) -> None:
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


def main() -> int:
    import evtx as _evtx
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    import duckdb

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    # Different source channels, but every output file is named Security.evtx.
    plan = [("DC01", "Security.evtx", 6), ("DC02", "Application.evtx", 6),
            ("DC03", "System.evtx", 6)]
    avail = [(d, os.path.join(LOGS, s), r) for d, s, r in plan
             if os.path.exists(os.path.join(LOGS, s))]
    if len(avail) < 2:
        print(f"need >=2 source logs under {LOGS} — skipping"); return 0

    work = tempfile.mkdtemp(prefix="ad_same_")
    try:
        truth = {}
        paths = []
        for dc, src, reps in avail:
            chans, n_src = collections.Counter(), 0
            for rec in _evtx.PyEvtxParser(src).records_json():
                n_src += 1
                try:
                    d = json.loads(rec["data"])
                    chans[(d.get("Event", {}).get("System", {}) or {}).get("Channel", "")] += 1
                except Exception:
                    chans[""] += 1
            d_dir = os.path.join(work, dc); os.makedirs(d_dir, exist_ok=True)
            # EVERY file is called Security.evtx — that is the point.
            out = os.path.join(d_dir, "Security.evtx")
            build_big(src, out, reps)
            truth[out] = {"n": n_src * reps,
                          "chans": collections.Counter({k: v * reps for k, v in chans.items()})}
            paths.append(out)
            print(f"  {dc}/Security.evtx  {os.path.getsize(out)/MB:6.1f} MB  "
                  f"{n_src*reps:>8,} records  (from {os.path.basename(src)})")
        print()

        check("every file is over 64 MB (all go through the splitter)",
              all(os.path.getsize(p) > 64 * MB for p in paths),
              ", ".join(f"{os.path.getsize(p)/MB:.0f}MB" for p in paths))
        check("every file has the identical basename",
              len({os.path.basename(p) for p in paths}) == 1,
              str({os.path.basename(p) for p in paths}))

        # ── DATA ─────────────────────────────────────────────────────────
        pq = HeavyweightEngine(parquet_dir=os.path.join(work, "pq")).run(paths)
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        q = "[" + ", ".join(f"'{s}'" for s in shards) + "]"
        con = duckdb.connect()
        rows = con.execute(f"SELECT source_file, channel, COUNT(*) "
                           f"FROM parquet_scan({q}) GROUP BY 1,2").fetchall()
        con.close()

        got_n, got_ch = collections.Counter(), collections.defaultdict(collections.Counter)
        for sf, ch, n in rows:
            got_n[sf] += n
            got_ch[sf][ch or ""] += n

        want_total = sum(t["n"] for t in truth.values())
        check("total rows equal the sum of all files (nothing lost)",
              sum(got_n.values()) == want_total,
              f"{sum(got_n.values()):,} vs {want_total:,}")
        check("same-named files did NOT collapse into one identity",
              len(got_n) == len(truth),
              f"{len(got_n)} distinct source_file value(s) for {len(truth)} input files")

        bad = []
        for p, t in truth.items():
            key = next((k for k in got_n if os.path.realpath(k) == os.path.realpath(p)), None)
            if key is None:
                bad.append(f"{p}: absent"); continue
            if got_n[key] != t["n"]:
                bad.append(f"{os.path.basename(os.path.dirname(p))}: {got_n[key]:,} vs {t['n']:,}")
        check("each DC's file reports its OWN record count",
              not bad, "; ".join(bad) or f"{len(truth)}/{len(truth)} exact")

        bad_ch = []
        for p, t in truth.items():
            key = next((k for k in got_ch if os.path.realpath(k) == os.path.realpath(p)), None)
            if key and dict(got_ch[key]) != dict(t["chans"]):
                bad_ch.append(f"{os.path.basename(os.path.dirname(p))}: "
                              f"{dict(got_ch[key])} != {dict(t['chans'])}")
        check("no cross-contamination between same-named files",
              not bad_ch, "; ".join(bad_ch[:2]))

        check("source_file keeps the full path, not the basename",
              all(os.sep in k and k.strip(os.sep) != "Security.evtx" for k in got_n),
              str(list(got_n)[:1]))

        # ── DISPLAY ──────────────────────────────────────────────────────
        # Correct data the analyst cannot attribute is not usable evidence.
        # Through the REAL MainWindow method the tabs call, not the helper
        # directly -- calling the helper proves only that the helper works, and
        # would still pass if the tab sites never used it.
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance() or QApplication([])
        from evtx_tool.gui.main_window import MainWindow
        win = MainWindow()
        try:
            win._last_parsed_files = list(paths)
            labels = {p: win._tab_label_for(p) for p in paths}
        finally:
            win.close()
            app.processEvents()
        vals = [labels[p] for p in paths]
        check("per-file tab labels are unique for same-named files",
              len(set(vals)) == len(paths),
              f"labels={vals} — identical labels leave the analyst unable to "
              f"tell which DC a tab belongs to")
        check("each label still identifies its own host directory",
              all(os.path.basename(os.path.dirname(p)) in labels[p] for p in paths),
              str(vals))
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
