"""Every record is accounted for, and every loss is reported.

Two properties, checked against real logs and against deliberately damaged
files:

  ACCOUNTING -- for each source file the engine's own counters must balance:

      iterated == json_errors + extract_errors + filtered + rows

      and `rows` must equal what actually landed in Parquet. A record that
      falls out of the pipeline without incrementing a counter is evidence
      that vanished with nothing to show for it.

  REPORTING  -- a damaged file must not parse to "0 records, no complaint".
      Silence and success look identical to an analyst, so every damaged
      fixture must produce either a stats entry a human sees or a hard error.

Run: QT_QPA_PLATFORM=offscreen python tests/test_record_accounting.py [LOGS_DIR]
"""
import os, sys, glob, json, struct, binascii, tempfile, shutil

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HDR_BLOCK, CHUNK = 4096, 65536


def main() -> int:
    import evtx as _evtx
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    import duckdb

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:40]
    if not files:
        print(f"no logs under {LOGS} — skipping"); return 0

    work = tempfile.mkdtemp(prefix="acct_")
    try:
        # ══ A. accounting on real files ══════════════════════════════════
        eng = HeavyweightEngine(parquet_dir=os.path.join(work, "pq"))
        pq = eng.run(files)
        stats = dict(getattr(eng, "last_parse_stats", {}) or {})
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        q = "[" + ", ".join(f"'{s}'" for s in shards) + "]"
        con = duckdb.connect()
        pq_total = con.execute(f"SELECT COUNT(*) FROM parquet_scan({q})").fetchone()[0]
        con.close()

        real = {k: v for k, v in stats.items() if not k.startswith("__")}
        check("per-file stats were recorded for every input",
              len(real) == len(files), f"{len(real)} stats vs {len(files)} files")

        unbalanced = []
        for k, v in real.items():
            it = v.get("iterated", 0)
            acc = (v.get("json_errors", 0) + v.get("extract_errors", 0)
                   + v.get("filtered", 0) + v.get("rows", 0))
            if it != acc:
                unbalanced.append(f"{os.path.basename(k)}: iterated={it:,} "
                                  f"but json+extract+filtered+rows={acc:,}")
        check("counters balance for every file (no record falls out unaccounted)",
              not unbalanced, "\n      ".join(unbalanced[:3]) or f"{len(real)} file(s) balanced")

        sum_rows = sum(v.get("rows", 0) for v in real.values())
        check("rows reported equal rows actually written to Parquet",
              sum_rows == pq_total, f"stats say {sum_rows:,}, Parquet holds {pq_total:,}")

        # Independent ground truth: pyevtx-rs on a subset.
        gt_bad = []
        for p in files[:8]:
            want = sum(1 for _ in _evtx.PyEvtxParser(p).records_json())
            got = real.get(p, {}).get("iterated", -1)
            if want != got:
                gt_bad.append(f"{os.path.basename(p)}: iterated={got:,} vs pyevtx {want:,}")
        check("every record the parser yields is iterated (nothing skipped upstream)",
              not gt_bad, "\n      ".join(gt_bad[:3]) or "8 file(s) match pyevtx exactly")

        # ══ B. damaged inputs must be REPORTED, never silently empty ═════
        src = files[0]
        raw = open(src, "rb").read()
        n_src = (len(raw) - HDR_BLOCK) // CHUNK
        dmg = os.path.join(work, "damaged"); os.makedirs(dmg, exist_ok=True)

        # 1. truncated: header claims far more chunks than the file holds
        t = os.path.join(dmg, "truncated.evtx")
        hdr = bytearray(raw[:HDR_BLOCK])
        struct.pack_into("<H", hdr, 0x2A, (n_src + 500) & 0xFFFF)
        struct.pack_into("<I", hdr, 0x7C, binascii.crc32(bytes(hdr[:120])) & 0xFFFFFFFF)
        with open(t, "wb") as o:
            o.write(hdr); o.write(raw[HDR_BLOCK:])

        # 2. not an EVTX at all
        g = os.path.join(dmg, "garbage.evtx")
        open(g, "wb").write(b"NOTEVTX\x00" + os.urandom(200_000))

        # 3. zero bytes
        e = os.path.join(dmg, "empty.evtx")
        open(e, "wb").close()

        # 4. valid header, no chunk data at all
        h = os.path.join(dmg, "headeronly.evtx")
        open(h, "wb").write(raw[:HDR_BLOCK])

        fixtures = [("truncated", t), ("garbage", g), ("empty", e), ("header-only", h)]

        eng2 = HeavyweightEngine(parquet_dir=os.path.join(work, "pq2"))
        crashed = None
        try:
            eng2.run([p for _n, p in fixtures])
        except Exception as exc:
            crashed = f"{type(exc).__name__}: {exc}"
        check("a batch of damaged files does not crash the engine",
              crashed is None, crashed or "")

        st2 = dict(getattr(eng2, "last_parse_stats", {}) or {})

        def visible(v: dict) -> bool:
            """Would the integrity dialog print a line for this file?"""
            return bool(v.get("json_errors") or v.get("extract_errors")
                        or v.get("stream_error") or v.get("open_error")
                        or v.get("rows_lost_to_write_failure")
                        or v.get("missing_vs_expected") or v.get("truncation"))

        for name, p in fixtures:
            v = st2.get(p)
            if v is None:
                check(f"{name}: appears in parse stats at all", False,
                      "absent from stats — the file would vanish without trace")
                continue
            rows = v.get("rows", 0)
            # A file that yields nothing must say WHY. Producing rows is fine too.
            ok = rows > 0 or visible(v)
            check(f"{name}: either yields records or is reported as a problem",
                  ok, f"rows={rows} stats={ {k: v.get(k) for k in
                       ('stream_error','open_error','truncation','missing_vs_expected')
                       if v.get(k)} }")

        check("the truncated file is specifically flagged as truncated",
              bool((st2.get(t) or {}).get("truncation")),
              str((st2.get(t) or {}).get("truncation"))[:90])
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
