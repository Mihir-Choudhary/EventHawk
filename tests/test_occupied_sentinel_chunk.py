"""A sentinel chunk header over records that ARE there must not hide them.

tests/test_empty_evtx.py (issue #4) pins that a chunk whose record-ID fields
hold the 0xFFFF_FFFF_FFFF_FFFF "no records" sentinel -- in either field -- adds
nothing to the expected record count, so an empty log is never reported as
missing a record.  That stays exactly as it is.

What it did not ask is whether the chunk really IS empty.  The sentinel is a
claim in a header; the chunk's free-space offset says whether its record area
holds data.  When the two disagree (a damaged or edited header over real
records), classing the chunk as empty slack made salvage skip it: after the
primary parse aborted earlier in the file, every record in that chunk was
silently left out.  Now:

  * sentinel + empty record area  -> slack (unchanged, as issue #4 requires);
  * sentinel + occupied area      -> "unranged": still no range, so still no
    2**64-sized expected count, but salvage reads it;

and, through the real MainWindow in Normal and Juggernaut mode, a log whose
primary parse aborts before such a chunk still loads that chunk's records,
checked against an independent per-chunk parse of the unmodified file.

Run: QT_QPA_PLATFORM=offscreen python tests/test_occupied_sentinel_chunk.py
     (set EVTX_TEST_LOGS for the real-log parts)
"""
import glob
import os
import re
import shutil
import struct
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.core.chunk_salvage import (                       # noqa: E402
    read_chunk_index, expected_record_count, salvage_records_json, IdRuns,
)

S = 0xFFFF_FFFF_FFFF_FFFF
HDR, CHUNK = 4_096, 65_536

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def synth(path, chunks):
    """Chunks as (first_id, last_id, free_space_offset)."""
    hdr = bytearray(HDR)
    hdr[0:8] = b"ElfFile\x00"
    struct.pack_into("<H", hdr, 0x2A, len(chunks))
    with open(path, "wb") as fh:
        fh.write(hdr)
        for first, last, free in chunks:
            blk = bytearray(CHUNK)
            blk[0:8] = b"ElfChnk\x00"
            struct.pack_into("<QQQQ", blk, 8, 1, 1, first, last)
            struct.pack_into("<I", blk, 0x30, free)
            fh.write(blk)
    return path


def chunk_ids(src, ci):
    """Record IDs in chunk *ci* of *src*, parsed on their own (independent truth)."""
    import evtx
    with open(src, "rb") as fh:
        hdr = bytearray(fh.read(HDR))
        fh.seek(HDR + ci * CHUNK)
        chunk = fh.read(CHUNK)
    struct.pack_into("<Q", hdr, 0x08, 0)
    struct.pack_into("<Q", hdr, 0x10, 0)
    struct.pack_into("<H", hdr, 0x2A, 1)
    import zlib
    struct.pack_into("<I", hdr, 0x7C, zlib.crc32(bytes(hdr[:120])) & 0xFFFFFFFF)
    fd, one = tempfile.mkstemp(suffix=".evtx")
    os.close(fd)
    try:
        with open(one, "wb") as fh:
            fh.write(hdr)
            fh.write(chunk)
        p = evtx.PyEvtxParser(one)
        ids = sorted(r["event_record_id"] for r in p.records_json())
        del p
        return ids
    finally:
        os.unlink(one)


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="occ_sentinel_")
    try:
        print("=== 1. sentinel headers: empty vs occupied record area ===")
        for label, first, last in (("both fields", S, S), ("last field only", 5, S),
                                   ("first field only", S, 9)):
            p = synth(os.path.join(tmp, f"empty_{first}_{last}.evtx"), [(first, last, 0x200)])
            i = read_chunk_index(p)
            check(f"sentinel in {label}, empty record area -> slack",
                  i["slack"] == [0] and not i["valid"] and not i.get("unranged", []), str(i))
            p = synth(os.path.join(tmp, f"occ_{first}_{last}.evtx"), [(first, last, 0x9000)])
            i = read_chunk_index(p)
            e, _ = expected_record_count(p)
            check(f"sentinel in {label}, occupied record area -> unranged, not slack",
                  i.get("unranged", []) == [0] and not i["slack"] and not i["valid"], str(i))
            check(f"…and it adds nothing to the expected count ({label})",
                  e == 0, f"expected={e:,}")
        p = synth(os.path.join(tmp, "mixed.evtx"),
                  [(1, 50, 0x8000), (S, S, 0x9000), (51, 100, 0x8000)])
        e, _ = expected_record_count(p)
        check("real ranges beside an occupied sentinel chunk still count exactly",
              e == 100, f"expected={e}")

        LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
        logs = [f for f in sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
                if os.path.getsize(f) >= HDR + 8 * CHUNK]
        if not logs:
            print(f"\n  (no multi-chunk log under {LOGS!r} — real-log parts skipped)")
            return finish()
        src = min(logs, key=os.path.getsize)
        print(f"\n=== 2. real log {os.path.basename(src)} with one chunk header blanked ===")
        idx = read_chunk_index(src)
        ranged = [ci for ci, a, b in idx["valid"] if b - a >= 20]
        k, j = ranged[5], ranged[2]           # k: header blanked; j: record corrupted (j < k)
        truth_k = chunk_ids(src, k)
        check("independent parse finds records in the chunk to blank",
              len(truth_k) > 20, f"chunk {k}: {len(truth_k)} records")

        blanked = os.path.join(tmp, "Blanked.evtx")
        shutil.copyfile(src, blanked)
        d = bytearray(open(blanked, "rb").read())
        struct.pack_into("<QQ", d, HDR + k * CHUNK + 0x18, S, S)
        open(blanked, "wb").write(d)
        i = read_chunk_index(blanked)
        e_src, _ = expected_record_count(src)
        e_bl, _ = expected_record_count(blanked)
        check("the blanked chunk is unranged, not slack",
              k in i.get("unranged", []) and k not in i["slack"], f"chunk {k}")
        check("the expected count drops by that chunk, not to 2**64",
              e_bl == e_src - len(truth_k), f"{e_src:,} -> {e_bl:,} (chunk had {len(truth_k)})")

        others = IdRuns()
        for ci, a, b in idx["valid"]:
            if ci != k:
                for rid in range(a, b + 1):
                    others.add(rid)
        got = sorted(r["event_record_id"] for r in salvage_records_json(blanked, already_emitted=others))
        check("salvage reads the blanked chunk's records, exactly",
              got == truth_k, f"{len(got)} vs {len(truth_k)}")

        # primary parse aborts in chunk j (< k): salvage is the only way chunk k is read
        aborted = os.path.join(tmp, "AbortsBefore.evtx")
        d = bytearray(d)
        base = HDR + j * CHUNK
        sig = [m.start() for m in re.finditer(rb"\x2a\x2a\x00\x00", bytes(d[base + 0x200:base + CHUNK]))][4]
        d[base + 0x200 + sig: base + 0x200 + sig + 4] = b"XXXX"
        open(aborted, "wb").write(d)

        print("\n=== 2b. accounting: recovered records never hide missing ones ===")
        # The "missing records" warning compares the IDs the headers declare with
        # the IDs read.  Records recovered from a header-less (sentinel) chunk
        # have no declared range, so they must not offset IDs that ARE declared
        # and were lost (here: the records after the corrupt one in chunk j).
        import queue as _q
        import threading as _th
        from evtx_tool.core.engine import _worker_parse_file
        from evtx_tool.core.heavyweight.engine import _hw_worker_stream
        idx_a = read_chunk_index(aborted)
        declared = set()
        for _ci, a, b2 in idx_a["valid"]:
            declared.update(range(a, b2 + 1))
        res = _worker_parse_file({"filepath": aborted, "filter_config": {}})
        got_ids = [e["event_record_id"] for e in res["events"]]
        truth_missing = len(declared - set(got_ids))
        check("independent count: some declared records really are lost", truth_missing > 0,
              f"{truth_missing} declared IDs never read")
        check("Normal: missing_vs_expected equals the declared IDs never read",
              res.get("missing_vs_expected") == truth_missing,
              f"{res.get('missing_vs_expected')} vs {truth_missing}")
        check("Normal: the hidden chunk's records are still loaded", set(truth_k) <= set(got_ids))
        qq, stop = _q.Queue(), _th.Event()
        _hw_worker_stream({"filepath": aborted}, qq, stop)
        done = None
        while not qq.empty():
            m = qq.get()
            if m[0] == "DONE":
                done = m[2]
        check("Juggernaut: missing_vs_expected equals the declared IDs never read",
              done is not None and done.get("missing_vs_expected") == truth_missing,
              f"{(done or {}).get('missing_vs_expected')} vs {truth_missing}")

        # a sentinel header over a COPY of another chunk's records: no duplicates
        dup = os.path.join(tmp, "DupBody.evtx")
        m_ci = ranged[6]
        d3 = bytearray(open(aborted, "rb").read())
        d3[HDR + k * CHUNK: HDR + (k + 1) * CHUNK] = d3[HDR + m_ci * CHUNK: HDR + (m_ci + 1) * CHUNK]
        struct.pack_into("<QQ", d3, HDR + k * CHUNK + 0x18, S, S)
        open(dup, "wb").write(d3)
        r2 = _worker_parse_file({"filepath": dup, "filter_config": {}})
        ids2 = [e["event_record_id"] for e in r2["events"]]
        # The copy is physically in the file twice, and the reader returns both
        # copies when the primary pass reads through (no abort here, so no
        # salvage): showing both is faithful to the file, and dropping one would
        # hide a possible sign of tampering (Claude ruling R33).  What must hold:
        # no row beyond the records the file holds.
        from evtx import PyEvtxParser
        physical = sum(1 for _ in PyEvtxParser(dup).records_json())
        check("Normal: a hidden chunk holding another chunk's records adds no rows beyond the file's",
              len(ids2) == physical, f"{len(ids2)} rows vs {physical} records in the file "
              f"({len(ids2) - len(set(ids2))} physically duplicated)")

        print("\n=== 3. through the real window, both modes ===")
        from PySide6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance() or QApplication([])
        for n in ("warning", "critical", "information"):
            setattr(QMessageBox, n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
        from evtx_tool.gui.main_window import MainWindow
        # The integrity warning this file is built to trigger is a real modal
        # (_warn_blocking); offscreen nobody could dismiss it.
        MainWindow._warn_blocking = lambda self, *a, **k: None

        def pump(sec, until=None):
            end = time.time() + sec
            while time.time() < end:
                app.processEvents(); time.sleep(0.02)
                if until and until():
                    return True
            return False

        def record_ids_normal(path):
            w = MainWindow()
            w._add_path(path)
            w._on_parse_clicked()
            pump(240, lambda: w._active_proxy is not None and w._active_proxy.rowCount() > 0
                 and w._btn_parse.isEnabled())
            pump(2)
            ids = {e.get("record_id") for e in w._active_events}
            w.close(); pump(0.5)
            return ids

        def record_ids_jm(path):
            w = MainWindow()
            w._launch_juggernaut_mode([path])
            pump(300, lambda: w._hw_model is not None and w._hw_model.rowCount() > 0)
            pump(3)
            tbl = w._hw_model._full_table
            ids = set(tbl.column("record_id").to_pylist()) if tbl is not None else set()
            w.close(); pump(0.5)
            return ids

        for mode, fn in (("Normal", record_ids_normal), ("Juggernaut", record_ids_jm)):
            ids = fn(aborted)
            missing = [r for r in truth_k if r not in ids]
            check(f"{mode}: after an abort earlier in the file, the blanked chunk's "
                  f"records are loaded", not missing,
                  f"{len(truth_k) - len(missing)}/{len(truth_k)} loaded; {len(ids):,} rows total")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return finish()


def finish() -> int:
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
