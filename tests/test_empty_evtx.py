"""GitHub issue #4 — an EVTX with no records must not be reported as damaged.

Windows pre-creates and initialises a chunk for every enabled channel, so a log
that has never been written still contains one chunk whose record-ID fields hold
0xFFFF_FFFF_FFFF_FFFF, the "no records here" sentinel.  read_chunk_index used to
accept that as a record-ID range because ``0 < first <= last`` is true for
2**64-1, so expected_record_count returned 1 for an empty file and every parse
containing one raised a modal "Parse Integrity Warning" claiming evidence was
missing.  On a real log directory that is the majority of files (988 of 1616 in
the reference corpus), and a modal dialog blocks the whole window.

Claiming evidence is missing when none is, is precisely the failure this
accounting exists to prevent, so these checks are about forensic truth as much
as about the dialog.
"""
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.core.chunk_salvage import (                       # noqa: E402
    read_chunk_index, expected_record_count,
)

# Spelled out here rather than imported: these are facts about the EVTX format,
# so the test must run unchanged against a build that predates the fix and fail
# on it, instead of failing to import.
_U64_SENTINEL = 0xFFFF_FFFF_FFFF_FFFF
_HDR_BLOCK = 4_096
_CHUNK_SIZE = 65_536
_CHUNK_MAGIC = b"ElfChnk\x00"

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def make_evtx(path, chunks):
    """Write a minimal EVTX whose chunk headers carry *chunks*.

    *chunks* is a list of (first_num, last_num, first_id, last_id) or None for
    an all-zero (slack) chunk.
    """
    hdr = bytearray(_HDR_BLOCK)
    hdr[0:8] = b"ElfFile\x00"
    struct.pack_into("<H", hdr, 0x2A, len(chunks))
    with open(path, "wb") as fh:
        fh.write(hdr)
        for c in chunks:
            blk = bytearray(_CHUNK_SIZE)
            if c is not None:
                blk[0:8] = _CHUNK_MAGIC
                struct.pack_into("<QQQQ", blk, 8, *c)
            fh.write(blk)
    return path


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="issue4_")
    S = _U64_SENTINEL

    print("=== 1. the empty-chunk sentinel is not a record range ===")
    p = make_evtx(os.path.join(tmp, "empty.evtx"), [(1, S, S, S)])
    idx = read_chunk_index(p)
    exp, dmg = expected_record_count(p)
    check("an empty chunk is not counted as a valid range",
          idx["valid"] == [], str(idx["valid"]))
    check("it is classified as slack, not damaged",
          len(idx["slack"]) == 1 and idx["damaged"] == [], str(idx))
    check("expected_record_count is 0, not 1", exp == 0, f"expected={exp}")
    check("no damaged chunks reported", dmg == 0, f"damaged={dmg}")

    print("\n=== 2. a half-written sentinel cannot claim ~1.8e19 records ===")
    # first_id real, last_id sentinel.  The old guard accepted this and the
    # range length would have been 2**64 - 5, i.e. an absurd missing count.
    p2 = make_evtx(os.path.join(tmp, "halfsentinel.evtx"), [(1, 1, 5, S)])
    exp2, _ = expected_record_count(p2)
    check("a sentinel in the last_id position yields 0, not 2**64",
          exp2 == 0, f"expected={exp2:,}")

    print("\n=== 3. real chunk ranges still count exactly ===")
    p3 = make_evtx(os.path.join(tmp, "real.evtx"),
                   [(1, 100, 1, 100), (101, 200, 101, 200)])
    exp3, _ = expected_record_count(p3)
    i3 = read_chunk_index(p3)
    check("two contiguous 100-record chunks expect 200",
          exp3 == 200, f"expected={exp3}")
    check("both chunks are valid", len(i3["valid"]) == 2, str(i3["valid"]))

    print("\n=== 4. genuinely damaged headers are still reported ===")
    p4 = make_evtx(os.path.join(tmp, "damaged.evtx"), [(1, 1, 100, 50)])
    i4 = read_chunk_index(p4)
    check("last_id < first_id is still damaged",
          i4["damaged"] == [0] and i4["valid"] == [], str(i4))
    p5 = make_evtx(os.path.join(tmp, "zeroid.evtx"), [(1, 1, 0, 0)])
    i5 = read_chunk_index(p5)
    check("a zero record id is still damaged",
          i5["damaged"] == [0], str(i5))

    print("\n=== 5. an all-zero chunk is slack, as before ===")
    p6 = make_evtx(os.path.join(tmp, "slack.evtx"), [None])
    i6 = read_chunk_index(p6)
    check("all-zero chunk is slack", i6["slack"] == [0] and i6["damaged"] == [],
          str(i6))

    print("\n=== 6. mixed file: empty chunk alongside real ones ===")
    p7 = make_evtx(os.path.join(tmp, "mixed.evtx"),
                   [(1, 50, 1, 50), (1, S, S, S), (51, 100, 51, 100)])
    exp7, dmg7 = expected_record_count(p7)
    check("the empty chunk adds nothing to the expected count",
          exp7 == 100, f"expected={exp7}")
    check("and is not counted as damage", dmg7 == 0, f"damaged={dmg7}")

    print("\n=== 7. real corpus, if present ===")
    LOGS = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    if os.path.isdir(LOGS):
        try:
            import evtx as _evtx
            import glob
            empties = [f for f in sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
                       if os.path.getsize(f) <= 69632][:3]
            bad = []
            for f in empties:
                n = sum(1 for _ in _evtx.PyEvtxParser(f).records_json())
                e, _ = expected_record_count(f)
                if n == 0 and e != 0:
                    bad.append(f"{os.path.basename(f)}: expected={e} actual=0")
            check(f"no false missing records on {len(empties)} real empty log(s)",
                  not bad, "; ".join(bad))
            big = [f for f in sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
                   if os.path.getsize(f) > 1_000_000][:2]
            bad2 = []
            for f in big:
                n = sum(1 for _ in _evtx.PyEvtxParser(f).records_json())
                e, _ = expected_record_count(f)
                if e != n:
                    bad2.append(f"{os.path.basename(f)}: expected={e} actual={n}")
            check(f"populated logs still account exactly ({len(big)} checked)",
                  not bad2, "; ".join(bad2))
        except Exception as exc:
            print(f"  (corpus check skipped: {type(exc).__name__}: {exc})")
    else:
        print(f"  (no corpus at {LOGS!r} — skipped)")

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*60}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
