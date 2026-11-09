"""
chunk_salvage — chunk-isolated EVTX recovery and record accounting.

Why this exists
---------------
pyevtx-rs (the Python binding over the omerbenamram/evtx Rust crate) ABORTS the
entire record iterator when it hits a corrupt chunk: one bad chunk mid-file
loses every record after it, even though later chunks are pristine.  Native
Rust callers (e.g. Chainsaw with --skip-errors) and other forensic parsers
(EvtxECmd, libevtx) are chunk-isolated: a bad chunk costs only that chunk.

EVTX chunks are fully self-contained — each 64 KiB chunk carries its own
string and template tables — so any chunk can be parsed in isolation by
wrapping it in a minimal single-chunk EVTX file (4096-byte header + chunk).
This module does exactly that, using the same fast Rust parser:

  * ``read_chunk_index``      — per-chunk header info (first/last record IDs),
                                 distinguishing zeroed SLACK chunks (normal in
                                 pre-allocated logs) from DAMAGED chunks.
  * ``expected_record_count`` — sum of per-chunk declared record ranges: the
                                 number of records the file itself says it
                                 holds.  Validated exact on real dirty logs.
                                 Lets callers detect records that a parser
                                 silently skipped (iterated < expected).
  * ``salvage_records_json``  — generator yielding records chunk-by-chunk,
                                 skipping chunks that individually fail and
                                 (optionally) chunks already fully consumed by
                                 a primary parse pass.

  * ``IdRuns``                — O(runs) memory tracker of emitted record IDs,
                                 so a salvage pass never duplicates rows the
                                 primary pass already produced.

The active (currently-written) chunk of a live dirty log may have a STALE-LOW
header record range; ``expected_record_count`` can therefore only ever
under-count on healthy files, so ``iterated < expected`` is a safe one-sided
integrity test (no false positives on routine dirty logs).
"""

from __future__ import annotations

import logging
import os
import struct
import tempfile
import zlib
from bisect import bisect_right
from typing import Generator, Iterable

logger = logging.getLogger(__name__)

_HDR_BLOCK   = 4_096
_CHUNK_SIZE  = 65_536
_CHUNK_MAGIC = b"ElfChnk\x00"
# 0xFFFF_FFFF_FFFF_FFFF in a chunk's record-ID fields means "this chunk holds no
# records", not a record ID.  Record IDs start at 1 and increment by one, so the
# value is unreachable by a real log.
_U64_SENTINEL = 0xFFFF_FFFF_FFFF_FFFF
# Records start here in a chunk; a free-space offset at (or before) this point
# means the chunk's record area is empty.
_CHUNK_DATA_START = 0x200
_FILE_MAGIC  = b"ElfFile\x00"


class IdRuns:
    """Compact tracker of a mostly-increasing sequence of record IDs.

    Records arrive in near-monotonic runs (per physical chunk order, including
    the single wrap point of circular logs), so the interval list stays tiny —
    O(1) memory for healthy files instead of a per-ID set (which would cost
    ~1 GB for a 20M-record Security.evtx).
    """

    __slots__ = ("_runs", "_sorted")

    def __init__(self) -> None:
        self._runs: list[list[int]] = []   # [[start, end], ...] in append order
        self._sorted: list[tuple[int, int]] | None = None

    def add(self, rid: int) -> None:
        runs = self._runs
        if runs and rid == runs[-1][1] + 1:
            runs[-1][1] = rid
        elif runs and runs[-1][0] <= rid <= runs[-1][1]:
            pass                            # duplicate within current run
        else:
            runs.append([rid, rid])
        self._sorted = None

    def _ensure_sorted(self) -> list[tuple[int, int]]:
        if self._sorted is None:
            merged: list[list[int]] = []
            for a, b in sorted((r[0], r[1]) for r in self._runs):
                if merged and a <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], b)
                else:
                    merged.append([a, b])
            self._sorted = [(a, b) for a, b in merged]
        return self._sorted

    def contains(self, rid: int) -> bool:
        s = self._ensure_sorted()
        i = bisect_right(s, (rid, float("inf"))) - 1
        return i >= 0 and s[i][0] <= rid <= s[i][1]

    def covers_range(self, lo: int, hi: int) -> bool:
        """True if every ID in [lo, hi] is already tracked."""
        s = self._ensure_sorted()
        i = bisect_right(s, (lo, float("inf"))) - 1
        return i >= 0 and s[i][0] <= lo and hi <= s[i][1]

    def total(self) -> int:
        return sum(b - a + 1 for a, b in self._ensure_sorted())

    def count_within(self, ranges: "list[tuple[int, int]]") -> int:
        """How many tracked IDs fall inside *ranges* (sorted, merged intervals)."""
        s = self._ensure_sorted()
        n = i = j = 0
        while i < len(s) and j < len(ranges):
            lo = max(s[i][0], ranges[j][0])
            hi = min(s[i][1], ranges[j][1])
            if lo <= hi:
                n += hi - lo + 1
            if s[i][1] < ranges[j][1]:
                i += 1
            else:
                j += 1
        return n


def read_chunk_index(filepath: str) -> dict:
    """Scan all chunk headers.  Returns::

        {
          "valid":   [(chunk_idx, first_id, last_id), ...],
          "slack":   [chunk_idx, ...],   # holds no records — normal, not a fault.
                                         # Either an all-zero header (unused
                                         # pre-allocation) or an initialised
                                         # chunk whose record-ID fields are the
                                         # 0xFFFF_FFFF_FFFF_FFFF "empty" sentinel,
                                         # which is how an enabled-but-never-written
                                         # channel looks on disk.
          "damaged": [chunk_idx, ...],   # non-zero garbage where a chunk should be
          "unranged": [chunk_idx, ...],  # sentinel record-ID header over a record
                                         # area that is NOT empty: no usable
                                         # range, but it may hold records
        }

    A sentinel header is only taken at its word ("no records") when the
    chunk's free-space offset agrees that the record area is empty.  When the
    record area is occupied the header and the body disagree -- a damaged or
    edited header -- and the chunk goes to "unranged": it adds nothing to the
    expected count (it has no range, so no 2**64-sized total can come from it),
    but salvage still parses it, so its records are not hidden.

    Never raises; on I/O failure returns empty lists.
    """
    out = {"valid": [], "slack": [], "damaged": [], "unranged": []}
    try:
        size = os.path.getsize(filepath)
        n = max(0, (size - _HDR_BLOCK) // _CHUNK_SIZE)
        with open(filepath, "rb") as fh:
            for i in range(n):
                fh.seek(_HDR_BLOCK + i * _CHUNK_SIZE)
                h = fh.read(0x34)
                if len(h) < 0x34:
                    break
                if h[:8] == _CHUNK_MAGIC:
                    _fn, _ln, first_id, last_id = struct.unpack_from("<QQQQ", h, 8)
                    if first_id == _U64_SENTINEL or last_id == _U64_SENTINEL:
                        # A chunk that holds NO records writes 0xFFFF_FFFF_FFFF_FFFF
                        # in its record-ID fields.  Windows pre-creates and
                        # initialises a chunk for every enabled channel, so this is
                        # the normal state of any log that has never been written to
                        # — not damage, and not a record range.
                        #
                        # Both positions must be rejected, not just a sentinel pair:
                        #   • both sentinel  → the old 0 < first <= last test passed
                        #     and counted ONE phantom record, so every empty EVTX
                        #     reported "1 record declared in chunk headers was not
                        #     parsed" and raised a Parse Integrity Warning.
                        #   • last only      → the range would span from a real
                        #     first_id to 2**64-1, i.e. ~1.8e19 "expected" records.
                        # Claiming evidence is missing when none is, is exactly the
                        # failure this accounting exists to prevent.
                        #
                        # The free-space offset decides which: an empty record
                        # area confirms the sentinel; an occupied one means the
                        # header cannot be trusted, and the chunk must still be
                        # read rather than skipped as empty.
                        free_off = struct.unpack_from("<I", h, 0x30)[0]
                        if free_off > _CHUNK_DATA_START:
                            out["unranged"].append(i)
                        else:
                            out["slack"].append(i)
                    elif 0 < first_id <= last_id:
                        out["valid"].append((i, first_id, last_id))
                    else:
                        out["damaged"].append(i)
                elif not any(h):
                    out["slack"].append(i)
                else:
                    out["damaged"].append(i)
    except OSError as exc:
        logger.debug("read_chunk_index(%s) failed: %s", filepath, exc)
    return out


def expected_record_count(filepath: str) -> tuple[int, int]:
    """(expected_records, damaged_chunk_count) from chunk-header accounting.

    ``expected_records`` is the count of DISTINCT record IDs implied by the
    valid chunk ranges.  Real EVTX chunks hold disjoint, monotonically
    increasing ID ranges (a circular log has exactly one wrap), so the ranges
    are merged as intervals rather than naively summed — this makes the count
    robust against overlapping/duplicated ranges that can appear in carved
    fragments or deliberately manipulated files (naive summation would
    massively over-count and produce false "missing record" findings).

    Because a live log's active chunk header can only be stale-LOW, comparing
    ``iterated`` against this value is a one-sided test: ``iterated < expected``
    reliably indicates records physically present were not parsed.
    """
    idx = read_chunk_index(filepath)
    merged = _merge_ranges(first_last for _, *first_last in idx["valid"])
    return sum(hi - lo + 1 for lo, hi in merged), len(idx["damaged"])


def _merge_ranges(pairs) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for lo, hi in sorted(tuple(p) for p in pairs):
        if out and lo <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], hi)          # overlap/adjacent — merge
        else:
            out.append([lo, hi])
    return [(lo, hi) for lo, hi in out]


def expected_ranges(filepath: str) -> list[tuple[int, int]]:
    """The merged record-ID ranges the valid chunk headers declare.

    The expected-vs-read comparison must count only IDs read INSIDE these
    ranges: records with no declared range (e.g. salvaged from a chunk whose
    header carries the sentinel) cannot stand in for declared records that
    were lost.
    """
    return _merge_ranges(first_last for _, *first_last in read_chunk_index(filepath)["valid"])


def _build_single_chunk_file(hdr: bytes, chunk: bytes, out_path: str) -> None:
    """Write a minimal valid one-chunk EVTX file for isolated parsing."""
    h = bytearray(hdr[:_HDR_BLOCK].ljust(_HDR_BLOCK, b"\x00"))
    struct.pack_into("<Q", h, 0x08, 0)        # oldest chunk number
    struct.pack_into("<Q", h, 0x10, 0)        # current chunk number
    struct.pack_into("<H", h, 0x2A, 1)        # chunk count = 1
    struct.pack_into("<I", h, 0x7C, zlib.crc32(bytes(h[:120])) & 0xFFFFFFFF)
    with open(out_path, "wb") as fh:
        fh.write(h)
        fh.write(chunk)


def salvage_records_json(
    filepath: str,
    already_emitted: "IdRuns | None" = None,
    chunk_indices: "Iterable[int] | None" = None,
) -> Generator[dict, None, dict]:
    """Yield records chunk-by-chunk with per-chunk failure isolation.

    Yields the same dict shape as ``PyEvtxParser.records_json()``:
    ``{"event_record_id", "timestamp", "data"}``.

    * Chunks whose entire declared ID range is covered by *already_emitted*
      are skipped WITHOUT parsing (fast path — a primary pass that aborted at
      chunk K skips chunks 0..K-1 instantly).
    * Records individually present in *already_emitted* are suppressed, so a
      caller can safely merge salvage output after a partial primary pass.
    * Chunks that fail to parse in isolation are counted, not fatal.

    The generator's ``return`` value (via StopIteration.value, or use
    ``yield from``) is a stats dict::

        {"salvaged": int, "chunks_parsed": int, "chunks_skipped": int,
         "chunks_unrecoverable": int, "damaged_chunk_headers": int,
         "unranged_chunks": int}
    """
    from evtx import PyEvtxParser  # type: ignore[import]

    stats = {"salvaged": 0, "chunks_parsed": 0, "chunks_skipped": 0,
             "chunks_unrecoverable": 0, "damaged_chunk_headers": 0,
             "unranged_chunks": 0}

    idx = read_chunk_index(filepath)
    stats["damaged_chunk_headers"] = len(idx["damaged"])
    wanted = set(chunk_indices) if chunk_indices is not None else None
    # "unranged" chunks have no declared range, so the covers-range fast path
    # cannot skip them; per-record de-duplication below still applies.  Read
    # in file order.  A header that says "no records" over an occupied record
    # area looks edited or damaged: an examiner should be able to see that.
    to_read = sorted(list(idx["valid"]) + [(ci, None, None) for ci in idx["unranged"]])
    stats["unranged_chunks"] = len(idx["unranged"])
    if idx["unranged"]:
        logger.warning("%s: %d chunk header(s) declare no records over an occupied record "
                       "area (chunk %s) -- possibly edited or damaged; read anyway",
                       os.path.basename(filepath), len(idx["unranged"]),
                       ", ".join(str(c) for c in idx["unranged"]))
    yielded = IdRuns()       # never yield one record ID twice (e.g. a copied chunk body)

    try:
        with open(filepath, "rb") as fh:
            hdr = fh.read(_HDR_BLOCK)
            for ci, first_id, last_id in to_read:
                if wanted is not None and ci not in wanted:
                    continue
                if (already_emitted is not None and first_id is not None
                        and already_emitted.covers_range(first_id, last_id)):
                    stats["chunks_skipped"] += 1
                    continue

                fh.seek(_HDR_BLOCK + ci * _CHUNK_SIZE)
                chunk = fh.read(_CHUNK_SIZE)
                if len(chunk) < _CHUNK_SIZE:
                    stats["chunks_unrecoverable"] += 1
                    continue

                tmp = tempfile.NamedTemporaryFile(
                    suffix=".evtx", prefix="_salvage_", delete=False
                )
                tmp_path = tmp.name
                try:
                    tmp.close()
                    _build_single_chunk_file(hdr, chunk, tmp_path)
                    parser = PyEvtxParser(tmp_path)
                    try:
                        for rec in parser.records_json():
                            rid = rec["event_record_id"]
                            if ((already_emitted is not None and already_emitted.contains(rid))
                                    or yielded.contains(rid)):
                                continue
                            yielded.add(rid)
                            stats["salvaged"] += 1
                            yield rec
                    finally:
                        del parser   # release Rust file handle before unlink
                    stats["chunks_parsed"] += 1
                except Exception as exc:
                    stats["chunks_unrecoverable"] += 1
                    logger.info("Salvage: chunk %d of %s unrecoverable: %s",
                                ci, os.path.basename(filepath), exc)
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
    except OSError as exc:
        logger.warning("Salvage of %s failed at file level: %s", filepath, exc)

    return stats
