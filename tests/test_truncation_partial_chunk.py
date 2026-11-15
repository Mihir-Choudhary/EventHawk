"""A log that ends in a cut-off chunk is reported as truncated, with what it loses.

Gemini audit 1-06 (Medium): check_evtx_truncation compared only the header's
chunk count with the number of WHOLE chunks in the file.  A file whose last
chunk is cut short (size - 4096 not a multiple of 65536) passed as intact,
and so did a file shorter than its 4096-byte header block.  The corpus has
such a log: 1.7 GB, last chunk 61,440 of 65,536 bytes, declaring 57 records
that no parser reads -- and nothing said so.

Expected:
- every corpus log whose size is not header + whole chunks is warned about,
  and the warning gives the record IDs the cut chunk declares (read here
  straight from that chunk's header);
- no other corpus log gets a new warning (only those whose header declares
  more chunks than present, as before);
- a synthetic file shorter than 4096 bytes is warned about.
Real logs read in place (needs EVTX_TEST_LOGS / EVTX_TEST_LOGS_ONLINE).
"""
import glob
import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    roots = [os.environ.get(v) for v in ("EVTX_TEST_LOGS", "EVTX_TEST_LOGS_ONLINE")]
    roots = [r for r in roots if r and os.path.isdir(r)]
    if not roots:
        print("SKIP: corpus not set")
        return 0
    from evtx_tool.core.parser import check_evtx_truncation
    files = [f for r in roots for f in glob.glob(os.path.join(r, "**", "*.evtx"), recursive=True)]
    partial, header_short, other_warned = [], [], []
    for f in files:
        sz = os.path.getsize(f)
        w = check_evtx_truncation(f)
        with open(f, "rb") as fh:
            hdr = fh.read(4096)
        hdr_chunks = struct.unpack_from("<H", hdr, 0x2A)[0] if len(hdr) >= 44 else 0
        if sz >= 4096 and (sz - 4096) % 65536:
            with open(f, "rb") as fh:
                fh.seek(4096 + ((sz - 4096) // 65536) * 65536)
                ch = fh.read(0x34)
            ids = struct.unpack_from("<QQ", ch, 24) if len(ch) >= 0x28 and ch[:8] == b"ElfChnk\x00" else None
            partial.append((w, ids))
        elif hdr_chunks > max(0, (sz - 4096) // 65536):
            header_short.append(w)
        elif w:
            other_warned.append(w)
    print(f"{len(files)} logs; {len(partial)} end in a partial chunk; {len(header_short)} header-declares-more")
    check("every log ending in a partial chunk is warned about", partial and all(w for w, _ in partial),
          str([w for w, _ in partial])[:300])
    check("the warning names the record IDs the cut chunk declares",
          partial and all(ids is None or (f"{ids[0]:,}" in (w or "") and f"{ids[1]:,}" in (w or ""))
                          for w, ids in partial), str(partial)[:300])
    check("header-declares-more logs are still warned about", all(header_short), str(len(header_short)))
    check("no other log gets a warning", not other_warned, str(other_warned[:2]))
    tiny = os.path.join(tempfile.mkdtemp(prefix="trunc_"), "short.evtx")
    with open(tiny, "wb") as fh:
        fh.write(b"ElfFile\x00".ljust(512, b"\x00"))
    check("a file shorter than its 4096-byte header is warned about", bool(check_evtx_truncation(tiny)),
          repr(check_evtx_truncation(tiny)))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
