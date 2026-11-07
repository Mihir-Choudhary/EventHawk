"""The PDF IOC section lists every category and every value, whole, from real IOC entries (Codex CK91-2, CK91-3).

CK91-2: the PDF listed 7 hard-coded categories; extract_iocs() returns 18.
  ipv6, sha1, commandlines, filepaths, registry, urls, named_pipes, services,
  tasks, shares and dlls were silently left out (40,343 values on a real set).
CK91-3: callers pass extract_iocs() entries - dicts - and the PDF printed the
  whole dict (record_keys, record_ids...) as the value.  One real Computer
  entry with 500 producer keys, or one 16,000-character value, made the export
  fail with LayoutError (a table row taller than a page).
Expected: every list category the extractor returns appears with every value
exactly and whole, no entry metadata dumped, no LayoutError.
Synthetic data only.  Needs reportlab and PyMuPDF.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def entry(value, nkeys=3):
    keys = [["C:\\x\\Security.evtx", i] for i in range(1, nkeys + 1)]
    return {"value": value, "count": nkeys, "first_seen": "2024-01-02T03:04:05Z",
            "last_seen": "2024-01-02T04:04:05Z", "event_ids": [4688],
            "record_ids": list(range(1, nkeys + 1)), "record_keys": keys,
            "users": ["u1"], "computers": ["HOST-A"], "sources": ["Security.evtx"],
            "score": 0, "score_reasons": [], "threat_intel": None}


def squash(s):
    return "".join(s.split())


def main() -> int:
    import pymupdf as fitz
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    from evtx_tool.output import exporters as X

    cats = [k for k, v in extract_iocs([]).items() if isinstance(v, list)]
    check("the extractor's own category list is used (not vacuous)", len(cats) >= 18, f"{len(cats)} categories")
    LONG_SPACED = " ".join(f"word{i:05d}" for i in range(1600))          # ~16,000 characters
    LONG_SOLID = "C:\\" + "A" * 16000 + ".exe"
    iocs = {k: [entry(f"SENT-{k}-a&b<c>")] for k in cats}
    iocs["computers"].append(entry("BUSY-HOST", nkeys=500))
    iocs["commandlines"].append(entry(LONG_SPACED))
    iocs["filepaths"].append(entry(LONG_SOLID))
    iocs["correlation"] = {}
    ev = {"event_id": 4688, "record_id": 1, "timestamp": "2024-01-02T03:04:05Z", "level_name": "Information",
          "computer": "HOST-A", "channel": "Security", "source_file": "C:\\x\\a.evtx", "event_data": {}}
    tmp = tempfile.mkdtemp(prefix="pdfioc_")
    try:
        p = os.path.join(tmp, "r.pdf")
        try:
            X.export_pdf([ev], p, iocs=iocs)
        except Exception as e:                                          # noqa: BLE001
            check("PDF export with real-shaped IOC entries works (no LayoutError)", False, repr(e)[:200])
            return finish()
        check("PDF export with real-shaped IOC entries works (no LayoutError)", True)
        text = "".join(pg.get_text() for pg in fitz.open(p))
        flat = squash(text)
        missing = [k for k in cats if squash(f"SENT-{k}-a&b<c>") not in flat]
        check("every extractor category's value appears, exactly", not missing,
              f"{len(cats) - len(missing)}/{len(cats)}; missing {missing}")
        check("a 500-producer entry shows its value", "BUSY-HOST" in flat)
        check("no entry metadata dumped as the value", "record_keys" not in text and "record_ids" not in text
              and "'value'" not in text)
        check("a ~16,000-character spaced value appears whole", squash(LONG_SPACED) in flat)
        check("a 16,000-character unbroken value appears whole", squash(LONG_SOLID) in flat)
        # The cover counted only IPv4 + SHA-256 + MD5 from a summary: every value counts.
        total = sum(len(v) for v in iocs.values() if isinstance(v, list))
        check("the cover's IOC count is every value in every category",
              squash(f"IOCs Found{total} indicators") in flat, f"expected {total}")
        p0 = os.path.join(tmp, "r0.pdf")
        X.export_pdf([ev], p0, iocs={k: [] for k in cats}, chains=[])
        flat0 = squash("".join(pg.get_text() for pg in fitz.open(p0)))
        check("correlation and IOC extraction that found nothing say 0, not 'not used'",
              squash("Chains Found0") in flat0 and squash("IOCs Found0 indicators") in flat0
              and "notused" not in flat0, flat0[:300])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return finish()


def finish():
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
