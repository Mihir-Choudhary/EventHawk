"""An IOC seen in a log and in a saved part of that log counts once and keeps both records.

Since d6984c3 copies are recognised by the XML EventRecordID, which a saved
part of a log keeps while its record header number restarts at 1.  The IOC
then counted the record once (right), but its record_ids listed only the kept
record's number: the copy's number disappeared from the IOC's context (found
by Claude's old-vs-new corpus comparison: 88 numbers on 24 sample IOCs).

Expected: count 1; record_keys hold both (file, record number) pairs, so the
pivot shows both rows; record_ids hold both record numbers.  Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(sf, header, xml):
    return {"record_id": header, "event_record_id": xml, "source_file": sf, "event_id": 4688,
            "computer": "WS1", "channel": "Security", "timestamp": "2026-01-01T00:00:01.000000Z",
            "event_data": {"NewProcessName": r"C:\Temp\evil.exe", "CommandLine": "evil.exe -x"}}


def main() -> int:
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    full = ev(r"C:\c\Security.evtx", 6575, 6575)
    part = ev(r"C:\c\saved-part.evtx", 1, 6575)
    iocs = extract_iocs([full, part])
    e = next((x for x in iocs.get("commandlines", []) if x["value"] == "evil.exe -x"), None)
    check("the IOC is found", e is not None)
    if e:
        check("counted once (the same record twice)", e["count"] == 1, str(e["count"]))
        keys = {tuple(k) for k in e["record_keys"]}
        check("record_keys hold both copies for the pivot",
              keys == {(r"C:\c\Security.evtx", 6575), (r"C:\c\saved-part.evtx", 1)}, str(keys))
        check("record_ids hold both record numbers", e["record_ids"] == [1, 6575], str(e["record_ids"]))
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
