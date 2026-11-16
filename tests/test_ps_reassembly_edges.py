"""PowerShell script blocks: every fragment kept, keys per host, copies counted once.

Gemini audit 9-04 / 9-08 / 9-03 (High), ps_extractor:
1. a 4104 with MessageNumber 0 and MessageTotal 0 assembled to "" (the
   script text was lost); with (0, 1) or (-1, 1) the text was replaced by
   "[MISSING FRAGMENT 1 of 1]";
2. a fragment numbered past its MessageTotal (2 of 1) was dropped;
3. a 4104 with no ScriptBlockId was skipped entirely;
4. one fragment claiming MessageTotal 1,000,000 wrote a million
   "[MISSING FRAGMENT]" lines (a ~9,200x blow-up from one event);
5. zero-GUID blocks were keyed by record ID only, so two hosts' blocks with
   the same record ID overwrote each other;
6. a log loaded twice (a copy) doubled every record.

Expected: the text kept (and marked when its number is invalid), the extra
fragment kept with fragment 1 marked missing, the no-ID block analysed,
missing runs written as one range line, two zero-GUID blocks, copies
counted once.  Synthetic records.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
OP = "Microsoft-Windows-PowerShell/Operational"
ZERO = "00000000-0000-0000-0000-000000000000"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rec(rid, text, sbid, num=1, tot=1, host="HOST", ts="2026-02-17T20:49:12.000000Z"):
    data = {"Event": {
        "System": {"Channel": OP, "EventID": 4104, "Computer": host, "Level": 5,
                   "EventRecordID": rid,
                   "TimeCreated": {"#attributes": {"SystemTime": ts}}},
        "EventData": {"MessageNumber": num, "MessageTotal": tot, "ScriptBlockText": text,
                      "ScriptBlockId": sbid, "Path": ""}}}
    return {"event_record_id": rid, "timestamp": ts, "data": json.dumps(data)}


def index(records):
    from evtx_tool.analysis.ps_extractor.event_parsers import parse_4104
    from evtx_tool.analysis.ps_extractor.reassembler import build_script_block_index
    evs = []
    for r in records:
        d = json.loads(r["data"])
        d["_record_id"] = r["event_record_id"]
        evs.append(parse_4104(d))
    return build_script_block_index(evs)


def main() -> int:
    t = "Get-WmiObject Win32_Process | Select Name"
    a = list(index([rec(1, t, "{11111111-1111-1111-1111-111111111111}", 0, 0)]).values())
    check("(0, 0): the script text is kept", a and t in a[0].assemble(), repr(a[0].assemble()[:80]) if a else "")
    for num in (0, -1):
        a = list(index([rec(1, t, "{22222222-2222-2222-2222-22222222222%d}" % (num + 2), num, 1)]).values())
        s = a[0].assemble() if a else ""
        check(f"({num}, 1): the text is kept and marked as an invalid fragment number",
              t in s and "MessageNumber" in s, repr(s[:120]))
    a = list(index([rec(1, "part two", "{33333333-3333-3333-3333-333333333333}", 2, 1)]).values())
    s = a[0].assemble() if a else ""
    check("(2, 1): the fragment past the total is kept, fragment 1 marked missing",
          "part two" in s and "MISSING FRAGMENT 1" in s and a and not a[0].is_complete, repr(s[:120]))
    a = index([rec(7, t, "")])
    check("a 4104 with no ScriptBlockId is kept", len(a) == 1 and t in list(a.values())[0].assemble(), str(list(a)))
    a = list(index([rec(1, "x", "{44444444-4444-4444-4444-444444444444}", 1, 1_000_000)]).values())
    s = a[0].assemble() if a else ""
    check("one fragment claiming 1,000,000 parts writes one range line, not a million",
          len(s) < 1000 and "2-1000000" in s.replace(",", "").replace(" to ", "-"), f"{len(s)} chars: {s[:100]!r}")
    a = index([rec(5, "host one", ZERO, host="HOST-1"), rec(5, "host two", ZERO, host="HOST-2")])
    texts = sorted(x.assemble() for x in a.values())
    check("two hosts' zero-GUID blocks with one record ID stay two", texts == ["host one", "host two"], str(texts))

    # A log loaded twice: through the whole extractor.
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor
    out = tempfile.mkdtemp(prefix="ps_reasm_")
    try:
        one = [rec(10, "Get-Date", "{55555555-5555-5555-5555-555555555555}")]
        s1 = PSExtractor(list(one), out).run()
        s2 = PSExtractor(one + [dict(one[0], _source_file="copy.evtx")], tempfile.mkdtemp(prefix="ps_reasm2_")).run()
        check("a copied record counts once", s2.get("total_ps_events") == s1.get("total_ps_events") == 1,
              f"{s1.get('total_ps_events')} vs {s2.get('total_ps_events')}")
    finally:
        shutil.rmtree(out, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
