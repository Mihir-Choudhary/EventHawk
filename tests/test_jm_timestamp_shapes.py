"""Juggernaut stores the right UTC time for unusual timestamp shapes.

Gemini audit 2-05 (Medium): with no <TimeCreated>, Juggernaut stored NULL
although pyevtx-rs gives the record's timestamp (Normal mode keeps it); a
"+05:30" offset became "...+05:300" or was cut off without converting to UTC;
and the parse-time filter lacked keywords and event_source_name.

pyevtx-rs always writes SystemTime as "...Z", so these are synthetic records.

Expected: no TimeCreated -> the record timestamp; "2026-01-01T05:30:00+05:30"
-> "2026-01-01 00:00:00.000000"; with a fraction and offset -> converted with
its fraction; a plain "Z" time unchanged; a keywords filter applies at parse
time.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rec(ts=None, keywords="0x8020000000000000"):
    system = {"Provider": {"#attributes": {"Name": "P", "EventSourceName": "Src"}}, "EventID": 1, "Level": 4,
              "EventRecordID": 5, "Channel": "Security", "Computer": "HOST-A", "Keywords": keywords}
    if ts is not None:
        system["TimeCreated"] = {"#attributes": {"SystemTime": ts}}
    return {"Event": {"System": system, "EventData": {"A": "1"}}}


def main() -> int:
    from evtx_tool.core.heavyweight import engine as H
    i = H._COL_NAMES.index("timestamp_utc") if hasattr(H, "_COL_NAMES") else 4

    def ts_of(r, **kw):
        row = H._extract_and_filter(r, "f.evtx", None, 5, **kw)
        return row[i] if isinstance(row, tuple) else row
    try:
        v = ts_of(rec(None), record_ts="2026-04-01T08:15:00.500000Z")
    except TypeError as e:
        v = repr(e)
    check("no TimeCreated: the record's own timestamp is used", v == "2026-04-01 08:15:00.500000", repr(v))
    v = ts_of(rec("2026-01-01T05:30:00+05:30"))
    check("+05:30 offset is converted to UTC", v == "2026-01-01 00:00:00.000000", repr(v))
    v = ts_of(rec("2026-01-01T05:30:00.123456+05:30"))
    check("+05:30 with a fraction is converted with its fraction", v == "2026-01-01 00:00:00.123456", repr(v))
    v = ts_of(rec("2026-01-01T05:30:00.123456Z"))
    check("a plain Z time is unchanged", v == "2026-01-01 05:30:00.123456", repr(v))
    from evtx_tool.core.filters import compile_filter, empty_filter
    fc = empty_filter()
    fc["levels"] = ["Audit Failure"]          # decided by the Keywords bits
    try:
        p = compile_filter(fc)
        a = H._extract_and_filter(rec("2026-01-01T00:00:00Z"), "f.evtx", p, 5)
        b = H._extract_and_filter(rec("2026-01-01T00:00:00Z", keywords="0x8010000000000000"), "f.evtx", p, 5)
        ok, d = (a is False and isinstance(b, tuple)), f"{type(a).__name__} / {type(b).__name__}"
    except Exception as e:
        ok, d = False, repr(e)
    check("an Audit Failure level filter (Keywords bits) applies at parse time", ok, d)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
