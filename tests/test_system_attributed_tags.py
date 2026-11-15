"""A <System> tag that carries XML attributes keeps its value in both modes.

Gemini audit 1-08 / 2-03 (High): pyevtx-rs renders a tag with attributes as
{"#attributes": {...}, "#text": value}.  The extractors unwrapped that only
for EventID and EventRecordID: Level became 4 (Information) whatever it was,
Computer/Channel/Keywords stayed dicts (compile_filter crashed on them;
Juggernaut wrote the dict's repr), and Juggernaut's _safe_int turned
{"#text": 0} into the default and raised on {"#text": ""} (dropping the event).

None of the 8.3 million records in the corpus has such a tag (only EventID
carries Qualifiers), so this is a synthetic-record test.

Expected: Level 2 stays 2 (Error), Level 0 stays 0, Computer/Channel/Keywords
are their text, a computer filter matches, and Juggernaut keeps the event
when an integer tag is {"#text": ""}.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rec(level, eid_extra=None):
    w = lambda v: {"#attributes": {"Name": "x"}, "#text": v}
    system = {
        "Provider": {"#attributes": {"Name": "Synth-Provider"}},
        "EventID": 4624, "Version": 0, "Level": w(level), "Task": w(12544), "Opcode": w(0),
        "Keywords": w("0x8020000000000000"),
        "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00.000000Z"}},
        "EventRecordID": 7, "Channel": w("Security"), "Computer": w("HOST-A"),
        "Execution": {"#attributes": {"ProcessID": 4, "ThreadID": 8}},
    }
    if eid_extra:
        system.update(eid_extra)
    return {"Event": {"System": system, "EventData": {"TargetUserName": "u1"}}}


def main() -> int:
    from evtx_tool.core.engine import _extract_event_inline
    from evtx_tool.core.parser import _extract_from_json
    from evtx_tool.core.filters import compile_filter
    ts = "2026-01-01T00:00:00.000000Z"
    for label, fn in (("Normal worker", lambda d: _extract_event_inline(d, 7, ts, "f.evtx")),
                      ("parser", lambda d: _extract_from_json(d, 7, ts, "f.evtx"))):
        e2, e0 = fn(rec(2)), fn(rec(0))
        check(f"{label}: Level 2 stays 2", e2["level"] == 2, repr(e2["level"]))
        check(f"{label}: Level 0 stays 0", e0["level"] == 0, repr(e0["level"]))
        check(f"{label}: Computer/Channel/Keywords are text",
              (e2["computer"], e2["channel"], e2["keywords"]) == ("HOST-A", "Security", "0x8020000000000000"),
              repr((e2["computer"], e2["channel"], e2["keywords"])))
        check(f"{label}: Task/Opcode are numbers", (e2["task"], e2["opcode"]) == (12544, 0),
              repr((e2["task"], e2["opcode"])))
        try:
            ok = compile_filter({"computers": ["host-a"]})(e2)
            err = ""
        except Exception as x:
            ok, err = False, repr(x)
        check(f"{label}: a computer filter matches it", ok, err)

    from evtx_tool.core.heavyweight import engine as H
    check("Juggernaut _safe_int({'#text': 0}, 4) is 0", H._safe_int({"#text": 0}, 4) == 0, repr(H._safe_int({"#text": 0}, 4)))
    try:
        v = H._safe_int({"#text": ""}, None)
        err = ""
    except Exception as x:
        v, err = "raised", repr(x)
    check("Juggernaut _safe_int({'#text': ''}, None) is None (no exception)", v is None, err)
    row = H._extract_and_filter(rec(2), "f.evtx", None)
    vals = [str(v) for v in (row if isinstance(row, tuple) else ())]
    check("Juggernaut row keeps the text values, no dict repr",
          isinstance(row, tuple) and "HOST-A" in vals and "Security" in vals
          and not any("#attributes" in v for v in vals), repr(row)[:200])
    row0 = H._extract_and_filter(rec(0, {"EventRecordID": {"#attributes": {"a": "b"}, "#text": ""}}), "f.evtx", None)
    check("Juggernaut keeps an event whose EventRecordID is {'#text': ''}", isinstance(row0, tuple), repr(row0)[:120])
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
