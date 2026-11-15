"""Unusual payload and System shapes keep their data in both modes.

Gemini audit 1-09 (Medium): an <EventData Name="..."/> that carries only
attributes is a non-empty dict, so "EventData or UserData" picked it and the
populated <UserData> was thrown away; a scalar EventData was dropped.
Gemini audit 1-10 (Medium): a self-closing <Channel/>, <Computer/> or
<Keywords/> is null in pyevtx-rs JSON; dict.get(k, "") then returned None and
event_to_text() raised TypeError.

In the corpus 530 records have an attributes-only EventData (none with
UserData) and none has a null Channel/Computer/Keywords, so this is a
synthetic-record test.

Expected: the UserData fields are the event's data in the Normal worker, the
parser and Juggernaut; a scalar EventData is kept as "Data"; a null
Channel/Computer/Keywords reads as "" and event_to_text works.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rec(payload, **sys_over):
    system = {"Provider": {"#attributes": {"Name": "Synth"}}, "EventID": 21, "Level": 4,
              "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00.000000Z"}},
              "EventRecordID": 3, "Channel": "Synth/Operational", "Computer": "HOST-A", "Keywords": "0x0"}
    system.update(sys_over)
    return {"Event": {"System": system, **payload}}


def main() -> int:
    from evtx_tool.core.engine import _extract_event_inline
    from evtx_tool.core.parser import _extract_from_json, event_to_text
    from evtx_tool.core.heavyweight import engine as H
    ts = "2026-01-01T00:00:00.000000Z"
    shadow = {"EventData": {"#attributes": {"Name": "EmptySchema"}},
              "UserData": {"EventXML": {"User": "u1", "Address": "192.0.2.50"}}}
    scalar = {"EventData": "plain text payload"}
    for label, fn in (("Normal worker", lambda d: _extract_event_inline(d, 3, ts, "f.evtx")),
                      ("parser", lambda d: _extract_from_json(d, 3, ts, "f.evtx"))):
        e = fn(rec(shadow))
        check(f"{label}: UserData is kept under an attributes-only EventData",
              "u1" in json.dumps(e["event_data"]), repr(e["event_data"]))
        e = fn(rec(scalar))
        check(f"{label}: a scalar EventData is kept", "plain text payload" in json.dumps(e["event_data"]),
              repr(e["event_data"]))
        e = fn(rec({"EventData": {"A": "1"}}, Channel=None, Computer=None, Keywords=None))
        check(f"{label}: null Channel/Computer/Keywords read as ''",
              (e["channel"], e["computer"], e["keywords"]) == ("", "", ""),
              repr((e["channel"], e["computer"], e["keywords"])))
        try:
            event_to_text(e)
            err = ""
        except Exception as x:
            err = repr(x)
        check(f"{label}: event_to_text works on it", not err, err)
    for label, payload, want in (("UserData under an attributes-only EventData", shadow, "u1"),
                                 ("a scalar EventData", scalar, "plain text payload")):
        row = H._extract_and_filter(rec(payload), "f.evtx", None)
        check(f"Juggernaut: {label} is kept", isinstance(row, tuple) and any(want in str(v) for v in row),
              repr(row)[-200:])
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
