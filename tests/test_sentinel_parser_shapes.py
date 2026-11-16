"""Sentinel's parser reads every EventData shape, and its times are UTC-aware.

Gemini audit 10-06 (High), sentinel/analysis/parser.py:
1. EventData with ONE named <Data> (pyevtx-rs gives a dict, not a list)
   came out empty;
2. a JSON null value became the text "None";
3. a timestamp whose last six characters hold a "-" (a date only) parsed
   naive, and comparing it with aware times raises;
4. Computer given as JSON null became None (and as {"#text": ...} a dict:
   the 1-08 pattern of the main parser);
5. the diagnostic scanner counted a target ID from any provider, while the
   parser reads it only from its own provider (_is_target).

Expected: each right.  Synthetic records.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import json
    import types
    from sentinel.analysis import parser as P
    one = P._flatten_event_data({"Data": {"#attributes": {"Name": "CommandLine"}, "#text": "cmd.exe /c whoami"}})
    check("one named <Data> is read", one == {"CommandLine": "cmd.exe /c whoami"}, str(one))
    nul = P._flatten_event_data({"Data": {"CommandLine": None, "User": "u"}})
    check("a JSON null is empty, not 'None'", nul.get("CommandLine") == "", str(nul))
    t = P._parse_ts("2026-01-01")
    check("a date-only timestamp is UTC-aware", t.tzinfo is not None, repr(t))
    t2 = P._parse_ts("2026-01-01T15:30:00+05:30")
    check("an offset time is converted to UTC", t2.utcoffset().total_seconds() == 0 and t2.hour == 10, repr(t2))

    def rec(computer):
        return {"Event": {"System": {"EventID": 4688, "Channel": "Security",
                                     "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                                     "Computer": computer,
                                     "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T10:00:00.000000Z"}}},
                          "EventData": {"Data": [{"#attributes": {"Name": "NewProcessName"}, "#text": "C:\\x\\a.exe"}]}}}
    fn = getattr(P, "_parse_record", None)
    hosts = []
    for c in (None, {"#text": "HOST-A"}):
        try:
            r = fn(rec(c), "")
        except Exception as exc:          # pre-fix: a dict Computer raised
            r = None
            print("   ", type(exc).__name__, exc)
        hosts.append(getattr(r, "host", "?") if r is not None else None)
    check("Computer null is empty, and {'#text': ...} is its text", hosts == ["", "HOST-A"], str(hosts))

    class _Parser:
        def __init__(self, p):
            pass

        def records_json(self):
            d = rec("H")
            d["Event"]["System"]["Provider"] = {"#attributes": {"Name": "SomeApp"}}
            yield {"data": json.dumps(d)}
    found = P._scan_file_for_target_ids("x.evtx", types.SimpleNamespace(PyEvtxParser=_Parser))
    check("the diagnostic scan applies the provider check", 4688 not in found, str(found))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
