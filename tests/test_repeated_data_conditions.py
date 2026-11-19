"""Field conditions on a repeated <Data Name> (Gemini audit 3-06).

A record with two <Data Name="Files"> values is read as Files = ["alpha.dll",
"beta.dll"] (record_json._keep_repeats).  Every engine compared the list as
one text -- "['alpha.dll', 'beta.dll']" in Normal mode, '["alpha.dll",
"beta.dll"]' in Juggernaut SQL -- so "Files equals alpha.dll", "starts with"
and "ends with" never matched it, and "not equals" kept it.  The XML-shaped
named-Data list kept only the last value.  Expected: each element is a value
of its own (one must match a positive operator, all must pass a "not" one),
in the CLI filter, the Normal view and the JM view alike.  The expected sets
are computed here from the element lists directly.  Synthetic events only.
"""
import os
import re
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_around_pivot as T                                       # noqa: E402
from test_jm_export_text_filter import write_jm                     # noqa: E402
from test_partial_date_modes_tz import normal_ids, jm_ids           # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


VALUES = [
    ["Alpha.dll", "beta.dll"],          # repeated name, mixed case
    "alpha.dll",                         # plain value
    "gamma.dll",
    ["delta.exe", "alpha.dll", "x"],
    ["only.sys"],
    [],                                  # (cannot come from XML, kept for the rule)
    None,                                # field absent
    ["12", "40"],                        # numbers held as text
    "[bracketed] text",                  # a plain value that looks like a list
]
FIELD = "Files"
SPACED = "Target Files"                  # a name read through a JSON pointer


def events():
    out = []
    for n, v in enumerate(VALUES, 1):
        ed = {"Other": "o"}
        if v is not None:
            ed[FIELD] = v
            ed[SPACED] = v
        out.append({"event_id": 1, "level": 4, "level_name": "Information", "provider": "P",
                    "channel": "C", "computer": "PC", "record_id": n, "source_file": r"C:\a\s.evtx",
                    "timestamp": f"2024-01-01T00:00:{n:02d}.000000Z", "event_data": ed})
    return out


def elements(v):
    if v is None:
        return [""]
    if isinstance(v, list):
        return [str(x) for x in v] or [""]
    return [str(v)]


def num(s):
    try:
        return float(s)
    except ValueError:
        return None


def oracle(op, val, cs):
    low = (lambda s: s) if cs else str.lower
    tests = {
        "equals": lambda e: low(e) == low(val),
        "contains": lambda e: low(val) in low(e),
        "starts with": lambda e: low(e).startswith(low(val)),
        "ends with": lambda e: low(e).endswith(low(val)),
        "regex": lambda e: re.search(val, e, 0 if cs else re.I) is not None,
        "greater than": lambda e: num(e) is not None and num(e) > float(val),
        "less than": lambda e: num(e) is not None and num(e) < float(val),
        "not equals": lambda e: low(e) != low(val),
        "not contains": lambda e: low(val) not in low(e),
    }
    t = tests[op]
    agg = all if op.startswith("not ") else any
    return {n for n, v in enumerate(VALUES, 1) if agg(t(e) for e in elements(v))}


CASES = [("equals", "alpha.dll"), ("equals", "beta.dll"), ("starts with", "beta"),
         ("ends with", ".exe"), ("contains", "pha"), ("regex", r"^only\.sys$"),
         ("greater than", "30"), ("less than", "13"), ("not equals", "alpha.dll"),
         ("not contains", "dll"), ("equals", "[bracketed] text")]


def cfg_for(field, op, val, cs):
    from evtx_tool.core.filters import empty_filter
    return dict(empty_filter(), conditions=[{"name": field, "operator": op, "value": val}],
                case_sensitive=cs)


def main() -> int:
    from evtx_tool.core.filters import compile_filter, flatten_fields
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    evs = events()
    tmp = tempfile.mkdtemp(prefix="repdata_")
    jm = ArrowTableModel(write_jm(evs, tmp), parquet_dir=tmp)
    T.wait_for(lambda: not jm.filter_pending(), 30)
    try:
        for field in (FIELD, SPACED):
            for op, val in CASES:
                for cs in (False, True):
                    want = oracle(op, val, cs)
                    cfg = cfg_for(field, op, val, cs)
                    label = f"[{field}] {op} {val!r}{' (case-sensitive)' if cs else ''}"
                    fn = compile_filter(cfg)
                    got = {e["record_id"] for e in evs if fn(e)}
                    check(f"{label}: CLI filter", got == want, f"{sorted(got)} vs {sorted(want)}")
                    got = normal_ids(evs, cfg)
                    check(f"{label}: Normal", got == want, f"{sorted(got)} vs {sorted(want)}")
                    got = jm_ids(jm, cfg)
                    check(f"{label}: JM", got == want, f"{sorted(got)} vs {sorted(want)}")
        xml = {"Data": [{"#attributes": {"Name": "Files"}, "#text": "alpha.dll"},
                        {"#attributes": {"Name": "Files"}, "#text": "beta.dll"},
                        {"#attributes": {"Name": "Files"}, "#text": "gamma.dll"},
                        {"#attributes": {"Name": "User"}, "#text": "u"}]}
        flat = flatten_fields(xml)
        check("XML named-Data list keeps every repeated value",
              flat.get("Files") == ["alpha.dll", "beta.dll", "gamma.dll"] and flat.get("User") == "u",
              str(flat))
        check("a name set before the Data list is not merged into it",
              flatten_fields({"Files": "top", "Data": [{"#attributes": {"Name": "Files"}, "#text": "a"}]})
              .get("Files") == "a")
    finally:
        jm.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
