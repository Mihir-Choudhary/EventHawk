"""Positional custom columns follow document order when UserData mixes named fields and Data (Codex C2-2).

data_items() took the "Data" key alone whenever it existed, so for UserData
holding a named field before a <Data> child, {Data[1]} returned the Data value
instead of the first field (4 real EID 18 records disagreed with Windows'
EventLogReader.Properties[0]).  Expected: every leaf in document order, unless
Data is the event's only content (ordinary EventData), which is unchanged.
Synthetic data only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.custom_columns import data_items
    mixed = {"Version": "2", "Data": "C:\\x.dll"}
    got = data_items(mixed)
    check("UserData: a named field before Data comes first", got[:2] == [("Version", "2"), ("Data", "C:\\x.dll")],
          str(got))
    check("the positional fast path (need=1) gives the same first item", data_items(mixed, need=1)[:1] == got[:1],
          str(data_items(mixed, need=1)))
    named = {"Data": [{"#attributes": {"Name": "A"}, "#text": "1"}, {"#attributes": {"Name": "B"}, "#text": "2"}]}
    check("ordinary named EventData unchanged", data_items(named) == [("A", "1"), ("B", "2")], str(data_items(named)))
    unnamed = {"Data": {"#text": ["x", "y"]}, "Binary": "00AA"}
    check("unnamed EventData with Binary unchanged", data_items(unnamed) == [(None, "x"), (None, "y")],
          str(data_items(unnamed)))
    attrs = {"#attributes": {"xmlns": "u"}, "Data": "only"}
    check("Data with only metadata keys beside it is still the Data branch", data_items(attrs) == [(None, "only")],
          str(data_items(attrs)))
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
