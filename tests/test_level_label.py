"""A level with no standard name is shown as its number, in both modes.

Codex audit-5b A5B-LEVEL16: Juggernaut mode labelled every level it had no name
for "Information" (`_LEVEL_MAP.get(level, "Information")`).  On the real corpus
4,672 events with raw Level 16 read "Information" in the grid and in all four
export formats -- a severity the log never recorded.  Normal mode shows the
number ("16").

Expected: both modes give the same label for every level: the standard name
for 0-5, the number itself for anything else.  Synthetic records only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def record(level):
    system = {"EventID": 4624, "Level": level, "EventRecordID": 9, "Channel": "Security", "Computer": "C",
              "Provider": {"#attributes": {"Name": "P"}},
              "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00.000000Z"}}}
    return {"Event": {"System": system, "EventData": {}}}


def main() -> int:
    from evtx_tool.core.heavyweight.engine import _ARROW_COLS, _extract_and_filter
    from evtx_tool.core.parser import LEVEL_NAMES
    li, ni = _ARROW_COLS.index("level"), _ARROW_COLS.index("level_name")
    for level in (0, 1, 2, 3, 4, 5, 6, 16, 255):
        row = _extract_and_filter(record(level), r"C:\s\Security.evtx", None)
        jm = (row[li], row[ni]) if isinstance(row, tuple) else ("not a row", row)
        normal = LEVEL_NAMES.get(level, str(level))
        check(f"Level {level}: JM label equals Normal's ({normal!r})", jm == (level, normal), str(jm))
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
