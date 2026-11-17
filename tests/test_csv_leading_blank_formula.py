"""A formula after leading blank characters is made safe too (Gemini 6-12 / 13-06, ruling R37).

The user's CSV rule of 2026-11-06 checked only the first character, so " =1+1" or
"\\n=1+1" reached the spreadsheet unprefixed. The user left the choice to Claude
on 2026-11-17 ("idk ill take ur recommendation"); ruling R37 widens the rule:
a cell whose first non-blank character (str.isspace) is = + - @ gets one leading
apostrophe. Plain numbers, also with blanks around them, and the lone "-" stay
untouched. Both the EventHawk and the standalone Sentinel writer must agree.
Synthetic values only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.output.exporters import csv_cell as eh
    from sentinel.report.csv_safe import csv_cell as se
    risky = [" =1+1", "\n=1+1", "  +cmd|' /C calc'!A0", " @SUM(A1)", "\r\n-2+3", "\t =1", " \t\n=HYPERLINK(\"x\")"]
    unchanged = [" -1", "  +44 ", "\n1e5", " - ", "-", " ", "", "  normal text", " a=b", "x =1"]
    for name, fn in (("exporters.csv_cell", eh), ("sentinel csv_cell", se)):
        for v in risky:
            check(f"{name}: {v!r} gets one apostrophe", fn(v) == "'" + v, repr(fn(v)))
        for v in unchanged:
            check(f"{name}: {v!r} unchanged", fn(v) == v, repr(fn(v)))
        for v in ("=1", "+a", "-a", "@a", "\t1", "\r1"):
            check(f"{name}: old rule kept for {v!r}", fn(v) == "'" + v, repr(fn(v)))
        check(f"{name}: non-text unchanged", fn(5) == 5 and fn(None) is None)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
