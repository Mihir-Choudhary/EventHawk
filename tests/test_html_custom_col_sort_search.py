"""HTML report with custom columns: ATT&CK sorts as ATT&CK; custom values are searchable.

Gemini audit 6-07 (Medium): custom columns sit between Source and ATT&CK in
the report table, but the sort code dispatched on a fixed column 7, so the
first custom column was sorted by ATT&CK tag count and ATT&CK as text; and
the search index left custom column values out.

Expected: with one custom column the report names ATT&CK's column (8) for the
sort code and has no fixed "case 7"; the search text of an event holds its
custom column value.  Synthetic event.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.output import exporters as X
    ev = {"record_id": 1, "event_id": 4688, "timestamp": "2026-01-01T00:00:00.000000Z", "channel": "Security",
          "computer": "H", "provider": "P", "event_data": {}, "source_file": "a.evtx", "level": 4,
          "level_name": "Information", "custom_columns": {"Parent": "qzxparentval"}}
    d = tempfile.mkdtemp(prefix="htmlcc_")
    try:
        p = os.path.join(d, "r.html")
        X.export_html([ev], p)
        html = open(p, encoding="utf-8").read()
        check("the sort code is told ATT&CK is column 8", "window._ATKCOL=8" in html)
        check("no fixed 'case 7' ATT&CK branch is left", "case 7:" not in html)
        check("the search text holds the custom column value", "qzxparentval" in X._build_search_string(ev))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
