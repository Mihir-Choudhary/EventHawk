"""Sentinel's CSV report works without evtx_tool, with EventHawk's formula rule.

Gemini audit 10-12 (Low): sentinel/report/generator.py imported
SafeDictWriter from evtx_tool, so Sentinel -- documented as a standalone
package -- failed to write its CSV report outside the EventHawk tree.

Expected: the report is written with evtx_tool unavailable, and Sentinel's
own cell rule gives exactly EventHawk's result on the same values (the
user's CSV rule of 2026-11-06).  Synthetic.
"""
import builtins
import csv
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

VALUES = ['=HYPERLINK("x")', "+cmd", "-2+3", "@SUM(A1)", "\t=1", "\r=1", "-1", "+44", "1e5", "-", "plain", "", "a=b"]


def main() -> int:
    from sentinel.models import NormalizedEvent, RawEvent, ScoredEvent
    raw = RawEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), host="H", event_id=1, process_guid="",
                   pid=1, ppid=0, parent_guid="", process_name="a.exe", process_path="", parent_name="",
                   parent_path="", cmdline='=HYPERLINK("http://x")', user="u", integrity_level="", image_hash="")
    se = ScoredEvent(normalized=NormalizedEvent(raw=raw, proc_norm="a.exe", parent_norm="b.exe",
                                                cmdline_norm="x", ancestry_chain=["a.exe"]), composite=90.0, tier=4)
    for m in [k for k in sys.modules if k == "evtx_tool" or k.startswith("evtx_tool.")]:
        del sys.modules[m]
    real_import = builtins.__import__

    def no_evtx_tool(name, *a, **k):
        if name == "evtx_tool" or name.startswith("evtx_tool."):
            raise ModuleNotFoundError(f"No module named '{name}'")
        return real_import(name, *a, **k)
    out = Path(tempfile.mkdtemp(prefix="scsv_")) / "r.csv"
    builtins.__import__ = no_evtx_tool
    try:
        from sentinel.report.generator import generate_csv_report
        try:
            generate_csv_report([se], {}, None, out)
            ok1 = out.exists()
            err = ""
        except Exception as exc:
            ok1, err = False, f"{type(exc).__name__}: {exc}"
    finally:
        builtins.__import__ = real_import
    print(f"  {'PASS' if ok1 else 'FAIL'}  the CSV report is written without evtx_tool  -- {err}")
    cell = ""
    if ok1:
        with open(out, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        cell = rows[0].get("cmdline_raw", "") if rows else ""
    ok2 = cell == "'" + '=HYPERLINK("http://x")'
    print(f"  {'PASS' if ok2 else 'FAIL'}  a formula-like cell is protected  -- {cell!r}")
    from sentinel.report.csv_safe import csv_cell as s_cell
    from evtx_tool.output.exporters import csv_cell as e_cell
    ok3 = [s_cell(v) for v in VALUES] == [e_cell(v) for v in VALUES]
    print(f"  {'PASS' if ok3 else 'FAIL'}  Sentinel's rule equals EventHawk's on every case")
    n = ok1 + ok2 + ok3
    print(f"{n}/3 checks passed")
    return 0 if n == 3 else 1


if __name__ == "__main__":
    sys.exit(main())
