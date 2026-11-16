"""PowerShell extraction reports a failure in its last steps everywhere.

Gemini audit 9-09 (Medium): the summary (and its error count) was written
before ps_extraction.json and ps_timeline.xlsx.  When the workbook could not
be written, the returned summary, the JSON and ps_extraction_summary.txt
all said 0 errors, the text still listed ps_timeline.xlsx as written, and
the GUI showed a clean "complete" box.

Expected: the error counted in the returned summary, the JSON and the text,
and the text marks the workbook as not written.  Synthetic records.
"""
import json
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
    import evtx_tool.analysis.ps_extractor.extractor as ex
    data = {"Event": {"System": {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104,
                                 "Computer": "C1", "Level": 5, "EventRecordID": 1,
                                 "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:05.000000Z"}}},
                      "EventData": {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": "Get-Date",
                                    "ScriptBlockId": "{aaaaaaaa-1111-1111-1111-111111111111}", "Path": ""}}}
    rec = {"event_record_id": 1, "timestamp": "2024-01-02T03:04:05.000000Z", "data": json.dumps(data)}
    real = ex.write_csv_timeline

    def boom(**kw):
        raise ModuleNotFoundError("No module named 'openpyxl'")
    ex.write_csv_timeline = boom
    out = tempfile.mkdtemp(prefix="ps_late_")
    try:
        s = ex.PSExtractor([rec], out).run()
        check("the returned summary counts the workbook failure", s.get("parse_errors") == 1, str(s.get("parse_errors")))
        js = json.load(open(os.path.join(out, "ps_extraction.json"), encoding="utf-8"))
        jerr = (js.get("summary") or {}).get("parse_errors")
        check("the JSON counts it and lists it", jerr == 1 and any("xlsx" in e for e in js.get("parse_errors", [])),
              f"{jerr} {js.get('parse_errors')}")
        txt = open(os.path.join(out, "ps_extraction_summary.txt"), encoding="utf-8").read()
        check("ps_extraction_summary.txt shows the error", "ps_timeline.xlsx write failed" in txt)
        line = next((ln for ln in txt.splitlines() if "ps_timeline.xlsx" in ln and "Excel" in ln), "")
        check("...and marks the workbook as not written", "NOT WRITTEN" in line, line)
    finally:
        ex.write_csv_timeline = real
        shutil.rmtree(out, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
