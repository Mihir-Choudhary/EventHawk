"""The HTML report's search finds words anywhere in an event's data (Codex FO-2).

The report's search reads a prebuilt index (window._SD) that held only the
first 30 event-data fields, each cut to 200 characters: a word further into a
long command line or script block -- shown in the event's detail -- was not
found, and the event was hidden by the search.  Expected: every field, in
full.  Checked on the index the exporter writes into the report.  Synthetic.
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.output.exporters import export_html
    long_val = "x" * 400 + " Zebrafinch " + "y" * 100
    many = {f"F{i:02d}": f"value{i}" for i in range(40)}
    many["F38"] = "Quokkaword"
    evs = [
        {"event_id": 4104, "timestamp": "2024-01-02T03:04:05Z", "provider": "P", "channel": "C",
         "computer": "PC", "record_id": 1, "source_file": "a.evtx", "level_name": "Verbose",
         "event_data": {"ScriptBlockText": long_val}},
        {"event_id": 1, "timestamp": "2024-01-02T03:04:06Z", "provider": "P", "channel": "C",
         "computer": "PC", "record_id": 2, "source_file": "a.evtx", "level_name": "Information",
         "event_data": many},
        {"event_id": 2, "timestamp": "2024-01-02T03:04:07Z", "provider": "P", "channel": "C",
         "computer": "PC", "record_id": 3, "source_file": "a.evtx", "level_name": "Information",
         "event_data": {"Files": ["C:\\one.dll", "C:\\two.dll", "C:\\Lastfile.dll"]}},
    ]
    path = os.path.join(tempfile.mkdtemp(prefix="html_sd_"), "r.html")
    export_html(evs, path)
    txt = open(path, encoding="utf-8").read()
    m = re.search(r"<script>window\._SD=(\[.*?\]);</script>", txt, re.S)
    sd = json.loads(m.group(1)) if m else []
    check("the report holds one search entry per event", len(sd) == 3, str(len(sd)))
    if len(sd) == 3:
        check("a word past character 200 of a value is searchable", "zebrafinch" in sd[0])
        check("a word in the 39th field is searchable", "quokkaword" in sd[1])
        check("every value of a repeated name is searchable", "lastfile.dll" in sd[2])
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
