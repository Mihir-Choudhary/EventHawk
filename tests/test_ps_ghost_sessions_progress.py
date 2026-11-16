"""PowerShell outputs agree on metadata-less sessions, and progress never goes back.

Gemini audit 9-08 (High), remaining parts:
1. a "ghost" session (an EID 400 with no HostId, host name or command
   line) was left out of ps_commands.txt and the JSON but written to
   ps_timeline.xlsx, and the summary's session count did not say how many
   such sessions there were;
2. the script-block step reported progress up to 0.92, then the summary
   step reported 0.86: the bar went backwards.

Expected: the xlsx leaves the ghost out like the other exports; the summary
says 1 session without metadata; progress values never decrease.
Synthetic records.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_ps_extraction_fields import block                        # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def classic(rid, blk, pid, ts):
    data = {"Event": {
        "System": {"EventID": {"#attributes": {"Qualifiers": 0}, "#text": 400}, "EventRecordID": rid,
                   "Channel": "Windows PowerShell", "Computer": "C1",
                   "TimeCreated": {"#attributes": {"SystemTime": ts}},
                   "Execution": {"#attributes": {"ProcessID": pid, "ThreadID": 1}}},
        "EventData": {"Data": {"#text": ["Available", "None", blk]}}}}
    return {"event_record_id": rid, "timestamp": ts, "data": json.dumps(data)}


def sb(rid, i, ts):
    data = {"Event": {"System": {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104,
                                 "Computer": "C1", "Level": 5, "EventRecordID": rid,
                                 "TimeCreated": {"#attributes": {"SystemTime": ts}}},
                      "EventData": {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": f"Get-Date {i}",
                                    "ScriptBlockId": "{%08d-1111-1111-1111-111111111111}" % i, "Path": ""}}}
    return {"event_record_id": rid, "timestamp": ts, "data": json.dumps(data)}


def main() -> int:
    from openpyxl import load_workbook
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor
    recs = [classic(1, block("powershell.exe -c Get-Date", host_id="HID-REAL"), 100, "2024-01-02T03:04:05.000000Z"),
            classic(2, "\tNewEngineState=Available\r\n", 200, "2024-01-02T03:05:05.000000Z")]   # ghost: nothing
    recs += [sb(10 + i, i, "2024-01-02T03:06:%02d.000000Z" % i) for i in range(30)]
    out = tempfile.mkdtemp(prefix="ps_ghost_")
    try:
        x = PSExtractor(recs, out)
        pcts = []
        x.progress_callback = lambda step, pct: pcts.append(pct) if pct >= 0 else None
        s = x.run()
        check("the summary says how many sessions have no metadata", s.get("sessions_without_metadata") == 1,
              str({k: s.get(k) for k in ("sessions", "sessions_without_metadata")}))
        ws = load_workbook(os.path.join(out, "ps_timeline.xlsx")).active
        rows = [[c for c in r] for r in ws.iter_rows(values_only=True)]
        hdr = rows[0]
        sid_col = next((i for i, h in enumerate(hdr) if h and "session" in str(h).lower()), None)
        ghost = [r for r in rows[1:] if sid_col is not None and str(r[sid_col] or "").startswith("_pid")]
        check("the xlsx leaves the metadata-less session out, like ps_commands and the JSON",
              sid_col is not None and not ghost, f"col={sid_col} ghost rows={len(ghost)}")
        back = [(a, b) for a, b in zip(pcts, pcts[1:]) if b < a]
        check("progress never goes back", not back, str(back[:3]))
    finally:
        shutil.rmtree(out, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
