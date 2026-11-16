"""PowerShell History reads records as the parse engines do.

Gemini audit 9-05 (High): the extractor decoded records with json.loads,
so a <Data> name logged twice kept only its LAST value (the engines keep
every value: core.record_json.load_record); and PSWorker never ran the
engines' chunk salvage (records after a corrupt chunk were not examined)
nor the truncated-file check.

Expected: a repeated HostId keeps its first value and shows all values; a
read that stops part-way is continued by the chunk salvage, whose records
are extracted; a truncated file is reported.  Synthetic records; the
salvage and truncation helpers are stubbed to see that they are used.
"""
import json
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_ps_history_reading as H                                 # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor
    import tempfile
    import shutil
    # A 4103 whose ContextInfo-free EventData repeats a name (as pyevtx-rs
    # renders two <Data Name="HostId">): JSON text with a duplicate key.
    text = ('{"Event": {"System": {"Channel": "Windows PowerShell", "EventID": 400, "Computer": "C1", '
            '"EventRecordID": 5, "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:05.000000Z"}}, '
            '"Execution": {"#attributes": {"ProcessID": 9, "ThreadID": 1}}}, '
            '"EventData": {"HostId": "99999999-8888-7777-6666-555555555555", "HostId": "11111111-2222-3333-4444-555555555555", '
            '"HostApplication": "powershell.exe"}}}')
    out = tempfile.mkdtemp(prefix="ps_rr_")
    try:
        PSExtractor([{"event_record_id": 5, "timestamp": "2024-01-02T03:04:05.000000Z", "data": text}], out).run()
        js = json.load(open(os.path.join(out, "ps_extraction.json"), encoding="utf-8"))
        hids = [s.get("host_id") for s in js.get("sessions", [])]
        check("a repeated HostId keeps its first value (one session)",
              hids == ["99999999-8888-7777-6666-555555555555"], str(hids))
    finally:
        shutil.rmtree(out, ignore_errors=True)
    from evtx_tool.analysis.ps_extractor.event_parsers import extract_eventdata
    ed = extract_eventdata({"Event": {"EventData": {"HostId": ["a", "b"]}}})
    check("...and the field shows every value", ed.get("HostId") == "a" and "b" in ed.get("HostId (all values)", ""), str(ed))

    # PSWorker: a read that stops after one record; salvage gives one more.
    import evtx_tool.core.chunk_salvage as cs
    import evtx_tool.core.parser as cp
    calls = {}

    def fake_salvage(path, already_emitted=None, chunk_indices=None):
        calls["salvage"] = path
        yield H._ps_record(2)
        return {"chunks_unrecoverable": 1, "records_unreadable": 0}

    real = (cs.salvage_records_json, cp.check_evtx_truncation)
    cs.salvage_records_json = fake_salvage
    cp.check_evtx_truncation = lambda p: "header declares 9 chunks, the file holds 3"
    try:
        s, _txt, _err = H.run_worker({"a.evtx": [H._ps_record(1), "RAISE"]}, ["a.evtx"])
    finally:
        cs.salvage_records_json, cp.check_evtx_truncation = real
    s = s or {}
    msgs = " | ".join(s.get("error_messages", []))
    check("the chunk salvage continues after the read stopped", calls.get("salvage") == "a.evtx", str(calls))
    check("...and its record is extracted (2 script blocks)", s.get("script_blocks") == 2, str(s.get("script_blocks")))
    check("the truncated file is reported", "9 chunks" in msgs, msgs[:200])
    check("the unrecoverable chunk is reported", "unrecoverable" in msgs.lower() or "could not be recovered" in msgs.lower(), msgs[:300])
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
