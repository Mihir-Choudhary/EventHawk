"""PowerShell export: full values in the JSON, -EncodedCommand decoded on every channel, numbers do not crash.

Gemini audit 9-01 (High): ps_extraction.json left out a 4103's payload,
user_data and host application, and a 4100/4102's payload and user_data,
though the workbook cuts long cells and points to the JSON for the whole
value.
Gemini audit 9-02 (High): -EncodedCommand was decoded only from a classic
EID 400, so a PowerShell 7 (PowerShellCore) 4103 or an Operational-only
collection never had it decoded, and ps_commands.txt did not even show a
4103's host application.
Gemini audit 9-06 (High): a 4104 whose ScriptBlockText pyevtx-rs gives as a
JSON number made assembling the block raise, which stopped ps_commands.txt,
the JSON and every later script-block file.

Expected: all of those.  Synthetic records.
"""
import base64
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
CORE = "PowerShellCore/Operational"
OP = "Microsoft-Windows-PowerShell/Operational"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ctx_rec(rid, eid, channel, host_app, payload, user_data, ts):
    ctx = (f"        Severity = Informational\r\n        Host Name = ConsoleHost\r\n"
           f"        Host Application = {host_app}\r\n        Command Name = Get-Date\r\n"
           f"        Command Type = Cmdlet\r\n        Script Name = \r\n        User = D\\u\r\n")
    data = {"Event": {"System": {"Channel": channel, "EventID": eid, "Computer": "C1", "EventRecordID": rid,
                                 "TimeCreated": {"#attributes": {"SystemTime": ts}},
                                 "Execution": {"#attributes": {"ProcessID": 77, "ThreadID": 1}}},
                      "EventData": {"Data": [{"#attributes": {"Name": "ContextInfo"}, "#text": ctx},
                                             {"#attributes": {"Name": "UserData"}, "#text": user_data},
                                             {"#attributes": {"Name": "Payload"}, "#text": payload}]}}}
    return {"event_record_id": rid, "timestamp": ts, "data": json.dumps(data)}


def sb_rec(rid, text, sbid, ts):
    data = {"Event": {"System": {"Channel": OP, "EventID": 4104, "Computer": "C1", "Level": 5, "EventRecordID": rid,
                                 "TimeCreated": {"#attributes": {"SystemTime": ts}}},
                      "EventData": {"Data": [{"#attributes": {"Name": "MessageNumber"}, "#text": 1},
                                             {"#attributes": {"Name": "MessageTotal"}, "#text": 1},
                                             {"#attributes": {"Name": "ScriptBlockText"}, "#text": text},
                                             {"#attributes": {"Name": "ScriptBlockId"}, "#text": sbid},
                                             {"#attributes": {"Name": "Path"}, "#text": ""}]}}}
    return {"event_record_id": rid, "timestamp": ts, "data": json.dumps(data)}


def main() -> int:
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor
    enc = base64.b64encode("Get-Date -Format o".encode("utf-16-le")).decode()
    host_app = f"pwsh.exe -NoProfile -EncodedCommand {enc}"
    big = "A" * 33126
    recs = [ctx_rec(1, 4103, CORE, host_app, big, "ModuleTelemetry=v1", "2024-01-02T03:04:05.000000Z"),
            ctx_rec(2, 4100, CORE, host_app, "Localized engine error", "EngineErrorContext=acl",
                    "2024-01-02T03:04:06.000000Z"),
            sb_rec(3, 12345, "{aaaaaaaa-1111-1111-1111-111111111111}", "2024-01-02T03:04:07.000000Z"),
            sb_rec(4, "Get-Process", "{bbbbbbbb-1111-1111-1111-111111111111}", "2024-01-02T03:04:08.000000Z")]
    out = tempfile.mkdtemp(prefix="ps_json_")
    try:
        x = PSExtractor(recs, out)
        x.run()
        errs = x.errors if not callable(getattr(x, "errors", None)) else x.errors()
        check("a numeric ScriptBlockText raises nothing", not any("rstrip" in e or "Attribute" in e for e in errs), str(errs))
        files = os.listdir(out)
        check("ps_commands.txt, the JSON and both block files are written",
              {"ps_commands.txt", "ps_extraction.json"} <= set(files)
              and sum(f.startswith("scriptblock_") for f in files) == 2, str(sorted(files)))
        blk = [f for f in files if f.startswith("scriptblock_aaaaaaaa")]
        check("the numeric script text is kept as text", blk and "12345" in open(os.path.join(out, blk[0]), encoding="utf-8").read())
        jp = os.path.join(out, "ps_extraction.json")
        js = json.load(open(jp, encoding="utf-8")) if os.path.exists(jp) else {}
        evs = [e for s in js.get("sessions", []) for e in s.get("events", [])] + js.get("unsessioned_events", js.get("unsessioned", []))
        e4103 = next((e for e in evs if e.get("event_id") == 4103), {})
        e4100 = next((e for e in evs if e.get("event_id") == 4100), {})
        check("JSON 4103: the whole payload, user_data and host application",
              e4103.get("payload") == big and e4103.get("user_data") == "ModuleTelemetry=v1"
              and e4103.get("host_application") == host_app, str(sorted(e4103)))
        check("JSON 4100: payload and user_data", e4100.get("payload") == "Localized engine error"
              and e4100.get("user_data") == "EngineErrorContext=acl", str(sorted(e4100)))
        check("JSON: the PowerShell 7 -EncodedCommand is decoded", e4103.get("encoded_command") == "Get-Date -Format o",
              repr(e4103.get("encoded_command")))
        tp = os.path.join(out, "ps_commands.txt")
        txt = open(tp, encoding="utf-8").read() if os.path.exists(tp) else ""
        check("ps_commands.txt shows the 4103's host application and the decoded command",
              host_app in txt and "Get-Date -Format o" in txt, "")
    finally:
        shutil.rmtree(out, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
