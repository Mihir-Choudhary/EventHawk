"""Custom-column expressions (Event Log Explorer style) evaluate exactly.

User (2026-11-01): "Value: the field to extract from the event's full XML ...
{EventID}, {TimeCreated[SystemTime]} (attribute in brackets), {Data[LogonType]}
or {Data[IpAddress]} (by name), {Data[3]} (by index)."  Spec item 4: a value is
a template (literal text plus tokens), {Data[n]} counts from 1, a System field
EventHawk does not keep is refused with "EventHawk does not keep <name>", a
kept field an event lacks gives an empty value, optional Event ID / Provider
filters, Text or Integer type.  One evaluator (evtx_tool.core.custom_columns)
serves both modes.  Synthetic events only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


LOGON = {"record_id": 77, "event_record_id": 77, "event_id": 4624, "timestamp": "2024-05-14T10:11:12.345678Z", "channel": "Security",
         "provider": "Microsoft-Windows-Security-Auditing", "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
         "event_source_name": "", "computer": "WS01", "level": 0, "task": 12544, "opcode": 0,
         "keywords": "0x8020000000000000", "version": 2, "process_id": 668, "thread_id": 1234,
         "correlation_id": "{AAAA}", "user_id": "S-1-5-18", "qualifiers": None,
         "event_data": {"SubjectUserSid": "S-1-5-18", "TargetUserName": "alice", "TargetDomainName": "CORP",
                        "LogonType": "3", "IpAddress": "10.1.2.3", "ProcessId": "0x29c"}}
UNNAMED = {"event_id": 7036, "provider": "Service Control Manager", "channel": "System",
           "event_data": {"Data": {"#text": ["Windows Update", "running", "770075"]}}}
USERDATA = {"event_id": 1102, "provider": "Microsoft-Windows-Eventlog", "channel": "Security",
            "event_data": {"LogFileCleared": {"SubjectUserName": "bob", "SubjectDomainName": "CORP"}}}


def main() -> int:
    from evtx_tool.core.custom_columns import (CustomColumnError, CustomColumnSpec, compile_spec,
                                               field_catalog, int_sort_key)

    def col(template, **kw):
        return compile_spec(CustomColumnSpec(col_id=1, title="T", template=template, **kw))

    def val(template, ev, **kw):
        return col(template, **kw).value(ev)

    check("{EventID}", val("{EventID}", LOGON) == "4624")
    check("{TimeCreated[SystemTime]} is the raw UTC time", val("{TimeCreated[SystemTime]}", LOGON) == LOGON["timestamp"])
    check("{Provider[Name]} / {Provider[Guid]}",
          val("{Provider[Name]} {Provider[Guid]}", LOGON) == f"{LOGON['provider']} {LOGON['provider_guid']}")
    check("{Execution[ProcessID]}, {Security[UserID]}, {EventRecordID}, {Computer}",
          val("{Execution[ProcessID]}|{Security[UserID]}|{EventRecordID}|{Computer}", LOGON) == "668|S-1-5-18|77|WS01")
    check("System names are case-insensitive", val("{eventid}", LOGON) == "4624")
    check("{Data[LogonType]} by name", val("{Data[LogonType]}", LOGON) == "3")
    check("{Data[3]} counts from 1 in document order", val("{Data[3]}", LOGON) == "CORP")
    check("{Data[n]} on unnamed <Data> elements", val("{Data[2]}", UNNAMED) == "running")
    check("a nested UserData leaf by name", val("{Data[SubjectUserName]}", USERDATA) == "bob")
    check("{UserData[Name]} is the same lookup", val("{UserData[SubjectDomainName]}", USERDATA) == "CORP")
    check("a template with literal text and a backslash (DOMAIN\\user)",
          val("{Data[TargetDomainName]}\\{Data[TargetUserName]}", LOGON) == "CORP\\alice")
    check("{{ and }} write literal braces", val("{{{EventID}}}", LOGON) == "{4624}")
    odd = dict(LOGON, event_data={"Cmd": "x {Data[1]} }} {{ C:\\path\\{a}"})
    check("a value holding braces and backslashes is shown exactly as found",
          val("[{Data[Cmd]}]", odd) == "[x {Data[1]} }} {{ C:\\path\\{a}]")
    check("a field the event does not have is empty", val("{Data[NoSuchField]}", LOGON) == "")
    check("an index past the end is empty", val("{Data[40]}", LOGON) == "")
    check("a template whose every field is missing is empty, not its literal text",
          val("user: {Data[TargetUserName]}", UNNAMED) == "")

    def refused(template, needle):
        try:
            col(template)
        except CustomColumnError as exc:
            return needle in str(exc)
        return False
    check("a System field EventHawk does not keep is refused by name",
          refused("{Correlation[RelatedActivityID]}", "EventHawk does not keep Correlation[RelatedActivityID]"))
    check("{Execution[ProcessorID]} is refused", refused("{Execution[ProcessorID]}", "does not keep"))
    check("{Data[0]} is refused (indexes start at 1)", refused("{Data[0]}", "1"))
    check("an unclosed brace is refused", refused("{Data[LogonType]", "brace"))
    check("an unknown bare name is refused with a hint", refused("{LogonType}", "{Data[LogonType]}"))

    c = col("{Data[LogonType]}", eid_expr="4624,4625", providers=("microsoft-windows-security-auditing",))
    check("Event ID + provider filter: a matching event gets a value", c.value(LOGON) == "3")
    check("...a non-matching event ID gets nothing", c.value(dict(LOGON, event_id=4634)) == "")
    check("...a non-matching provider gets nothing", c.value(dict(LOGON, provider="Other")) == "")
    c2 = col("{Data[LogonType]}", eid_expr="4600-4700!4634")
    check("Event ID ranges and ! excludes", c2.value(LOGON) == "3" and c2.value(dict(LOGON, event_id=4634)) == "")

    c3 = col("{Data[LogonType]} {Data[Nope]}")
    for ev in (LOGON, LOGON, UNNAMED):
        c3.value(ev)
    check("hits count the events each field was found in",
          c3.hits.get("{Data[LogonType]}") == 2 and not c3.hits.get("{Data[Nope]}"), str(dict(c3.hits)))

    order = sorted(["100", "abc", "0x10", "9", "", "-2"], key=int_sort_key)
    check("Integer sort: decimal and 0x hex by value, other text after, empty last",
          order == ["-2", "9", "0x10", "100", "abc", ""], str(order))

    cat = field_catalog(LOGON)
    tokens = [t for t, _label, _v in cat]
    check("the field picker lists System fields then EventData by name",
          tokens[:2] == ["{EventID}", "{TimeCreated[SystemTime]}"] and "{Data[LogonType]}" in tokens
          and tokens.index("{Data[LogonType]}") > tokens.index("{Computer}"), str(tokens[:6]))
    check("...each with its value", dict((t, v) for t, _l, v in cat)["{Data[IpAddress]}"] == "10.1.2.3")
    check("...and EventData items show their 1-based index",
          any(t == "{Data[LogonType]}" and "#4" in lab for t, lab, _v in cat), str([l for t, l, v in cat if "LogonType" in t]))
    ucat = field_catalog(UNNAMED)
    check("unnamed <Data> elements are offered by index",
          [t for t, _l, _v in ucat if t.startswith("{Data")] == ["{Data[1]}", "{Data[2]}", "{Data[3]}"],
          str([t for t, _l, _v in ucat]))

    ok = sum(1 for _n, c_, _d in CHECKS if c_)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c_, d in CHECKS:
        if not c_:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
