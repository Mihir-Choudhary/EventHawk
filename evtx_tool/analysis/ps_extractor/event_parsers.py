"""
PowerShell forensic extraction — per-event parsers.

Handles the three EventData shapes emitted by pyevtx-rs:

  Shape A — named list (EID 4103, 4104 from Microsoft-Windows-PowerShell/Operational):
    EventData.Data = [{"#attributes": {"Name": "..."}, "#text": "..."}, ...]

  Shape B — raw key=value string (EID 400, 403, 600, 800 from Windows PowerShell):
    EventData.Data = "HostName=ConsoleHost\\r\\nHostVersion=5.1...\\r\\n..."

  Shape C — flat dict (hybrid, some 4103 variants):
    EventData = {"FieldName": "value", ...}

All parse_NNN() functions take a raw pyevtx-rs record dict (with "data" already
parsed from JSON) and return a normalized flat dict.
"""

from __future__ import annotations

import base64
import unicodedata
import re


# ── Low-level field extractors ────────────────────────────────────────────────

# Field names Windows writes in the classic "Windows PowerShell" log's detail
# block (EID 300/400/403/600/800), one "Name=value" per line.
_CLASSIC_KEYS = frozenset({
    "NewEngineState", "PreviousEngineState", "NewProviderState", "ProviderName",
    "ExceptionClass", "ErrorCategory", "ErrorId", "ErrorMessage", "Severity",
    "SequenceNumber", "DetailSequence", "DetailTotal", "UserId", "UserID",
    "HostName", "HostVersion", "HostId", "HostID", "HostApplication", "EngineVersion",
    "RunspaceId", "RunspaceID", "PipelineId", "PipelineID", "CommandName", "CommandType",
    "ScriptName", "CommandPath", "CommandLine",
})

# Field names in the Operational log's ContextInfo (EID 4100/4103/4104), one
# "Name = value" per line.
_CONTEXT_KEYS = frozenset({
    "Severity", "Host Name", "Host Version", "Host ID", "Host Application", "Engine Version",
    "Runspace ID", "Pipeline ID", "Command Name", "Command Type", "Script Name",
    "Command Path", "Sequence Number", "User", "Connected User", "Shell ID",
})

_FIELD_LINE = re.compile(r"\s*([^=\r\n]+?)\s*=(.*)")


def _parse_fields(text: str, keys: frozenset) -> dict[str, str]:
    """
    Parse a Windows "Name=value" detail block whose values can span lines.

    A line starts a field only if its name is one of *keys* and has not been
    seen yet; any other line continues the field before it.  HostApplication
    holds the whole command line PowerShell was started with, and a command
    passed with -Command can contain newlines and "x=y" lines of its own
    (about a third of EID 400 in the test corpus).  Splitting every line on
    "=" cut those commands short and invented fields from their lines.
    Blank lines inside a value are kept; blank lines after it are not.
    """
    result: dict[str, str] = {}
    current = None
    pending_blank = 0
    for line in str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        m = _FIELD_LINE.match(line)
        name = m.group(1).strip() if m else ""
        if m and name in keys and name not in result:
            result[name] = m.group(2)
            current = name
            pending_blank = 0
        elif current is None:
            continue
        elif not line.strip():
            pending_blank += 1
        else:
            # Kept exactly, spaces included: it is part of the command.
            result[current] += "\n" * (pending_blank + 1) + line
            pending_blank = 0
    return {k: v.strip() for k, v in result.items()}


def _parse_classic_texts(texts: list) -> dict[str, str]:
    """
    EventData of the classic channel as pyevtx-rs gives it: a list of
    unnamed strings, e.g. EID 400 [new state, previous state, detail block],
    EID 800 [command line, detail block, CommandInvocation/ParameterBinding].
    Each string is kept by position as "_0", "_1", ...; the detail block's
    fields are added by name.
    """
    result: dict[str, str] = {}
    for i, t in enumerate(texts):
        s = "" if t is None else str(t)
        result[f"_{i}"] = s
        for k, v in _parse_fields(s, _CLASSIC_KEYS).items():
            result.setdefault(k, v)
    return result


def extract_eventdata(event: dict) -> dict[str, str]:
    """
    Normalise the EventData shapes pyevtx-rs produces into a flat {name: value} dict.
    Returns empty dict on any parse failure.

    The classic "Windows PowerShell" log (EID 400/403/600/800) comes as
    ``{"Data": {"#text": [str, str, str]}}``: a LIST of unnamed strings.  Only a
    single string used to be parsed, so every one of those events came out
    empty -- no HostApplication, no HostId -- on every real log tested.
    """
    try:
        ed = event["Event"]["EventData"]
    except (KeyError, TypeError):
        # Some classic-channel events use UserData instead
        try:
            ed = event["Event"]["UserData"]
        except (KeyError, TypeError):
            return {}

    raw = ed.get("Data", ed) if isinstance(ed, dict) else ed

    # Shape B: a single unnamed string (the classic detail block on its own)
    if isinstance(raw, str):
        return _parse_classic_texts([raw])

    # Shape C: flat dict keyed by field name
    if isinstance(raw, dict):
        result: dict[str, str] = {k: str(v) for k, v in raw.items() if not k.startswith("#")}
        if not result:
            # The classic channel: the unnamed strings are the "#text" of Data,
            # either one string or (what pyevtx-rs actually emits) a list.
            text = raw.get("#text", "")
            if isinstance(text, list):
                return _parse_classic_texts(text)
            if text and isinstance(text, str):
                return _parse_classic_texts([text])
        return result

    # Shape A: list of {"#attributes": {"Name": ...}, "#text": ...}; un-named
    # items (and bare strings) are the classic channel's unnamed strings.
    if isinstance(raw, list):
        result = {}
        unnamed: list = []
        for item in raw:
            if not isinstance(item, dict):
                if isinstance(item, str):
                    unnamed.append(item)
                continue
            attrs = item.get("#attributes", {})
            name = attrs.get("Name", "")
            value = item.get("#text", "")
            if name:
                result[name] = value if value is not None else ""
            elif isinstance(value, str):
                unnamed.append(value)
        for k, v in _parse_classic_texts(unnamed).items():
            result.setdefault(k, v)
        return result

    return {}


def get_system_field(event: dict, field: str) -> str:
    """
    Extract a field from Event.System, handling nested dict variants.
    e.g. EventID may be {"#text": "4104"} or just "4104".
    """
    try:
        val = event["Event"]["System"][field]
    except (KeyError, TypeError):
        return ""
    if val is None:
        return ""
    if isinstance(val, dict):
        # Try common patterns: #text, Value, SystemTime
        for key in ("#text", "Value", "SystemTime"):
            if key in val:
                return str(val[key])
        # #attributes sub-dict
        attrs = val.get("#attributes", {})
        if attrs:
            # Return first value found
            for v in attrs.values():
                return str(v)
        return ""
    return str(val)


def _get_time_created(system: dict) -> str:
    """Extract ISO-8601 timestamp from System.TimeCreated (handles both shapes)."""
    tc = system.get("TimeCreated", {})
    if not isinstance(tc, dict):
        return str(tc) if tc else ""
    # Shape: {"SystemTime": "2024-..."}
    if "SystemTime" in tc:
        return str(tc["SystemTime"])
    # Shape: {"#attributes": {"SystemTime": "2024-..."}}
    attrs = tc.get("#attributes", {})
    if "SystemTime" in attrs:
        return str(attrs["SystemTime"])
    return ""


def _get_execution(system: dict) -> dict[str, str]:
    """Extract ProcessID / ThreadID from System.Execution (handles both shapes)."""
    ex = system.get("Execution", {})
    if not isinstance(ex, dict):
        return {}
    # Flat: {"ProcessID": "1234", "ThreadID": "5678"}
    if "ProcessID" in ex:
        return {"ProcessID": str(ex.get("ProcessID", "")),
                "ThreadID":  str(ex.get("ThreadID", ""))}
    # With #attributes
    attrs = ex.get("#attributes", {})
    return {"ProcessID": str(attrs.get("ProcessID", "")),
            "ThreadID":  str(attrs.get("ThreadID", ""))}


def _get_correlation(system: dict) -> str:
    """Extract ActivityID from System.Correlation."""
    corr = system.get("Correlation", {})
    if not isinstance(corr, dict):
        return ""
    if "ActivityID" in corr:
        return str(corr["ActivityID"])
    attrs = corr.get("#attributes", {})
    return str(attrs.get("ActivityID", ""))


def parse_context_info(ctx: str) -> dict[str, str]:
    """
    Parse the multi-line 'ContextInfo' string from EID 4103 EventData.

    Format (may be locale-dependent, but field names are usually English):
        Severity = Informational
        Host Name = ConsoleHost
        Host Version = 5.1.19041.1
        Host ID = 2c84a7f8-...
        Host Application = powershell.exe -Command ...   (may span lines)
        ...
    A multi-line Host Application keeps all its lines (see _parse_fields).
    """
    return _parse_fields(ctx or "", _CONTEXT_KEYS)


# -EncodedCommand as powershell.exe / pwsh.exe accept it: any unambiguous
# prefix ("-e", "-en", "-enco", ... "-encodedcommand") or "-ec", with "-" or "/".
_ENC_FLAG = re.compile(
    r"(?:^|\s)[-/–—]"
    r"(?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|"
    r"encoded|encode|encod|enco|enc|en|ec|e)"
    r"\s+[\"']?([A-Za-z0-9+/]{8,}={0,2})",
    re.IGNORECASE,
)


def _extract_encoded_command(host_app: str) -> str:
    """
    Detect and decode the -EncodedCommand argument in a command line.

    PowerShell encodes the command as UTF-16LE base64.  Returns the decoded
    command, "" if there is none, or "[not decodable: ...]" when the flag is
    there but its argument is not UTF-16LE base64 -- never a guess.
    """
    if not host_app:
        return ""
    m = _ENC_FLAG.search(host_app)
    if not m:
        return ""
    b64 = m.group(1)
    pad = (4 - len(b64) % 4) % 4
    try:
        raw = base64.b64decode(b64 + "=" * pad, validate=True)
    except Exception:
        return f"[not decodable: {b64[:60]}]"

    def _as_utf8_text(data: bytes) -> str | None:
        # PowerShell only runs UTF-16LE; base64 of UTF-8 text read as UTF-16LE
        # comes out as printable CJK, so recognise it by its bytes instead.
        try:
            u8 = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        ok = sum(1 for c in u8 if c in "\r\n\t" or (c.isprintable() and ord(c) < 0x80))
        return u8 if u8 and ok >= 0.9 * len(u8) else None

    try:
        text = raw.decode("utf-16-le")
    except UnicodeDecodeError:
        text = ""
    # Junk shows up as control characters (other than tab/CR/LF), unassigned
    # or private-use code points and lone surrogates -- in any script.  The
    # older rule (90% below U+2000) also rejected real CJK commands (Codex
    # release audit C6).
    bad = sum(1 for c in text
              if c not in "\r\n\t" and unicodedata.category(c) in ("Cc", "Cn", "Co", "Cs"))
    if text and bad <= 0.1 * len(text):
        latin = sum(1 for c in text if c in "\r\n\t" or ord(c) < 0x2000)
        if latin >= 0.9 * len(text):
            return text
        u8 = _as_utf8_text(raw)
        if u8 is not None:
            return f"[not UTF-16LE, so PowerShell could not have run it; as UTF-8: {u8}]"
        return text
    u8 = _as_utf8_text(raw)
    if u8 is not None:
        return f"[not UTF-16LE, so PowerShell could not have run it; as UTF-8: {u8}]"
    return f"[not decodable: {b64[:60]}]"


# ── Per-event-ID parsers ──────────────────────────────────────────────────────

def parse_4104(record: dict) -> dict:
    """
    EID 4104 — Script Block Logging (Shape A).
    Channel: Microsoft-Windows-PowerShell/Operational or PowerShellCore/Operational
    """
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ed = extract_eventdata(record)
    ts = _get_time_created(sys)
    ex = _get_execution(sys)

    msg_num_raw = ed.get("MessageNumber", "1") or "1"
    msg_tot_raw = ed.get("MessageTotal", "1") or "1"
    try:
        msg_num = int(msg_num_raw)
    except (ValueError, TypeError):
        msg_num = 1
    try:
        msg_tot = int(msg_tot_raw)
    except (ValueError, TypeError):
        msg_tot = 1

    level_raw = sys.get("Level", "5")
    try:
        level = int(level_raw) if not isinstance(level_raw, int) else level_raw
    except (ValueError, TypeError):
        level = 5

    sbid = ed.get("ScriptBlockId", "")
    # Normalise GUID: strip braces if present
    sbid = sbid.strip("{}").lower() if sbid else ""

    return {
        "event_id":          4104,
        "timestamp":         ts,
        "pid":               ex.get("ProcessID", ""),
        "tid":               ex.get("ThreadID", ""),
        "activity_id":       _get_correlation(sys),
        "computer":          get_system_field(record, "Computer"),
        "level":             level,
        "message_number":    msg_num,
        "message_total":     msg_tot,
        "script_block_text": ed.get("ScriptBlockText", ""),
        "script_block_id":   sbid,
        "path":              ed.get("Path", ""),
        "event_record_id":   record.get("_record_id", 0),
        "channel":           get_system_field(record, "Channel"),
    }


def parse_4103(record: dict) -> dict:
    """
    EID 4103 — Module Logging / Parameter Binding (Shape A).
    Channel: Microsoft-Windows-PowerShell/Operational or PowerShellCore/Operational
    """
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ed = extract_eventdata(record)
    ts = _get_time_created(sys)
    ex = _get_execution(sys)

    ctx_raw = ed.get("ContextInfo", "")
    ctx = parse_context_info(ctx_raw)

    return {
        "event_id":       4103,
        "timestamp":      ts,
        "pid":            ex.get("ProcessID", ""),
        "computer":       get_system_field(record, "Computer"),
        "host_id":        ctx.get("Host ID", ""),
        "runspace_id":    ctx.get("Runspace ID", ""),
        "pipeline_id":    ctx.get("Pipeline ID", ""),
        "command_name":   ctx.get("Command Name", ""),
        "command_type":   ctx.get("Command Type", ""),
        "script_name":    ctx.get("Script Name", ""),
        "host_application": ctx.get("Host Application", ""),
        "sequence_number": ctx.get("Sequence Number", ""),
        "user":           ctx.get("User", ""),
        "user_data":      ed.get("UserData", ""),
        "payload":        ed.get("Payload", ""),
        "event_record_id": record.get("_record_id", 0),
        "channel":        get_system_field(record, "Channel"),
    }


def parse_4100(record: dict) -> dict:
    """
    EID 4100 — "Error Message = ..." (Shape C, like 4103).
    Channel: Microsoft-Windows-PowerShell/Operational or PowerShellCore/Operational

    A PowerShell error: the command that failed, the script, the user and the
    host application that ran it.  A blocked or failed attacker command often
    leaves only this event.
    """
    return _parse_context_message(record, 4100)


def parse_4102(record: dict) -> dict:
    """
    EID 4102 — a PowerShell warning, written exactly like 4100: ContextInfo
    (with Host Application) plus "Error Message = ..." in Payload.
    """
    return _parse_context_message(record, 4102)


def _parse_context_message(record: dict, event_id: int) -> dict:
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ed = extract_eventdata(record)
    ctx = parse_context_info(ed.get("ContextInfo", ""))
    payload = ed.get("Payload", "") or ""
    err = _parse_fields(payload, frozenset({"Error Message", "Fully Qualified Error ID"}))
    return {
        "event_id":         event_id,
        "timestamp":        _get_time_created(sys),
        "pid":              _get_execution(sys).get("ProcessID", ""),
        "computer":         get_system_field(record, "Computer"),
        "host_id":          ctx.get("Host ID", ""),
        "runspace_id":      ctx.get("Runspace ID", ""),
        "pipeline_id":      ctx.get("Pipeline ID", ""),
        "command_name":     ctx.get("Command Name", ""),
        "command_type":     ctx.get("Command Type", ""),
        "script_name":      ctx.get("Script Name", ""),
        "host_application": ctx.get("Host Application", ""),
        "user":             ctx.get("User", ""),
        "error_message":    err.get("Error Message", ""),
        "error_id":         err.get("Fully Qualified Error ID", ""),
        "payload":          payload,
        "user_data":        ed.get("UserData", ""),
        "event_record_id":  record.get("_record_id", 0),
        "channel":          get_system_field(record, "Channel"),
    }


def parse_53504(record: dict) -> dict:
    """
    EID 53504 — "Windows PowerShell has started an IPC listening thread on
    process: <param1> in AppDomain: <param2>".
    Channel: Microsoft-Windows-PowerShell/Operational or PowerShellCore/Operational

    Written when any process loads the PowerShell engine, so it names the
    process that hosted PowerShell even when that is not powershell.exe.
    """
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ed = extract_eventdata(record)
    ex = _get_execution(sys)
    return {
        "event_id":        53504,
        "timestamp":       _get_time_created(sys),
        "pid":             ed.get("param1") or ex.get("ProcessID", ""),
        "computer":        get_system_field(record, "Computer"),
        "app_domain":      ed.get("param2", ""),
        "event_record_id": record.get("_record_id", 0),
        "channel":         get_system_field(record, "Channel"),
    }


def parse_300(record: dict) -> dict:
    """
    EID 300 — a provider or engine error (Shape B, classic log): the message
    first, then the detail block with ExceptionClass, the command that hit it
    and HostApplication.
    Channel: Windows PowerShell
    """
    ed = extract_eventdata(record)
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    host_id = ed.get("HostId", ed.get("HostID", ""))
    return {
        "event_id":         300,
        "timestamp":        _get_time_created(sys),
        "pid":              _get_execution(sys).get("ProcessID", ""),
        "computer":         get_system_field(record, "Computer"),
        "error_message":    ed.get("ErrorMessage") or ed.get("_0", ""),
        "exception_class":  ed.get("ExceptionClass", ""),
        "provider_name":    ed.get("ProviderName", ""),
        "severity":         ed.get("Severity", ""),
        "command_name":     ed.get("CommandName", ""),
        "command_line":     ed.get("CommandLine", ""),
        "script_name":      ed.get("ScriptName", ""),
        "host_id":          host_id.strip("{}"),
        "host_application": ed.get("HostApplication", ""),
        "runspace_id":      ed.get("RunspaceId", ed.get("RunspaceID", "")).strip("{}"),
        "event_record_id":  record.get("_record_id", 0),
        "channel":          get_system_field(record, "Channel"),
    }


def parse_400(record: dict) -> dict:
    """
    EID 400 — Engine Start (Shape B, classic log).
    Channel: Windows PowerShell
    """
    ed = extract_eventdata(record)
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ts = _get_time_created(sys)
    ex = _get_execution(sys)

    host_app = ed.get("HostApplication", "")
    encoded_cmd = _extract_encoded_command(host_app)

    host_id = ed.get("HostId", ed.get("HostID", ""))
    runspace_id = ed.get("RunspaceId", ed.get("RunspaceID", ""))

    # Extract UserID from System.Security (may be nested dict or plain str)
    security = sys.get("Security", {})
    user_sid = ""
    if isinstance(security, dict):
        user_sid = str(security.get("UserID", security.get("#attributes", {}).get("UserID", "")))
    elif isinstance(security, str):
        user_sid = security

    return {
        "event_id":          400,
        "timestamp":         ts,
        "pid":               ex.get("ProcessID", ""),
        "computer":          get_system_field(record, "Computer"),
        "host_name":         ed.get("HostName", ""),
        "host_version":      ed.get("HostVersion", ""),
        "host_id":           host_id.strip("{}"),
        "host_application":  host_app,
        "encoded_command":   encoded_cmd,
        "engine_version":    ed.get("EngineVersion", ""),
        "runspace_id":       runspace_id.strip("{}"),
        "new_engine_state":  ed.get("NewEngineState") or ed.get("_0", ""),
        "prev_engine_state": ed.get("PreviousEngineState") or ed.get("_1", ""),
        "user_sid":          user_sid,
        "event_record_id":   record.get("_record_id", 0),
        "channel":           get_system_field(record, "Channel"),
    }


def parse_403(record: dict) -> dict:
    """
    EID 403 — Engine Stop (Shape B, classic log).
    Channel: Windows PowerShell
    """
    ed = extract_eventdata(record)
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ts = _get_time_created(sys)
    ex = _get_execution(sys)

    host_id = ed.get("HostId", ed.get("HostID", ""))
    runspace_id = ed.get("RunspaceId", ed.get("RunspaceID", ""))

    return {
        "event_id":          403,
        "timestamp":         ts,
        "pid":               ex.get("ProcessID", ""),
        "computer":          get_system_field(record, "Computer"),
        "host_name":         ed.get("HostName", ""),
        "host_version":      ed.get("HostVersion", ""),
        "host_id":           host_id.strip("{}"),
        "host_application":  ed.get("HostApplication", ""),
        "runspace_id":       runspace_id.strip("{}"),
        "new_engine_state":  ed.get("NewEngineState") or ed.get("_0", ""),
        "prev_engine_state": ed.get("PreviousEngineState") or ed.get("_1", ""),
        "event_record_id":   record.get("_record_id", 0),
        "channel":           get_system_field(record, "Channel"),
    }


def parse_600(record: dict) -> dict:
    """
    EID 600 — Provider Start (Shape B, classic log).
    Channel: Windows PowerShell
    """
    ed = extract_eventdata(record)
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ts = _get_time_created(sys)
    ex = _get_execution(sys)

    host_id = ed.get("HostId", ed.get("HostID", ""))
    runspace_id = ed.get("RunspaceId", ed.get("RunspaceID", ""))

    return {
        "event_id":           600,
        "timestamp":          ts,
        "pid":                ex.get("ProcessID", ""),
        "computer":           get_system_field(record, "Computer"),
        "provider_name":      ed.get("ProviderName") or ed.get("_0", ""),
        "new_provider_state": ed.get("NewProviderState") or ed.get("_1", ""),
        "host_id":            host_id.strip("{}"),
        "host_application":   ed.get("HostApplication", ""),
        "runspace_id":        runspace_id.strip("{}"),
        "sequence_number":    ed.get("SequenceNumber", ""),
        "event_record_id":    record.get("_record_id", 0),
        "channel":            get_system_field(record, "Channel"),
    }


def parse_800(record: dict) -> dict:
    """
    EID 800 — Pipeline Execution Details (Shape B, classic log).
    Channel: Windows PowerShell
    """
    ed = extract_eventdata(record)
    try:
        sys = record["Event"]["System"]
    except (KeyError, TypeError):
        return {}
    ts = _get_time_created(sys)
    ex = _get_execution(sys)

    host_id = ed.get("HostId", ed.get("HostID", ""))
    runspace_id = ed.get("RunspaceId", ed.get("RunspaceID", ""))

    # Classic layout: [command line, detail block, details].  The command line
    # is the first string ("Pipeline execution details for command line: %1");
    # the block's own CommandLine= is usually empty.  The third string holds
    # CommandInvocation(...) / ParameterBinding(...) lines: the parameters.
    details = next((ed[k] for k in ("_2", "_0", "_1")
                    if "CommandInvocation(" in ed.get(k, "") or "ParameterBinding(" in ed.get(k, "")), "")
    command_line = ed.get("CommandLine", "")
    first = ed.get("_0", "")
    if first.strip() and first != details and "HostApplication=" not in first:
        command_line = first.strip()
    command_name = ed.get("CommandName", "")
    if not command_name and details:
        m = re.search(r"CommandInvocation\(([^)]*)\)", details)
        command_name = m.group(1) if m else ""

    return {
        "event_id":        800,
        "timestamp":       ts,
        "pid":             ex.get("ProcessID", ""),
        "computer":        get_system_field(record, "Computer"),
        "host_id":         host_id.strip("{}"),
        "host_application": ed.get("HostApplication", ""),
        "runspace_id":     runspace_id.strip("{}"),
        "pipeline_id":     ed.get("PipelineId", ed.get("PipelineID", "")),
        "command_name":    command_name,
        "command_type":    ed.get("CommandType", ""),
        "command_line":    command_line,
        "details":         details,
        "script_name":     ed.get("ScriptName", ""),
        "user_id":         ed.get("UserId", ed.get("UserID", "")),
        "sequence_number": ed.get("SequenceNumber", ""),
        "detail_sequence": ed.get("DetailSequence", ""),
        "detail_total":    ed.get("DetailTotal", ""),
        "event_record_id": record.get("_record_id", 0),
        "channel":         get_system_field(record, "Channel"),
    }
