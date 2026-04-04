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
import re


# ── Low-level field extractors ────────────────────────────────────────────────

def extract_eventdata(event: dict) -> dict[str, str]:
    """
    Normalise all three EventData shapes into a flat {name: value} dict.
    Returns empty dict on any parse failure.
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

    # Shape B: single raw key=value string
    if isinstance(raw, str):
        result: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                result[k.strip()] = v.strip()
        return result

    # Shape C: flat dict keyed by field name
    if isinstance(raw, dict):
        result: dict[str, str] = {k: str(v) for k, v in raw.items() if not k.startswith("#")}
        # Fallback: pyevtx-rs sometimes stores the entire classic-channel key=value
        # block as the "#text" pseudo-key of the EventData dict (e.g. Windows PowerShell
        # EID 400/403/600/800). The filter above strips it, leaving an empty result.
        # Detect this case and parse the text as Shape B.
        if not result:
            text = raw.get("#text", "")
            if text and isinstance(text, str):
                for line in text.splitlines():
                    if "=" in line:
                        k, _, v = line.partition("=")
                        k = k.strip()
                        if k:
                            result[k] = v.strip()
        return result

    # Shape A: list of {"#attributes": {"Name": ...}, "#text": ...}
    # Also handles a pyevtx-rs variant seen on the classic "Windows PowerShell"
    # channel where the entire key=value block is wrapped in a single un-named
    # list element: [{"#text": "HostName=ConsoleHost\nHostId=...\n..."}].
    # In that case name == "" so we fall back to parsing #text as Shape B.
    if isinstance(raw, list):
        result = {}
        for item in raw:
            if not isinstance(item, dict):
                # Bare string in list — treat as Shape B line
                if isinstance(item, str) and "=" in item:
                    k, _, v = item.partition("=")
                    k = k.strip()
                    if k:
                        result[k] = v.strip()
                continue
            attrs = item.get("#attributes", {})
            name = attrs.get("Name", "")
            value = item.get("#text", "")
            if name:
                result[name] = value if value is not None else ""
            elif value and isinstance(value, str):
                # Un-named item with text — parse as embedded Shape B string
                for line in value.splitlines():
                    if "=" in line:
                        k, _, v = line.partition("=")
                        k = k.strip()
                        if k:
                            result[k] = v.strip()
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
        ...
    """
    result: dict[str, str] = {}
    for line in ctx.splitlines():
        line = line.strip()
        if "=" in line:
            k, _, v = line.partition("=")
            result[k.strip()] = v.strip()
    return result


def _extract_encoded_command(host_app: str) -> str:
    """
    Detect and decode -EncodedCommand / -enc / -ec parameter from HostApplication.
    PowerShell encodes the command as UTF-16LE base64.
    Returns decoded string or "" if not found.
    """
    if not host_app:
        return ""
    m = re.search(
        r'(?:-EncodedCommand|-enc|-ec)\s+([A-Za-z0-9+/=]{4,})',
        host_app,
        re.IGNORECASE,
    )
    if not m:
        return ""
    b64 = m.group(1)
    # Pad to multiple of 4
    pad = (4 - len(b64) % 4) % 4
    try:
        decoded_bytes = base64.b64decode(b64 + "=" * pad)
        return decoded_bytes.decode("utf-16-le", errors="replace")
    except Exception:
        return f"[decode_failed:{b64[:50]}]"


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
        "new_engine_state":  ed.get("NewEngineState", ""),
        "prev_engine_state": ed.get("PreviousEngineState", ""),
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
        "runspace_id":       runspace_id.strip("{}"),
        "new_engine_state":  ed.get("NewEngineState", ""),
        "prev_engine_state": ed.get("PreviousEngineState", ""),
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
        "provider_name":      ed.get("ProviderName", ""),
        "new_provider_state": ed.get("NewProviderState", ""),
        "host_id":            host_id.strip("{}"),
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

    return {
        "event_id":        800,
        "timestamp":       ts,
        "pid":             ex.get("ProcessID", ""),
        "computer":        get_system_field(record, "Computer"),
        "host_id":         host_id.strip("{}"),
        "runspace_id":     runspace_id.strip("{}"),
        "pipeline_id":     ed.get("PipelineId", ed.get("PipelineID", "")),
        "command_name":    ed.get("CommandName", ""),
        "command_type":    ed.get("CommandType", ""),
        "command_line":    ed.get("CommandLine", ""),
        "script_name":     ed.get("ScriptName", ""),
        "user_id":         ed.get("UserId", ed.get("UserID", "")),
        "sequence_number": ed.get("SequenceNumber", ""),
        "detail_sequence": ed.get("DetailSequence", ""),
        "detail_total":    ed.get("DetailTotal", ""),
        "event_record_id": record.get("_record_id", 0),
        "channel":         get_system_field(record, "Channel"),
    }
