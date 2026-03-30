"""
EVTX Parser — Core parsing module.

Backend: pyevtx-rs (evtx.PyEvtxParser) — Rust-speed, ~91K records/sec.

Worker-safe: all functions are module-level and picklable for ProcessPoolExecutor.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Generator, Iterator

from evtx_tool.core._json_compat import fast_loads

logger = logging.getLogger(__name__)

# ── Backend detection ─────────────────────────────────────────────────────────

try:
    from evtx import PyEvtxParser as _RustParser  # type: ignore
    BACKEND = "rust"
except ImportError:
    _RustParser = None
    BACKEND = "none"

if BACKEND == "none":
    raise ImportError(
        "pyevtx-rs not found.\n"
        "Install with:  pip install evtx"
    )

# ── Level mappings ─────────────────────────────────────────────────────────────

LEVEL_NAMES: dict[int, str] = {
    0: "LogAlways",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}

LEVEL_COLORS: dict[int, str] = {
    0: "white",
    1: "bold red",
    2: "red",
    3: "yellow",
    4: "green",
    5: "dim white",
}

# ── Event extraction ──────────────────────────────────────────────────────────

def _extract_from_json(data: dict, record_id: int, timestamp: str, source_file: str) -> dict:
    """Extract structured fields from a pyevtx-rs JSON record dict."""
    event = data.get("Event", {})
    system = event.get("System", {})

    provider_attrs = system.get("Provider", {})
    if isinstance(provider_attrs, dict):
        attrs = provider_attrs.get("#attributes", {})
        provider_name = attrs.get("Name", "")
        provider_guid = attrs.get("Guid", "")
    else:
        provider_name = ""
        provider_guid = ""

    time_created = system.get("TimeCreated", {})
    if isinstance(time_created, dict):
        ts_str = time_created.get("#attributes", {}).get("SystemTime", timestamp)
    else:
        ts_str = timestamp

    event_data_raw = event.get("EventData") or event.get("UserData") or {}
    event_data: dict = {}
    if isinstance(event_data_raw, dict):
        event_data = {k: v for k, v in event_data_raw.items() if not k.startswith("#")}

    security = system.get("Security")
    user_id = ""
    if isinstance(security, dict):
        user_id = security.get("#attributes", {}).get("UserID", "")

    level = system.get("Level", 4)
    if not isinstance(level, int):
        try:
            level = int(level)
        except (ValueError, TypeError):
            level = 4

    event_id_raw = system.get("EventID", 0)
    qualifiers = None
    if isinstance(event_id_raw, dict):
        # {"#text": N, "#attributes": {"Qualifiers": Q}}
        qualifiers = event_id_raw.get("#attributes", {}).get("Qualifiers")
        event_id_raw = event_id_raw.get("#text", 0) or event_id_raw.get("Value", 0)
    try:
        event_id = int(event_id_raw)
    except (ValueError, TypeError):
        event_id = 0

    execution = system.get("Execution", {})
    exec_attrs = execution.get("#attributes", {}) if isinstance(execution, dict) else {}

    correlation = system.get("Correlation", {})
    correlation_id = ""
    if isinstance(correlation, dict):
        correlation_id = correlation.get("#attributes", {}).get("ActivityID", "")

    return {
        "record_id":      record_id,
        "event_id":       event_id,
        "qualifiers":     qualifiers,
        "timestamp":      ts_str,
        "channel":        system.get("Channel", ""),
        "provider":       provider_name,
        "provider_guid":  provider_guid,
        "computer":       system.get("Computer", ""),
        "level":          level,
        "level_name":     LEVEL_NAMES.get(level, str(level)),
        "task":           system.get("Task", 0),
        "opcode":         system.get("Opcode", 0),
        "keywords":       system.get("Keywords", ""),
        "version":        system.get("Version", 0),
        "process_id":     exec_attrs.get("ProcessID"),
        "thread_id":      exec_attrs.get("ThreadID"),
        "correlation_id": correlation_id,
        "user_id":        user_id,
        "event_data":     event_data,
        "source_file":    source_file,
    }


# ── Public parsing interface ──────────────────────────────────────────────────

def iter_events(filepath: str) -> Generator[dict, None, None]:
    """Parse an EVTX file using pyevtx-rs. Yields event dicts."""
    parser = _RustParser(filepath)
    for record in parser.records_json():
        try:
            data = fast_loads(record["data"])
            yield _extract_from_json(data, record["event_record_id"], record["timestamp"], filepath)
        except Exception as exc:
            logger.debug("Skipping malformed record %s in %s: %s", record.get("event_record_id"), filepath, exc)


def event_to_text(event: dict) -> str:
    """Convert event to searchable flat text string."""
    parts = [
        str(event.get("event_id", "")),
        event.get("channel", ""),
        event.get("provider", ""),
        event.get("computer", ""),
        event.get("level_name", ""),
        event.get("user_id", ""),
    ]
    ed = event.get("event_data", {})
    if isinstance(ed, dict):
        parts.extend(str(v) for v in ed.values() if v is not None)
    return " ".join(parts).lower()


def count_records(filepath: str) -> int:
    """Count total records in an EVTX file."""
    return sum(1 for _ in _RustParser(filepath).records())


def get_backend() -> str:
    return BACKEND
