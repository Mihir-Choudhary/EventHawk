"""
EVTX parser using the ``evtx`` package (pyevtx-rs, Rust backend) -- not the pure-Python ``python-evtx``.

Module: evtx  (lowercase — NOT 'Evtx')
API:    evtx.PyEvtxParser(path).records_json()

records_json() yields one dict per record:
  {
    "event_record_id": int,
    "timestamp":       str,   ← ISO-8601 UTC string
    "data":            str,   ← JSON-serialized event (must be json.loads'd)
  }
Or RuntimeError objects for corrupt records — must check isinstance(record, Exception).

The parsed "data" JSON has this shape:
  {
    "Event": {
      "System": {
        "EventID": 4688,   ← int, or {"#text": int, "#attributes": {...}}
        "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00Z"}},
        "Computer": "HOSTNAME",
        ...
      },
      "EventData": {
        "Data": [{"#attributes": {"Name": "foo"}, "#text": "bar"}, ...]
              or {"foo": "bar", ...}
      }
    }
  }

Targeted event IDs:
  Security log: 4688 (process create), 4689 (process terminate)
  Sysmon:       1 (process create), 5 (process terminate),
                8 (CreateRemoteThread), 10 (ProcessAccess)

Events with other IDs are silently skipped.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from sentinel.models import RawEvent

logger = logging.getLogger(__name__)

_PROCESS_CREATE_IDS    = {4688, 1}
_PROCESS_TERMINATE_IDS = {4689, 5}
_ALL_TARGET_IDS        = {4688, 4689, 1, 5, 8, 10}


def parse_evtx_files(
    paths: list[Path],
    progress_cb: Callable[[str, float], None] | None = None,
) -> list[RawEvent]:
    """Parse a list of .evtx files and return all targeted RawEvents."""
    try:
        import evtx as _evtx_mod
    except ImportError:
        logger.error("evtx (pyevtx-rs) not installed. Install with: pip install evtx")
        return []

    results: list[RawEvent] = []
    total = len(paths)
    total_seen = 0
    total_matched = 0

    for i, path in enumerate(paths):
        if progress_cb:
            progress_cb(f"Parsing {path.name}", i / max(total, 1))
        try:
            seen, matched, events = _parse_single_evtx(path, _evtx_mod)
            total_seen += seen
            total_matched += matched
            results.extend(events)
        except Exception as exc:
            logger.warning("Failed to open %s: %s", path.name, exc)

    logger.info(
        "Parsing complete: %d files, %d total records, %d matched target IDs %s",
        total, total_seen, total_matched, sorted(_ALL_TARGET_IDS),
    )
    if total_seen > 0 and total_matched == 0:
        logger.warning(
            "Parsed %d records but NONE matched target event IDs %s. "
            "Make sure you selected Security.evtx or Sysmon.evtx files "
            "(not Application.evtx, System.evtx, etc.).",
            total_seen, sorted(_ALL_TARGET_IDS),
        )
    results = _collapse_copies(results)
    _warn_unparsed_timestamps(results)
    return results


def hash_evtx_files(paths: list[Path]) -> dict[str, str]:
    """SHA-256 hash a list of EVTX files for forensic chain-of-custody (F11/S5).

    Returns a dict mapping resolved full path → sha256 hex digest.
    B5: Uses full resolved path as key (not basename) to avoid silent
    collisions when multiple files share the same name (e.g. Security.evtx
    from different evidence sources).
    Files that cannot be read are logged and mapped to the string "ERROR".
    """
    result: dict[str, str] = {}
    for path in paths:
        key = str(path.resolve())
        try:
            sha256 = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    sha256.update(chunk)
            result[key] = sha256.hexdigest()
        except OSError as exc:
            logger.warning("Could not hash %s: %s", path.name, exc)
            result[key] = "ERROR"
    return result


# ── Parallel parsing (F4) ──────────────────────────────────────────────────────

def _new_skips() -> dict[str, int]:
    return {"corrupt": 0, "oversize": 0, "unparsed": 0}


def _warn_skipped(name: str, skips: dict[str, int]) -> None:
    """One WARNING per file for records that could not be scored.

    These used to be dropped with no trace (or at DEBUG), so an analyst had
    no way to know the result was built on an incomplete log.
    """
    if any(skips.values()):
        logger.warning(
            "%s: skipped %d corrupt, %d oversized (>1 MB) and %d unparseable "
            "record(s); they are not in this analysis",
            name, skips["corrupt"], skips["oversize"], skips["unparsed"])


def _read_error_text(exc: Exception, seen: int) -> str:
    """Describe a file that could not be read to the end.

    pyevtx-rs can stop part-way through a file (e.g. a damaged chunk).  The
    records read before that point are kept, so say how far it got rather
    than implying nothing was read.
    """
    if seen:
        return (f"{exc} -- stopped after {seen} record(s); the rest of the file "
                f"is not in this analysis")
    return f"{exc} -- no records could be read"


def _parse_path_worker(path_str: str) -> tuple[int, int, list, dict]:
    """Top-level worker function for ProcessPoolExecutor (must be picklable).

    Returns (seen, matched, raw json-serialisable dicts, skip counts) so the
    worker does NOT need to import sentinel.models — avoids pickling RawEvent
    across processes.  Instead we return the raw field dict and reconstruct
    RawEvents in the caller.
    """
    import json as _json
    from datetime import datetime, timezone

    path = Path(path_str)
    records_out: list[dict] = []
    seen = 0
    matched = 0
    skips = _new_skips()

    # Anything logged here stays in the worker process and is never seen, so
    # an open failure travels back in the result for the caller to report.
    try:
        import evtx as _evtx_mod
    except ImportError:
        skips["open_error"] = "evtx (pyevtx-rs) not installed. Install with: pip install evtx"
        return 0, 0, [], skips

    _TARGET_IDS = {4688, 4689, 1, 5, 8, 10}

    try:
        parser = _evtx_mod.PyEvtxParser(str(path))
        for record in parser.records_json():
            if isinstance(record, Exception):
                skips["corrupt"] += 1
                continue
            seen += 1
            try:
                raw_data = record["data"]
                # S3: Guard against JSON bomb — skip records > 1MB
                if len(raw_data) > 1_048_576:
                    skips["oversize"] += 1
                    continue
                data = _json.loads(raw_data)
                # B3: Filter to target event IDs inside worker to avoid
                # serializing/transferring millions of irrelevant records
                event_node = data.get("Event", {})
                system = event_node.get("System", {})
                eid_raw = system.get("EventID", 0)
                eid = int(eid_raw.get("#text", 0) if isinstance(eid_raw, dict) else eid_raw)
                if eid not in _TARGET_IDS:
                    continue
                ts_raw = record.get("timestamp", "")
                records_out.append({"data": data, "ts_raw": ts_raw, "file": path.name,
                                    "rid": record.get("event_record_id")})
                matched += 1
            except Exception:
                skips["unparsed"] += 1
                continue
    except Exception as exc:
        skips["open_error"] = _read_error_text(exc, seen)

    return seen, matched, records_out, skips


def parse_evtx_files_parallel(
    paths: list[Path],
    progress_cb: Callable[[str, float], None] | None = None,
    max_workers: int | None = None,
) -> list[RawEvent]:
    """Parse .evtx files in parallel using ProcessPoolExecutor (F4).

    Falls back to serial parsing for single-file inputs or when
    ProcessPoolExecutor is unavailable (e.g. frozen executables).

    Args:
        paths:       List of .evtx file paths to parse.
        progress_cb: Optional (step_name, 0.0-1.0) callback.
        max_workers: Number of worker processes (default: CPU count).

    Returns:
        List of RawEvents sorted by timestamp.
    """
    if not paths:
        return []

    # For single files or tiny inputs, serial is faster (avoid fork overhead)
    if len(paths) == 1:
        return parse_evtx_files(paths, progress_cb=progress_cb)

    if max_workers is None:
        max_workers = min(len(paths), os.cpu_count() or 1)

    results: list[RawEvent] = []
    retry: list[Path] = []
    total_seen = 0
    total_matched = 0
    completed = 0
    total = len(paths)

    try:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_parse_path_worker, str(p)): p
                for p in paths
            }
            for fut in as_completed(futures):
                path = futures[fut]
                completed += 1
                if progress_cb:
                    progress_cb(f"Parsed {path.name}", completed / total)
                try:
                    seen, matched, records, skips = fut.result()
                except Exception as exc:
                    # A broken pool fails every future, not the executor, so
                    # the serial fallback below never ran: the analysis
                    # "completed" with 0 events.  Re-read such files here.
                    logger.warning("Worker failed for %s (%s); reading it in-process instead",
                                   path.name, exc)
                    retry.append(path)
                    continue
                open_error = skips.pop("open_error", None)
                if open_error:
                    logger.warning("Could not read %s: %s", path.name, open_error)
                total_seen += seen
                total_matched += matched
                # Per record, as in the serial path: one bad record used to
                # abort the rest of the file under a misleading "Worker failed".
                for rec in records:
                    try:
                        ev = _parse_record(rec["data"], rec["ts_raw"])
                        if ev is not None:
                            ev.record_id = _int(str(rec.get("rid") or 0))
                    except Exception as exc:
                        skips["unparsed"] += 1
                        logger.debug("Failed to parse record in %s: %s", path.name, exc)
                        continue
                    if ev is not None:
                        results.append(ev)
                _warn_skipped(path.name, skips)
    except Exception as exc:
        # ProcessPoolExecutor unavailable (e.g. frozen exe) — fall back to serial
        logger.warning("Parallel parsing unavailable (%s); falling back to serial", exc)
        return parse_evtx_files(paths, progress_cb=progress_cb)

    if retry:
        import evtx as _evtx_mod
        for path in retry:
            try:
                seen, matched, events = _parse_single_evtx(path, _evtx_mod)
            except Exception as exc:
                logger.warning("Failed to open %s: %s", path.name, exc)
                continue
            total_seen += seen
            total_matched += matched
            results.extend(events)

    logger.info(
        "Parallel parsing complete: %d files, %d total records, %d matched target IDs %s",
        total, total_seen, total_matched, sorted(_ALL_TARGET_IDS),
    )
    if total_seen > 0 and total_matched == 0:
        logger.warning(
            "Parsed %d records but NONE matched target event IDs %s. "
            "Make sure you selected Security.evtx or Sysmon.evtx files.",
            total_seen, sorted(_ALL_TARGET_IDS),
        )
    results = _collapse_copies(results)
    _warn_unparsed_timestamps(results)
    return results


def _parse_single_evtx(path: Path, evtx_mod) -> tuple[int, int, list[RawEvent]]:
    """Parse one .evtx file. Returns (records_seen, records_matched, events)."""
    events: list[RawEvent] = []
    seen = 0
    matched = 0
    skips = _new_skips()

    parser = evtx_mod.PyEvtxParser(str(path))

    # An error raised by the iterator itself ends the file early.  It used to
    # escape from here and discard every event already read from the file.
    try:
        for record in parser.records_json():
            # records_json() yields dicts OR RuntimeError objects — must check type
            if isinstance(record, Exception):
                skips["corrupt"] += 1
                logger.debug("Corrupt record in %s: %s", path.name, record)
                continue

            seen += 1
            try:
                raw_data = record["data"]
                # S3: Guard against JSON bomb — skip records > 1MB
                if len(raw_data) > 1_048_576:
                    skips["oversize"] += 1
                    logger.warning(
                        "Oversized record in %s (%d bytes) — skipping (potential JSON bomb)",
                        path.name, len(raw_data),
                    )
                    continue
                data = json.loads(raw_data)
                ts_raw = record.get("timestamp", "")
                ev = _parse_record(data, ts_raw)
                if ev is not None:
                    ev.record_id = _int(str(record.get("event_record_id") or 0))
                    matched += 1
                    events.append(ev)
            except Exception as exc:
                skips["unparsed"] += 1
                logger.debug("Failed to parse record in %s: %s", path.name, exc)
    except Exception as exc:
        logger.warning("Could not read %s: %s", path.name, _read_error_text(exc, seen))

    _warn_skipped(path.name, skips)
    return seen, matched, events


def _parse_record(data: dict, ts_raw: str) -> RawEvent | None:
    """
    Parse one decoded records_json() payload into a RawEvent.

    Args:
        data:   json.loads(record["data"]) — the full event dict.
        ts_raw: record["timestamp"]        — top-level ISO-8601 timestamp string.
    """
    event_node = data.get("Event", {})

    # ── System fields ──────────────────────────────────────────────────────────
    system = event_node.get("System", {})

    event_id_raw = system.get("EventID", 0)
    if isinstance(event_id_raw, dict):
        event_id = int(event_id_raw.get("#text", 0) or event_id_raw.get("Value", 0))
    else:
        event_id = int(event_id_raw)

    if event_id not in _ALL_TARGET_IDS:
        return None

    # Timestamp — prefer System/TimeCreated/@SystemTime from the event itself;
    # fall back to the record-level timestamp only if that is absent.
    #
    # This used to be the other way round, and it put EVERY event in the year
    # 0001.  pyevtx-rs formats the record-level timestamp with a trailing " UTC"
    # ("2026-02-17T20:49:12.7246031Z UTC"), which _parse_ts could not read, so
    # each one silently became datetime.min.  Measured on a real Security.evtx:
    # 117 of 117 process-creation events.  The effect was invisible but wide:
    # every reported time was wrong, drift monitoring skipped every event (the
    # rolling window cannot go below year 1, so host_drift was always 0), and
    # lineage tracking -- which relies on time order -- ran in arbitrary order.
    # SystemTime is the authoritative value in the event XML and is clean ISO
    # ("2026-02-17T20:49:12.724603Z"); it is also what EventHawk's own parser
    # uses.
    ts_str = ""
    tc = system.get("TimeCreated", {})
    if isinstance(tc, dict):
        ts_str = tc.get("#attributes", {}).get("SystemTime", "") or ""
    if not ts_str:
        ts_str = ts_raw
    timestamp = _parse_ts(ts_str)

    computer = system.get("Computer", "")

    # ── EventData ──────────────────────────────────────────────────────────────
    event_data_raw = event_node.get("EventData", {})
    d = _flatten_event_data(event_data_raw)

    if event_id == 4688:
        return _from_4688(timestamp, computer, event_id, d)
    elif event_id == 1:
        return _from_sysmon1(timestamp, computer, event_id, d)
    elif event_id == 8:
        return _from_sysmon8(timestamp, computer, event_id, d)
    elif event_id == 10:
        return _from_sysmon10(timestamp, computer, event_id, d)
    else:
        return _from_minimal(timestamp, computer, event_id, d)


def _flatten_event_data(event_data) -> dict[str, str]:
    """
    Normalize EventData into a flat {name: value} dict.

    Handles three shapes pyevtx-rs produces:
      List:  {"Data": [{"#attributes": {"Name": "k"}, "#text": "v"}, ...]}
      Dict:  {"Data": {"k": "v", ...}}
      Flat:  {"k": "v", ...}
    """
    if not event_data:
        return {}

    data_node = event_data.get("Data", event_data)

    if isinstance(data_node, list):
        result = {}
        for item in data_node:
            if isinstance(item, dict):
                name = item.get("#attributes", {}).get("Name", "")
                val  = item.get("#text", "")
                if name:
                    result[name] = str(val) if val is not None else ""
        return result

    if isinstance(data_node, dict):
        return {k: str(v) for k, v in data_node.items() if not k.startswith("#")}

    return {}


def _from_4688(ts: datetime, host: str, eid: int, d: dict) -> RawEvent:
    proc_path   = d.get("NewProcessName", "")
    parent_path = d.get("ParentProcessName", "")
    return RawEvent(
        timestamp=ts, host=host, event_id=eid,
        process_guid="",
        pid=_int(d.get("NewProcessId", "0")),
        ppid=_int(d.get("ProcessId", "0")),
        parent_guid="",
        process_name=_basename(proc_path),
        process_path=proc_path,
        parent_name=_basename(parent_path),
        parent_path=parent_path,
        cmdline=d.get("CommandLine", ""),
        user=d.get("SubjectUserName", ""),
        integrity_level=d.get("MandatoryLabel", ""),
        image_hash="",
    )


def _from_sysmon1(ts: datetime, host: str, eid: int, d: dict) -> RawEvent:
    proc_path   = d.get("Image", "")
    parent_path = d.get("ParentImage", "")
    return RawEvent(
        timestamp=ts, host=host, event_id=eid,
        process_guid=d.get("ProcessGuid", ""),
        pid=_int(d.get("ProcessId", "0")),
        ppid=_int(d.get("ParentProcessId", "0")),
        parent_guid=d.get("ParentProcessGuid", ""),
        process_name=_basename(proc_path),
        process_path=proc_path,
        parent_name=_basename(parent_path),
        parent_path=parent_path,
        cmdline=d.get("CommandLine", ""),
        user=d.get("User", ""),
        integrity_level=d.get("IntegrityLevel", ""),
        image_hash=d.get("Hashes", ""),
    )


def _from_minimal(ts: datetime, host: str, eid: int, d: dict) -> RawEvent:
    proc_path = d.get("Image", d.get("NewProcessName", ""))
    return RawEvent(
        timestamp=ts, host=host, event_id=eid,
        process_guid=d.get("ProcessGuid", ""),
        pid=_int(d.get("ProcessId", "0")),
        ppid=0, parent_guid="",
        process_name=_basename(proc_path),
        process_path=proc_path,
        parent_name="", parent_path="", cmdline="",
        user=d.get("User", d.get("SubjectUserName", "")),
        integrity_level="", image_hash="",
    )


def _from_sysmon8(ts: datetime, host: str, eid: int, d: dict) -> RawEvent:
    """Sysmon EID 8 — CreateRemoteThread.

    B14: Extracts SourceProcessId/SourceImage so lineage tracking and
    PPID spoofing detection work correctly for thread injection events.
    """
    src_path = d.get("SourceImage", "")
    tgt_path = d.get("TargetImage", "")
    return RawEvent(
        timestamp=ts, host=host, event_id=eid,
        process_guid=d.get("SourceProcessGuid", ""),
        pid=_int(d.get("SourceProcessId", "0")),
        ppid=0, parent_guid="",
        process_name=_basename(src_path),
        process_path=src_path,
        parent_name=_basename(tgt_path),
        parent_path=tgt_path,
        cmdline=d.get("StartFunction", ""),
        user=d.get("User", ""),
        integrity_level="", image_hash="",
    )


def _from_sysmon10(ts: datetime, host: str, eid: int, d: dict) -> RawEvent:
    """Sysmon EID 10 — ProcessAccess.

    B14: Extracts SourceProcessId/SourceImage and stores CallTrace in
    cmdline for injection detection via later scoring stages.
    """
    src_path = d.get("SourceImage", "")
    tgt_path = d.get("TargetImage", "")
    return RawEvent(
        timestamp=ts, host=host, event_id=eid,
        process_guid=d.get("SourceProcessGuid", ""),
        pid=_int(d.get("SourceProcessId", "0")),
        ppid=0, parent_guid="",
        process_name=_basename(src_path),
        process_path=src_path,
        parent_name=_basename(tgt_path),
        parent_path=tgt_path,
        cmdline=d.get("CallTrace", ""),
        user=d.get("User", ""),
        integrity_level="", image_hash="",
    )


def _parse_ts(s: str) -> datetime:
    """Parse an ISO-8601 timestamp string into a UTC-aware datetime.

    Preserves fractional seconds (up to microsecond precision) for correct
    sub-second ordering of rapid process spawn chains.  Returns a UTC-aware
    datetime.min on failure so sorting still works without crashing.
    """
    s = s.strip()
    # pyevtx-rs's record-level timestamp carries a trailing " UTC"
    # ("2026-02-17T20:49:12.7246031Z UTC").  Without stripping it the
    # endswith("Z") test below never fires and every such value fell through
    # to datetime.min.  _parse_record now prefers SystemTime, so this is the
    # fallback path -- but it must still work when it is used.
    if s.upper().endswith(" UTC"):
        s = s[:-4].rstrip()
    # Q6: Guard against empty/garbage strings before slicing
    if len(s) < 10:
        return datetime.min.replace(tzinfo=timezone.utc)
    # B6: Normalize ±HHMM (no colon) to ±HH:MM — some EVTX producers
    # emit offsets without the colon, which datetime.fromisoformat rejects.
    s = re.sub(r'([+-])(\d{2})(\d{2})$', r'\1\2:\3', s)
    # Normalize: trailing Z means UTC; replace T separator
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    elif not any(c in s[-6:] for c in ("+", "-")):
        # No timezone info — assume UTC
        s = s.rstrip() + "+00:00"
    s = s.replace("T", " ")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def _collapse_copies(events: list[RawEvent]) -> list[RawEvent]:
    """Drop repeats of the same physical record, keeping the first.

    A folder holding "Security.evtx" and "Security - Copy.evtx" yields every
    record twice.  Sentinel counts records: with the same log four times the
    baseline stability score rose from 0.91 to 0.98 -- the check meant to
    reject a short or compromised baseline is inflated simply by duplicating
    files -- and an analysis reported 468 events scored where 117 exist.
    Identity: host + event id + exact timestamp + EventRecordID (unique
    within a log).  A record without an id (0) is never collapsed.
    """
    seen: set = set()
    out: list[RawEvent] = []
    for ev in events:
        if not ev.record_id:
            out.append(ev)
            continue
        ident = (ev.host.strip().lower(), ev.event_id, ev.timestamp, ev.record_id)
        if ident in seen:
            continue
        seen.add(ident)
        out.append(ev)
    if len(out) != len(events):
        logger.warning(
            "%d record(s) appear in more than one input file (copies of the same "
            "log) and were counted once", len(events) - len(out))
    return out


def _warn_unparsed_timestamps(events: list[RawEvent]) -> None:
    """Report events whose timestamp could not be read, instead of hiding them.

    _parse_ts returns datetime.min on failure so that sorting keeps working.
    That is a reasonable fallback, but on its own it is silent: a whole file
    of unreadable timestamps used to become year 0001 with no trace anywhere,
    which is how every event in a real Security.evtx ended up there unnoticed.
    """
    bad = sum(1 for e in events if e.timestamp.year == 1)
    if bad:
        logger.warning(
            "%d of %d event(s) have an unreadable timestamp and were assigned "
            "0001-01-01. Their reported times, time order (and so lineage), "
            "and drift contribution are NOT reliable.",
            bad, len(events),
        )


def _basename(path: str) -> str:
    return Path(path).name if path else ""


def _int(s) -> int:
    """Parse a decimal integer string. Accepts hex only if prefixed with 0x."""
    try:
        v = str(s).strip()
        # B5: Use base 10 explicitly — Sysmon PIDs are always decimal.
        # Only fall back to auto-detect (base 0) if the string has an explicit
        # 0x or 0o prefix to avoid silently mis-parsing decimal strings.
        if v.startswith(("0x", "0X", "0o", "0O", "0b", "0B")):
            return int(v, 0)
        return int(v, 10)
    except (ValueError, TypeError):
        return 0


# ── File discovery ─────────────────────────────────────────────────────────────

def find_relevant_evtx_files(
    folder: Path,
    progress_cb: Callable[[str, float], None] | None = None,
) -> list[Path]:
    """
    Scan all .evtx files in *folder* (recursively) and return only those
    that contain at least one target event ID (4688/4689/1/5/8/10).

    Performs a complete scan of each file — no record limit.
    Files that cannot be opened are skipped with a warning.
    """
    try:
        import evtx as _evtx_mod
    except ImportError:
        logger.error("evtx (pyevtx-rs) not installed. Install with: pip install evtx")
        return []

    all_evtx = sorted(folder.rglob("*.evtx"))
    # S3: Prevent symlink/junction traversal — only accept files that resolve
    # within the original search folder to avoid evidence contamination.
    resolved_root = folder.resolve()
    all_evtx = [p for p in all_evtx if p.resolve().is_relative_to(resolved_root)]
    if not all_evtx:
        logger.warning("No .evtx files found in: %s", folder)
        return []

    logger.info(
        "Scanning %d EVTX files for target event IDs %s ...",
        len(all_evtx), sorted(_ALL_TARGET_IDS),
    )

    relevant: list[Path] = []
    failed: list[Path] = []
    total = len(all_evtx)
    # B3: Track found_ids per file during first pass to avoid re-scanning
    _file_found_ids: dict[Path, set[int]] = {}

    for i, path in enumerate(all_evtx):
        if progress_cb:
            progress_cb(f"Scanning {path.name}", i / total)
        try:
            found_ids = _scan_file_for_target_ids(path, _evtx_mod)
            _file_found_ids[path] = found_ids
            if found_ids:
                relevant.append(path)
                logger.debug("  + %s — EID %s", path.name, sorted(found_ids))
            else:
                logger.debug("  - %s — no target event IDs", path.name)
        except Exception as exc:
            failed.append(path)
            logger.warning("  ! %s — scan failed: %s", path.name, exc)

    # B3: Count create-event files using cached found_ids — no re-scan needed
    create_ids = {4688, 1}
    create_files = sum(
        1 for p in relevant
        if _file_found_ids.get(p, set()) & create_ids
    )

    logger.info(
        "Scan complete: %d / %d files contain target event IDs (%d failed to open); "
        "%d of %d selected files contain process-creation events (4688/1)",
        len(relevant), total, len(failed), create_files, len(relevant),
    )

    # If every file failed to open and none were relevant, surface a permissions
    # hint by raising so the caller can give a better error message.
    if not relevant and failed and len(failed) == total:
        raise PermissionError(
            f"All {total} EVTX file(s) in the folder failed to open.\n\n"
            "This usually means the files are locked by Windows (live system logs).\n"
            "Fix: run EventHawk as Administrator, or copy the .evtx files to a local "
            "folder first and point Sentinel at the copy."
        )

    return relevant


def _scan_file_for_target_ids(path: Path, evtx_mod) -> set[int]:
    """
    Return the set of target event IDs present in the file.
    Reads the complete file; stops early only when ALL target IDs are confirmed.
    """
    found: set[int] = set()
    parser = evtx_mod.PyEvtxParser(str(path))
    for record in parser.records_json():
        if isinstance(record, Exception):
            continue
        try:
            raw_data = record["data"]
            # B8: JSON bomb guard — same 1MB limit as main parser path
            if len(raw_data) > 1_048_576:
                continue
            data = json.loads(raw_data)
            system = data.get("Event", {}).get("System", {})
            eid_raw = system.get("EventID", 0)
            eid = int(eid_raw.get("#text", 0) if isinstance(eid_raw, dict) else eid_raw)
            if eid in _ALL_TARGET_IDS:
                found.add(eid)
                if found == _ALL_TARGET_IDS:   # found all possible targets — stop early
                    break
        except Exception:
            continue
    return found


# ── Diagnostic helper ──────────────────────────────────────────────────────────

def diagnose_evtx_files(paths: list[Path]) -> dict:
    """
    Scan EVTX files completely and report what event IDs are present.
    Call this when parse_evtx_files() returns 0 events to understand why.

    Returns a dict with top_event_ids, target_ids_found, file_errors.
    """
    try:
        import evtx as _evtx_mod
    except ImportError:
        return {"error": "evtx (pyevtx-rs) not installed. Install with: pip install evtx"}

    from collections import Counter
    id_counts: Counter = Counter()
    file_errors: list[str] = []
    total_records = 0

    for path in paths:
        try:
            parser = _evtx_mod.PyEvtxParser(str(path))
            for record in parser.records_json():
                if isinstance(record, Exception):
                    continue
                try:
                    raw_data = record["data"]
                    # B20: consistent 1MB JSON bomb guard
                    if len(raw_data) > 1_048_576:
                        continue
                    data = json.loads(raw_data)
                    system = data.get("Event", {}).get("System", {})
                    eid_raw = system.get("EventID", 0)
                    eid = int(eid_raw.get("#text", 0) if isinstance(eid_raw, dict) else eid_raw)
                    id_counts[eid] += 1
                    total_records += 1
                except Exception:
                    continue
        except Exception as exc:
            file_errors.append(f"{path.name}: {exc}")

    return {
        "files_scanned": len(paths),
        "total_records_scanned": total_records,
        "top_event_ids": id_counts.most_common(20),
        "target_ids_found": {k: v for k, v in id_counts.items() if k in _ALL_TARGET_IDS},
        "file_errors": file_errors,
        "verdict": (
            "OK — process creation events found"
            if any(k in _ALL_TARGET_IDS for k in id_counts)
            else "NO TARGET IDs FOUND — wrong EVTX files (need Security.evtx or Sysmon.evtx)"
        ),
    }
