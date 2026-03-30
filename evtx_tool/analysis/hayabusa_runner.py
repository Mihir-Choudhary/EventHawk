"""
Hayabusa binary integration — run Hayabusa against EVTX files and parse results.

This module provides:
  - ``find_hayabusa()``     — locate the Hayabusa binary
  - ``run_hayabusa()``      — execute Hayabusa and return parsed detections
  - ``parse_hayabusa_jsonl()`` — convert JSONL output to our chain format

Hayabusa is run via ``subprocess.Popen`` inside the worker subprocess,
so it has zero impact on the GUI process.

Reference: https://github.com/Yamato-Security/hayabusa
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Common install locations ──────────────────────────────────────────────────

_COMMON_PATHS_WIN = [
    r"C:\Tools\hayabusa\hayabusa.exe",
    r"C:\hayabusa\hayabusa.exe",
    r"C:\Program Files\hayabusa\hayabusa.exe",
    os.path.expanduser(r"~\hayabusa\hayabusa.exe"),
    os.path.expanduser(r"~\Desktop\hayabusa\hayabusa.exe"),
    os.path.expanduser(r"~\Downloads\hayabusa\hayabusa.exe"),
]

_COMMON_PATHS_LINUX = [
    "/usr/local/bin/hayabusa",
    "/opt/hayabusa/hayabusa",
    os.path.expanduser("~/.local/bin/hayabusa"),
    os.path.expanduser("~/hayabusa/hayabusa"),
]

# ── Severity mapping ─────────────────────────────────────────────────────────
# Hayabusa levels → our severity strings (matching correlator.py conventions)
_SEVERITY_MAP = {
    "critical": "critical",
    "crit":     "critical",
    "high":     "high",
    "medium":   "medium",
    "med":      "medium",
    "low":      "low",
    "info":     "low",
    "informational": "low",
}


def find_hayabusa(custom_path: str | None = None) -> str | None:
    """
    Locate the Hayabusa binary.

    Priority:
      1. ``custom_path`` (user-configured in settings)
      2. ``PATH`` lookup via ``shutil.which``
      3. Common install directories

    Returns the absolute path to the binary, or ``None`` if not found.
    """
    # 1. User-configured path
    if custom_path and os.path.isfile(custom_path):
        return os.path.abspath(custom_path)

    # 2. PATH lookup
    found = shutil.which("hayabusa")
    if found:
        return os.path.abspath(found)

    # 3. Common locations
    candidates = _COMMON_PATHS_WIN if sys.platform == "win32" else _COMMON_PATHS_LINUX
    for p in candidates:
        if os.path.isfile(p):
            return os.path.abspath(p)

    return None


def run_hayabusa(
    hayabusa_path: str,
    evtx_paths: list[str],
    cancel_event: Any = None,
    min_level: str = "low",
    progress_callback: Any = None,
) -> list[dict]:
    """
    Run Hayabusa against EVTX files and return detections as chain dicts.

    Parameters
    ----------
    hayabusa_path : str
        Absolute path to the Hayabusa binary.
    evtx_paths : list[str]
        EVTX file paths or directories to scan.
    cancel_event : mp.Event or None
        Checked periodically; if set, Hayabusa is terminated.
    min_level : str
        Minimum severity level (low/medium/high/critical).
    progress_callback : callable or None
        Called with status strings for progress updates.

    Returns
    -------
    list[dict]
        Chain dicts compatible with the correlator output format.
    """
    if not hayabusa_path or not os.path.isfile(hayabusa_path):
        logger.warning("Hayabusa binary not found: %s", hayabusa_path)
        return []

    if not evtx_paths:
        return []

    # Determine input: if single file, use -f; if multiple or directory, use -d
    # Build a temp dir with symlinks/copies if needed, or find common parent
    input_arg, input_val, tmp_dir = _resolve_input(evtx_paths)

    # Create temp file for JSONL output
    fd, output_path = tempfile.mkstemp(suffix=".jsonl", prefix="hayabusa_")
    os.close(fd)

    try:
        cmd = [
            hayabusa_path,
            "json-timeline",
            input_arg, input_val,
            "-L",                   # JSONL format (one JSON object per line)
            "-o", output_path,
            "-m", min_level,        # Minimum severity
            "-C",                   # Clobber (overwrite output)
            "--no-wizard",          # Skip interactive wizard
            "-q",                   # Quiet mode (less noise on stderr)
        ]

        if progress_callback:
            progress_callback("Starting Hayabusa scan…")

        logger.info("Running Hayabusa: %s", " ".join(cmd))

        with tempfile.TemporaryFile("w+", encoding="utf-8", prefix="hayabusa_err_") as stderr_file:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_file,
                text=True,
                creationflags=_get_creation_flags(),
            )

            # Wait with cancel check + periodic heartbeat
            heartbeat_counter = 0
            while proc.poll() is None:
                if cancel_event and cancel_event.is_set():
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    logger.info("Hayabusa cancelled by user")
                    return []
                try:
                    proc.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    pass
                # Send heartbeat every ~10 seconds to keep watchdog alive
                heartbeat_counter += 1
                if progress_callback and heartbeat_counter % 5 == 0:
                    elapsed = heartbeat_counter * 2
                    progress_callback(f"Scanning… ({elapsed}s elapsed)")

            returncode = proc.returncode
            if returncode != 0:
                stderr_file.seek(0)
                stderr_text = stderr_file.read()
                logger.warning("Hayabusa exited with code %d: %s", returncode, stderr_text[:500])
                # Hayabusa may still produce partial output — try to parse it

        if progress_callback:
            progress_callback("Parsing Hayabusa results…")

        return parse_hayabusa_jsonl(output_path)

    finally:
        # Cleanup temp files
        try:
            os.unlink(output_path)
        except OSError:
            pass
        if tmp_dir:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except OSError:
                pass


def _resolve_input(evtx_paths: list[str]) -> tuple[str, str, str | None]:
    """
    Resolve EVTX paths into a Hayabusa input argument.

    Returns (flag, value, tmp_dir_or_None):
      - Single file: ("-f", filepath, None)
      - Single directory: ("-d", dirpath, None)
      - Multiple files: ("-d", tmp_dir_with_symlinks, tmp_dir)
    """
    if len(evtx_paths) == 1:
        p = evtx_paths[0]
        if os.path.isdir(p):
            return "-d", p, None
        else:
            return "-f", p, None

    # Check if all files share a common parent directory. Most common case.
    parents = {str(Path(p).parent) for p in evtx_paths if os.path.isfile(p)}
    if len(parents) == 1:
        parent = parents.pop()
        
        # FATAL BUG FIX: If we just return "-d parent", Hayabusa scans ALL .evtx files
        # in that directory, not just the ones the user selected! 
        # Check if the folder contains ONLY our selected files.
        try:
            all_evtx = [f for f in os.listdir(parent) if f.lower().endswith(".evtx")]
        except OSError as _exc:
            logger.warning("Hayabusa: cannot list directory %s: %s", parent, _exc)
            all_evtx = []
            
        if len(all_evtx) == len(evtx_paths):
            # The folder contains exact parity — safe to scan the whole folder
            return "-d", parent, None

        # Unsafe! There are unselected files. We must isolate our selection.
        # Create a temp dir in the SAME directory so we can use Hard Links (os.link).
        # Hard links require no Admin/Dev privileges on Windows and take 0 bytes/0 seconds,
        # but they ONLY work on the same NTFS volume.
        # If the source directory is read-only (e.g., forensic image), this will raise OSError.
        try:
            tmp_dir = tempfile.mkdtemp(prefix=".hayabusa_tmp_", dir=parent)
            for i, src in enumerate(evtx_paths):
                if os.path.isfile(src):
                    dst = os.path.join(tmp_dir, f"{i:04d}_{os.path.basename(src)}")
                    try:
                        os.link(src, dst)  # Instant, 0-byte hard link
                    except OSError:
                        try:
                            os.symlink(src, dst)
                        except OSError:
                            shutil.copy2(src, dst)  # Desperate fallback
            return "-d", tmp_dir, tmp_dir
        except OSError:
            # Fall back to the system %TEMP% directory below
            pass

    # Scattered across multiple drives/dirs or read-only parent -> use generic temp dir in %TEMP%
    tmp_dir = tempfile.mkdtemp(prefix="hayabusa_input_")
    for i, src in enumerate(evtx_paths):
        if os.path.isfile(src):
            dst = os.path.join(tmp_dir, f"{i:04d}_{os.path.basename(src)}")
            try:
                os.symlink(src, dst)
            except OSError:
                # Hard link will fail across-drives, skip directly to copy
                shutil.copy2(src, dst)
        elif os.path.isdir(src):
            for f in Path(src).glob("*.evtx"):
                dst = os.path.join(tmp_dir, f"{i:04d}_{f.name}")
                try:
                    os.symlink(str(f), dst)
                except OSError:
                    shutil.copy2(str(f), dst)

    return "-d", tmp_dir, tmp_dir


def _get_creation_flags() -> int:
    """Return subprocess creation flags for Windows (no console window)."""
    if sys.platform == "win32":
        return subprocess.CREATE_NO_WINDOW  # type: ignore[attr-defined]
    return 0


def parse_hayabusa_jsonl(jsonl_path: str) -> list[dict]:
    """
    Parse Hayabusa JSONL output and convert to our chain dict format.

    Each line in the JSONL file is a detection event. We group related
    detections by rule title + computer to form chains.

    Returns a list of chain dicts matching the correlator.py format::

        {
            "rule_name": str,
            "tactic": str,
            "severity": str,
            "description": str,
            "computers": [str],
            "first_ts": str,
            "last_ts": str,
            "event_count": int,
            "events": [dict],        # original Hayabusa detection records
            "source": "hayabusa",    # distinguishes from correlator chains
        }
    """
    if not os.path.isfile(jsonl_path):
        return []

    # Parse all detections
    detections: list[dict] = []
    try:
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    det = json.loads(line)
                    detections.append(det)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        logger.warning("Failed to read Hayabusa output: %s", exc)
        return []

    if not detections:
        return []

    # Group by (RuleTitle, Computer) → chain
    chains_map: dict[str, dict] = {}
    for det in detections:
        if not isinstance(det, dict):
            logger.debug("Hayabusa: skipping non-dict JSON line (type=%s)", type(det).__name__)
            continue
        rule_title = det.get("RuleTitle", "") or det.get("rule_title", "") or "Unknown Rule"
        computer = det.get("Computer", "") or det.get("computer", "") or "Unknown"
        timestamp = det.get("Timestamp", "") or det.get("timestamp", "") or ""
        level = (det.get("Level", "") or det.get("level", "") or "info").lower()
        mitre = det.get("MitreTactics", "") or det.get("mitre_tactics", "") or ""
        details = det.get("Details", "") or det.get("details", "") or ""

        key = f"{rule_title}|{computer}"
        if key not in chains_map:
            chains_map[key] = {
                "rule_name": f"[Hayabusa] {rule_title}",
                "tactic": mitre if mitre else "Unknown",
                "severity": _SEVERITY_MAP.get(level, "low"),
                "description": details,
                "computers": [computer],
                "first_ts": timestamp,
                "last_ts": timestamp,
                "event_count": 0,
                "events": [],
                "source": "hayabusa",
            }

        chain = chains_map[key]
        chain["event_count"] += 1
        
        # Normalize into standard evtx_tool event schema so the UI can render it.
        # Include original JSON as the 'xml' representation for deep viewing.
        # event_data MUST be a dict (not a str) — models.py filter code calls
        # ed.get(...) on it.  Wrap the details string under a 'Details' key so
        # it remains searchable without breaking the dict contract.
        event_data_dict: dict = {}
        if details:
            event_data_dict["Details"] = details
        normalized_ev = {
            "timestamp": timestamp,
            "event_id": det.get("EventID", 0) or det.get("event_id", 0),
            "level_name": det.get("Level", "") or det.get("level", ""),
            "computer": computer,
            "channel": det.get("Channel", "") or det.get("channel", ""),
            "provider": det.get("Provider", "") or det.get("provider", "Hayabusa"),
            "user_id": det.get("UserId", "") or det.get("user_id", ""),
            "record_id": det.get("RecordID", 0) or det.get("EventRecordID", 0) or det.get("record_id", 0),
            "source_file": det.get("SourceFile", "") or det.get("source_file", ""),
            "task": det.get("Task", 0) or det.get("task", 0),
            "opcode": det.get("Opcode", 0) or det.get("opcode", 0),
            "process_id": det.get("ProcessId", 0) or det.get("process_id", 0),
            "thread_id": det.get("ThreadId", 0) or det.get("thread_id", 0),
            "correlation_id": det.get("CorrelationId", "") or det.get("correlation_id", ""),
            "keywords": det.get("Keywords", "") or det.get("keywords", ""),
            "event_data": event_data_dict,
            "event_data_list": [details] if details else [],
            "xml": json.dumps(det, indent=2),
            "source": "hayabusa",
        }
        
        chain["events"].append(normalized_ev)

        # Update time window
        if timestamp and (not chain["first_ts"] or timestamp < chain["first_ts"]):
            chain["first_ts"] = timestamp
        if timestamp and (not chain["last_ts"] or timestamp > chain["last_ts"]):
            chain["last_ts"] = timestamp

        # Add computer if new
        if computer not in chain["computers"]:
            chain["computers"].append(computer)

    chains = list(chains_map.values())

    # Sort by severity desc, then first_ts asc
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    chains.sort(key=lambda c: (-sev_order.get(c["severity"], 0), c["first_ts"]))

    logger.info("Hayabusa: %d chains from %d detections", len(chains), len(detections))
    return chains
