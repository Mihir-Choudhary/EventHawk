"""
PowerShell forensic extraction — PSExtractor main pipeline.

Pure Python, no Qt dependencies. Designed to be called from PSWorker.run().

Input:
    records: Iterable[dict] of raw pyevtx-rs record dicts:
             {"event_record_id": int, "timestamp": str, "data": str|dict}
    output_dir: Path — must exist and be writable
    source_files: list[str] — file paths for summary header

Output (written to output_dir):
    ps_commands.txt
    scriptblock_<GUID>.txt  × N
    ps_extraction_summary.txt
    ps_extraction.json
    ps_timeline.xlsx

Returns:
    Summary dict for display in GUI completion dialog.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Callable, Iterable

from .constants import ALL_PS_CHANNELS, RELEVANT_EVENT_IDS
from .content_analysis import analyze_script_block
from .event_parsers import (
    parse_400, parse_403, parse_4103, parse_4104, parse_600, parse_800,
)
from .models import ContentAnalysisResult, ScriptBlockAccumulator
from .reassembler import build_script_block_index
from .session_builder import build_sessions
from .writer import (
    write_commands_file, write_csv_timeline,
    write_json_export, write_scriptblock_files, write_summary,
)

logger = logging.getLogger(__name__)

# EID → parser function mapping
_PARSERS = {
    4103: parse_4103,
    4104: parse_4104,
    400:  parse_400,
    403:  parse_403,
    600:  parse_600,
    800:  parse_800,
}


class PSExtractor:
    """
    Main PowerShell forensic extraction pipeline.

    Usage:
        extractor = PSExtractor(records, output_dir, source_files)
        extractor.progress_callback = lambda step, pct: ...
        extractor.cancel_check = lambda: False
        summary = extractor.run()

    ``records`` may be any Iterable[dict] — a list, a generator, or any
    lazy sequence.  The pipeline consumes it in a single pass (L3: streaming).
    """

    def __init__(
        self,
        records: Iterable[dict],
        output_dir: Path,
        source_files: list[str] | None = None,
        total_hint: int = 0,
    ) -> None:
        self.records = records
        self.output_dir = Path(output_dir)
        self.source_files: list[str] = source_files or []
        # total_hint: used for progress % when records is a generator
        self.total_hint: int = total_hint
        self.progress_callback: Callable[[str, float], None] = lambda s, p: None
        self.cancel_check: Callable[[], bool] = lambda: False
        self._errors: list[str] = []

    def _emit(self, step: str, pct: float) -> None:
        try:
            self.progress_callback(step, pct)
        except Exception:
            pass

    def _is_cancelled(self) -> bool:
        try:
            return self.cancel_check()
        except Exception:
            return False

    def run(self) -> dict:
        """
        Execute the full extraction pipeline.
        Returns summary dict.
        """
        self._emit("Scanning events for PowerShell telemetry...", 0.0)

        # Step 1: Classify and parse PS events — O(n) single pass (0.0 → 0.25)
        # Uses total_hint for progress %; falls back to event-count reporting
        buckets, total = self._classify_events()
        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 2: Build session timeline from 400/403/600/800 (0.25 → 0.40)
        self._emit("Reconstructing PowerShell sessions...", 0.25)
        sessions = build_sessions(buckets)
        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 3: Reassemble script blocks from 4104 fragments (0.40 → 0.55)
        self._emit("Reassembling script block fragments...", 0.40)
        sb_index = build_script_block_index(buckets.get(4104, []))
        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 4: Content analysis on all assembled blocks (0.55 → 0.70)
        self._emit("Running content analysis on script blocks...", 0.55)
        analysis_results = self._analyze_all_blocks(sb_index)
        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 5: Write ps_commands.txt (0.70 → 0.76)
        self._emit("Writing ps_commands.txt...", 0.70)
        try:
            write_commands_file(
                sessions=sessions,
                buckets=buckets,
                sb_index=sb_index,
                analysis_results=analysis_results,
                output_path=self.output_dir / "ps_commands.txt",
                source_files=self.source_files,
            )
        except Exception as exc:
            self._errors.append(f"ps_commands.txt write failed: {type(exc).__name__}: {exc}")
            logger.error("write_commands_file failed", exc_info=True)

        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 6: Write scriptblock_<GUID>.txt files (0.76 → 0.86)
        self._emit("Writing script block files...", 0.76)
        try:
            write_scriptblock_files(
                sb_index=sb_index,
                analysis_results=analysis_results,
                output_dir=self.output_dir,
                progress_cb=self._emit,
                errors=self._errors,
            )
        except Exception as exc:
            self._errors.append(f"scriptblock files write failed: {type(exc).__name__}: {exc}")
            logger.error("write_scriptblock_files failed", exc_info=True)

        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 7: Write summary (0.86 → 0.91)
        self._emit("Writing extraction summary...", 0.86)
        summary = {}
        try:
            summary = write_summary(
                buckets=buckets,
                sb_index=sb_index,
                sessions=sessions,
                analysis_results=analysis_results,
                output_path=self.output_dir / "ps_extraction_summary.txt",
                source_files=self.source_files,
                total_scanned=total,
                errors=self._errors,
            )
        except Exception as exc:
            self._errors.append(f"ps_extraction_summary.txt write failed: {type(exc).__name__}: {exc}")
            logger.error("write_summary failed", exc_info=True)
            from .reassembler import classify_accumulators
            _complete, _partial = classify_accumulators(sb_index)
            real_sessions = [s for s in sessions if s.host_id != "_unsessioned"]
            summary = {
                "total_scanned":   total,
                "total_ps_events": sum(len(v) for v in buckets.values()),
                "script_blocks":   len(sb_index),
                "sessions":        len(real_sessions),
                "partial_blocks":  len(_partial),
                "safety_net":      sum(1 for a in sb_index.values() if a.was_safety_net_triggered),
                "ps_core_blocks":  0,
                "parse_errors":    len(self._errors),
            }

        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 8: Write ps_extraction.json (0.91 → 0.96)
        self._emit("Writing ps_extraction.json...", 0.91)
        try:
            write_json_export(
                sessions=sessions,
                sb_index=sb_index,
                analysis_results=analysis_results,
                summary=summary,
                output_path=self.output_dir / "ps_extraction.json",
                source_files=self.source_files,
                errors=self._errors,
            )
        except Exception as exc:
            self._errors.append(f"ps_extraction.json write failed: {type(exc).__name__}: {exc}")
            logger.error("write_json_export failed", exc_info=True)

        if self._is_cancelled():
            return self._cancelled_summary(total)

        # Step 9: Write ps_timeline.xlsx (0.96 → 1.00)
        self._emit("Writing ps_timeline.xlsx...", 0.96)
        try:
            write_csv_timeline(
                sessions=sessions,
                output_path=self.output_dir / "ps_timeline.xlsx",
                sb_index=sb_index,
            )
        except Exception as exc:
            self._errors.append(f"ps_timeline.xlsx write failed: {type(exc).__name__}: {exc}")
            logger.error("write_csv_timeline failed", exc_info=True)

        self._emit("PowerShell extraction complete.", 1.0)
        logger.info(
            "PSExtractor done: scanned=%d ps_events=%d script_blocks=%d errors=%d",
            total,
            summary.get("total_ps_events", 0),
            summary.get("script_blocks", 0),
            len(self._errors),
        )
        return summary

    def _classify_events(self) -> tuple[dict[int, list[dict]], int]:
        """
        Single-pass O(n) scan: filter by channel, parse by EID.

        L3: Accepts self.records as any Iterable — list, generator, or lazy
        sequence. Uses self.total_hint for progress % if provided; otherwise
        emits indeterminate progress (pct stays at ~0.0–0.25 range without
        a denominator). Returns (buckets, total_scanned).
        """
        buckets: dict[int, list[dict]] = {
            4103: [], 4104: [], 400: [], 403: [], 600: [], 800: [],
        }
        total = 0
        total_hint = self.total_hint
        CHUNK = max(1, total_hint // 20) if total_hint > 0 else 50_000
        # Track which source files actually yielded PS-relevant events so we can
        # report only those files in headers rather than every loaded EVTX.
        seen_files: set[str] = set()

        for i, raw in enumerate(self.records):
            if self._is_cancelled():
                break

            total += 1

            if i % CHUNK == 0:
                if total_hint > 0:
                    pct = min((i / total_hint) * 0.25, 0.24)
                    self._emit(f"Scanning events ({i:,}/{total_hint:,})...", pct)
                else:
                    # No total hint — emit indeterminate-style progress
                    self._emit(f"Scanning events ({i:,} processed)...", -0.05)

            try:
                data = raw.get("data")
                if isinstance(data, str):
                    try:
                        data = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                if not isinstance(data, dict):
                    continue

                sys_data = data.get("Event", {}).get("System", {})

                # Extract channel
                channel_raw = sys_data.get("Channel", "")
                channel = channel_raw if isinstance(channel_raw, str) else str(channel_raw)
                if channel not in ALL_PS_CHANNELS:
                    continue

                # This record is from a PS channel — record its source file.
                src = raw.get("_source_file", "")
                if src:
                    seen_files.add(src)

                # Extract EventID (may be nested dict or plain int/str)
                eid_raw = sys_data.get("EventID", 0)
                if isinstance(eid_raw, dict):
                    eid_val = eid_raw.get("#text", eid_raw.get("Value", 0))
                else:
                    eid_val = eid_raw
                try:
                    eid = int(eid_val)
                except (ValueError, TypeError):
                    continue

                if eid not in RELEVANT_EVENT_IDS:
                    continue

                # Shallow-copy to avoid mutating input record dict
                data = dict(data)
                data["_record_id"] = raw.get("event_record_id", 0)

                parser = _PARSERS.get(eid)
                if parser:
                    parsed = parser(data)
                    if parsed:  # parsers return {} on malformed records
                        buckets[eid].append(parsed)

            except Exception as exc:
                rid = raw.get("event_record_id", "?")
                self._errors.append(f"record {rid}: {exc}")

        # Trim source_files to only files that actually contained PS events,
        # preserving original order. Falls back to full list if nothing was tagged
        # (e.g., records came from a source that didn't set _source_file).
        if seen_files:
            self.source_files = [f for f in self.source_files if f in seen_files]

        return buckets, total

    def _analyze_all_blocks(
        self,
        sb_index: dict[str, ScriptBlockAccumulator],
    ) -> dict[str, ContentAnalysisResult]:
        """
        Run content analysis on every assembled script block.
        Returns dict: key → ContentAnalysisResult.
        """
        results: dict[str, ContentAnalysisResult] = {}
        total = len(sb_index)
        if total == 0:
            return results

        chunk = max(1, total // 10)
        for i, (key, acc) in enumerate(sb_index.items()):
            if self._is_cancelled():
                break
            if i % chunk == 0:
                pct = 0.55 + (i / total) * 0.15
                self._emit(f"Analysing script blocks ({i}/{total})...", pct)
            try:
                assembled = acc.assemble()
                results[key] = analyze_script_block(assembled)
            except Exception as exc:
                self._errors.append(f"content_analysis for {key}: {exc}")

        return results

    @staticmethod
    def _cancelled_summary(total: int = 0) -> dict:
        return {
            "total_scanned":   total,
            "total_ps_events": 0,
            "script_blocks":   0,
            "sessions":        0,
            "partial_blocks":  0,
            "safety_net":      0,
            "ps_core_blocks":  0,
            "parse_errors":    0,
            "cancelled":       True,
        }
