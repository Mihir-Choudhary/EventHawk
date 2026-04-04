"""
PowerShell forensic extraction — script block fragment reassembler.

Groups EID 4104 records by ScriptBlockId and reassembles multi-fragment
script blocks in correct MessageNumber order.
"""

from __future__ import annotations

import logging

from .constants import ZERO_GUID
from .models import ScriptBlockAccumulator, ScriptFragment

logger = logging.getLogger(__name__)


def _safe_int(val, default: int = 0) -> int:
    """Convert to int, returning *default* on failure (empty str, non-numeric)."""
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def build_script_block_index(
    events_4104: list[dict],
) -> dict[str, ScriptBlockAccumulator]:
    """
    First pass: group all EID 4104 records by ScriptBlockId.

    Special cases handled:
    - Duplicate MessageNumber for same ScriptBlockId: keep the longer text
    - Zero GUID (00000000-...): degenerate single-fragment; keyed as
      "{zero_guid}_{record_id}" to prevent incorrect cross-event grouping
    - Empty ScriptBlockId: logged and skipped

    Returns:
        dict mapping ScriptBlockId (or synthetic key) → ScriptBlockAccumulator
    """
    index: dict[str, ScriptBlockAccumulator] = {}

    for ev in events_4104:
        sbid = ev.get("script_block_id", "")
        if not sbid:
            logger.debug(
                "EID 4104 record %s: empty ScriptBlockId — skipping",
                ev.get("event_record_id", "?"),
            )
            continue

        record_id = int(ev.get("event_record_id", 0))

        # Zero GUID: degenerate block — do not group across events
        if sbid == ZERO_GUID:
            key = f"{sbid}_{record_id}"
        else:
            key = sbid

        if key not in index:
            index[key] = ScriptBlockAccumulator(
                script_block_id=sbid,
                path=ev.get("path", ""),
                computer=ev.get("computer", ""),
            )

        acc = index[key]

        # Update path if this fragment has it and the accumulator doesn't
        path = ev.get("path", "")
        if path and not acc.path:
            acc.path = path

        msg_num = ev.get("message_number", 1)
        msg_total = ev.get("message_total", 1)

        if msg_num in acc.fragments:
            # Duplicate: same ScriptBlockId + MessageNumber seen twice.
            # Keep the fragment with longer text (less likely to be truncated).
            existing = acc.fragments[msg_num]
            new_text = ev.get("script_block_text", "")
            if len(new_text) > len(existing.text):
                logger.debug(
                    "ScriptBlockId %s fragment %d duplicated — keeping longer text",
                    sbid, msg_num,
                )
                acc.fragments[msg_num] = ScriptFragment(
                    message_number=msg_num,
                    message_total=msg_total,
                    text=new_text,
                    timestamp=ev.get("timestamp", ""),
                    record_id=record_id,
                    level=_safe_int(ev.get("level", 5), default=5),
                    pid=ev.get("pid", ""),
                    activity_id=ev.get("activity_id", ""),
                    channel=ev.get("channel", ""),
                )
            # else: keep existing (longer)
        else:
            acc.fragments[msg_num] = ScriptFragment(
                message_number=msg_num,
                message_total=msg_total,
                text=ev.get("script_block_text", ""),
                timestamp=ev.get("timestamp", ""),
                record_id=record_id,
                level=_safe_int(ev.get("level", 5), default=5),
                pid=ev.get("pid", ""),
                activity_id=ev.get("activity_id", ""),
                channel=ev.get("channel", ""),
            )

    logger.debug(
        "build_script_block_index: %d unique script blocks from %d EID 4104 events",
        len(index), len(events_4104),
    )
    return index


def classify_accumulators(
    index: dict[str, ScriptBlockAccumulator],
) -> tuple[list[ScriptBlockAccumulator], list[ScriptBlockAccumulator]]:
    """
    Classify accumulators into complete and partial (missing fragments).

    Returns:
        (complete_list, partial_list)
    """
    complete: list[ScriptBlockAccumulator] = []
    partial: list[ScriptBlockAccumulator] = []

    for acc in index.values():
        if not acc.fragments:
            continue
        if acc.is_complete:
            complete.append(acc)
        else:
            partial.append(acc)

    return complete, partial
