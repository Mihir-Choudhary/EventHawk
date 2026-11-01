"""Identity of one physical event record, for collapsing copies of a log.

A collection folder often holds "Security.evtx" next to "Security - Copy.evtx";
loaded together, every record appears once per copy.  The event table shows
each (they are distinct rows from distinct files), but anything that COUNTS
records -- correlation thresholds, IOC occurrence counts -- must count the
record once, or copies fabricate evidence: a brute-force chain from two failed
logons, an IOC seen four times as often as it was.

EventRecordID is unique within a log, so host + channel + event id + exact
timestamp + record id is the same record seen twice.  Two genuinely distinct
events cannot collide: within one log the record id differs, across hosts the
computer differs.  An event with no record id is never treated as a copy.
"""
from __future__ import annotations


def record_identity(ev: dict) -> tuple | None:
    rid = ev.get("record_id")
    if rid is None or str(rid).strip() == "":
        return None
    return (str(ev.get("computer") or "").strip().lower(),
            str(ev.get("channel") or "").strip().lower(),
            str(ev.get("event_id") or ""),
            str(ev.get("timestamp") or "").strip(),
            str(rid).strip())


def collapse_copies(events: list[dict]) -> tuple[list[dict], dict[int, list[dict]]]:
    """Return (events with copies removed, {id(kept event): [its copies]}).

    The first occurrence is kept, in input order.
    """
    # Same identity is a copy only when the payload is the same too.  Two
    # records sharing the identity but not the content are both evidence:
    # collapsing them lost one record's indicators and credited the other's to
    # its file (Codex release audit C1).  They are kept, and logged.  The
    # payload is compared only on an identity collision, so this costs nothing
    # on data without copies.
    first: dict[tuple, list[dict]] = {}
    copies: dict[int, list[dict]] = {}
    out: list[dict] = []
    conflicts = 0
    for ev in events:
        ident = record_identity(ev)
        if ident is None:
            out.append(ev)
            continue
        variants = first.get(ident)
        if variants is None:
            first[ident] = [ev]
            out.append(ev)
            continue
        kept = next((k for k in variants if (k.get("event_data") or {}) == (ev.get("event_data") or {})), None)
        if kept is not None:
            copies.setdefault(id(kept), []).append(ev)
        else:
            variants.append(ev)
            out.append(ev)
            conflicts += 1
    if conflicts:
        import logging
        logging.getLogger(__name__).warning(
            "%d record(s) share host, channel, event ID, time and record ID with another record "
            "but differ in content; kept as separate records, not as copies", conflicts)
    return out, copies
