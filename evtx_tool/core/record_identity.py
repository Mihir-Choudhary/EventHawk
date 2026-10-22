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
    first: dict[tuple, dict] = {}
    copies: dict[int, list[dict]] = {}
    out: list[dict] = []
    for ev in events:
        ident = record_identity(ev)
        if ident is None:
            out.append(ev)
            continue
        kept = first.get(ident)
        if kept is None:
            first[ident] = ev
            out.append(ev)
        else:
            copies.setdefault(id(kept), []).append(ev)
    return out, copies
