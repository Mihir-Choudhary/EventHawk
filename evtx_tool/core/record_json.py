"""Read a pyevtx-rs record's JSON without losing repeated names (Codex FO-1).

An event can carry several elements with the same name -- System 1046 has one
``<Data Name="Files">`` per file.  pyevtx-rs writes those as one JSON object
with the key repeated, and every JSON reader keeps only the last value: on a
real System log 83 Files values were read as 27, in every view and export.

``load_record()`` keeps them all.  The fast reader (orjson) is used as before;
a repeat is detected by counting key tokens (``":`` -- serde writes every key as
``"name":``) in the EventData / UserData part of the text against the keys the
parsed object holds.  Only when the text holds more (a repeat, or a value that
merely contains ``":``) is the record read again keeping every pair: a repeated
name becomes a list of its values, in document order.  Records without repeats
come out exactly as before.
"""
from __future__ import annotations

import json

from evtx_tool.core._json_compat import fast_loads


def _nkeys(o) -> int:
    if isinstance(o, dict):
        return len(o) + sum(_nkeys(v) for v in o.values())
    if isinstance(o, list):
        return sum(_nkeys(v) for v in o)
    return 0


def _keep_repeats(pairs):
    out: dict = {}
    repeated: set = set()
    for k, v in pairs:
        if k not in out:
            out[k] = v
        elif k in repeated:
            out[k].append(v)
        else:
            out[k] = [out[k], v]
            repeated.add(k)
    return out


# <System> children that are plain values, but which pyevtx-rs renders as
# {"#attributes": {...}, "#text": value} when the tag carries attributes.
_SYSTEM_SCALARS = ("Level", "Task", "Opcode", "Keywords", "Version",
                   "Channel", "Computer")


def unwrap_system_scalars(system):
    """Return *system* with attributed scalar tags replaced by their #text.

    Without this, an attributed Level read as 4 (Information) whatever it
    was, and Computer / Channel / Keywords stayed dicts (Gemini audit
    1-08).  The input is not modified; it is returned as is when nothing
    needs unwrapping (the normal case: no record in the corpus has one).
    """
    if not isinstance(system, dict):
        return system
    out = None
    for k in _SYSTEM_SCALARS:
        v = system.get(k)
        if isinstance(v, dict):
            if out is None:
                out = dict(system)
            t = v.get("#text")
            if t is None:
                out.pop(k, None)
            else:
                out[k] = t
    return system if out is None else out


def pick_payload(event):
    """The event's data: <EventData>, or <UserData> when EventData is empty.

    "EventData or UserData" picked an <EventData Name="..."/> that carries
    only attributes (a non-empty dict) and threw the populated <UserData>
    away; a scalar payload was dropped (Gemini audit 1-09).  Returns a dict;
    a scalar payload (or a bare #text) is kept under "Data".
    """
    for key in ("EventData", "UserData"):
        v = event.get(key)
        if isinstance(v, dict):
            if any(not str(k).startswith("#") for k in v):
                return v
            if v.get("#text") not in (None, ""):
                return {"Data": v["#text"]}
        elif v not in (None, ""):
            return {"Data": v}
    # Another payload section: Windows writes <ProcessingErrorData> (ErrorCode,
    # DataItemName, EventPayload) when the provider's template does not fit the
    # data, and the schema also allows BinaryEventData / DebugData.  Reading
    # only EventData / UserData showed such an event with no data at all (931
    # records in the test corpus, AppLocker among them).  Kept under the
    # section's own name, so it reads as what it is: data Windows did not render.
    if isinstance(event, dict):
        for key, v in event.items():
            if key in ("System", "RenderingInfo", "EventData", "UserData") or str(key).startswith("#"):
                continue
            if v not in (None, "", {}):
                return {key: v}
    return {}


def load_record(raw):
    """The record dict for pyevtx-rs JSON text *raw* (str or bytes), keeping
    every value of a repeated name (as a list, in order)."""
    data = fast_loads(raw)
    text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
    for name in ("EventData", "UserData"):
        i = text.find(f'"{name}":')
        if i < 0:
            continue
        ev = data.get("Event") if isinstance(data, dict) else None
        sub = ev.get(name) if isinstance(ev, dict) else None
        # Key tokens from this section to the end of the text, against the
        # keys this section (plus its own key) parses to.  Anything after it in
        # the text only adds tokens, so a miss can only cost a slower re-read.
        if text.count('":', i) > 1 + _nkeys(sub):
            return json.loads(text, object_pairs_hook=_keep_repeats)
    return data
