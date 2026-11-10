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
