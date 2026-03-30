"""
Drop-in orjson accelerator with stdlib fallback.

Import from here instead of importing json directly in hot paths.

Usage
-----
    from evtx_tool.core._json_compat import fast_loads, fast_dumps

fast_loads
    orjson.loads  if available, else json.loads.
    Accepts both str and bytes (orjson natively accepts both; stdlib
    json.loads also accepts both since Python 3.6+).

fast_dumps
    Wrapper that ALWAYS returns str (never bytes).
    Uses orjson.dumps().decode('utf-8') if available, else json.dumps().

Design notes
------------
* orjson is detected once at module import time (not per call).
* If orjson is absent, one WARNING is logged at import time (never repeated).
* fast_dumps supports the `default` and `indent` kwargs used across this
  codebase.  Only indent=2 is accelerated by orjson (OPT_INDENT_2); any
  other indent value falls back to stdlib to preserve exact output.
* fast_dumps always behaves as ensure_ascii=False (orjson's default).
  The stdlib fallback path matches this.  All call sites in this project
  that previously used ensure_ascii=False are therefore unaffected; call
  sites that relied on the stdlib default of ensure_ascii=True are not
  present in this codebase (verified in Phase 1 audit).
* orjson serialises datetime/UUID/numpy natively, bypassing the default=
  handler for those types.  This differs from stdlib json, which calls
  default() for ALL non-native types.  Consequence: exporters.py's
  export_json (which uses json.dump with default=str and may receive
  datetime objects) is intentionally NOT migrated — see Phase 2 gate test.

Public API
----------
Only two names are exported.  Do NOT import orjson directly elsewhere.
"""

from __future__ import annotations

import json as _json_stdlib
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)

# ── Backend detection (once at import time) ────────────────────────────────────

try:
    import orjson as _orjson  # type: ignore[import]
except ImportError:
    _orjson = None  # type: ignore[assignment]
    logger.warning(
        "orjson not found — falling back to stdlib json "
        "(install orjson>=3.9.0 for ~5x faster parsing)"
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def fast_loads(s: str | bytes) -> Any:
    """
    Deserialise a JSON string or bytes object → Python object.

    Parameters
    ----------
    s : str or bytes
        JSON-encoded data.  Both str and bytes are accepted by both backends.

    Returns
    -------
    dict | list | str | int | float | bool | None
        The deserialised Python value.
    """
    if _orjson is not None:
        return _orjson.loads(s)
    return _json_stdlib.loads(s)


def fast_dumps(
    obj: Any,
    *,
    default: Callable[[Any], Any] | None = None,
    indent: int | None = None,
) -> str:
    """
    Serialise obj → JSON string.  Always returns str, never bytes.

    Parameters
    ----------
    obj : Any
        Python object to serialise (must be JSON-compatible).
    default : callable | None
        Handler for non-serialisable types.  Same signature as stdlib json:
        receives a single value, must return a serialisable value or raise
        TypeError.

        IMPORTANT — orjson difference: orjson calls default() only for types
        it cannot handle natively.  It handles datetime, date, time, UUID, and
        numpy arrays natively, so default() is NOT called for those even if
        provided.  For str/int/float/None/list/dict — the only types present
        in EVTX event dicts — both backends behave identically.

    indent : int | None
        Indentation level for pretty-printing.  Only indent=2 is natively
        supported by orjson (via OPT_INDENT_2); for any other non-None value
        the stdlib backend is used to preserve exact output.

    Returns
    -------
    str
        UTF-8 JSON string.  Non-ASCII characters are never escaped
        (equivalent to ensure_ascii=False in stdlib json).
    """
    if _orjson is not None:
        if indent is not None and indent != 2:
            # orjson only supports indent=2 natively.  Fall through to stdlib
            # for any other indent value so output is correct.
            return _json_stdlib.dumps(
                obj, default=default, indent=indent, ensure_ascii=False
            )

        # Build orjson kwargs — only include keys that differ from defaults
        # to keep the call as lean as possible on the hot path.
        option: int = 0
        if indent == 2:
            option = _orjson.OPT_INDENT_2

        kwargs: dict[str, Any] = {}
        if default is not None:
            kwargs["default"] = default
        if option:
            kwargs["option"] = option

        # orjson.dumps() returns bytes; decode to str for drop-in compatibility.
        return _orjson.dumps(obj, **kwargs).decode("utf-8")

    # ── stdlib fallback ────────────────────────────────────────────────────────
    # ensure_ascii=False matches orjson's default behaviour so that switching
    # backends does not change the byte content of written files.
    return _json_stdlib.dumps(obj, default=default, indent=indent, ensure_ascii=False)


def fast_dumps_bytes(obj: Any) -> bytes:
    """
    Serialize *obj* to raw JSON bytes.

    For SharedMemory / IPC paths where the consumer calls ``fast_loads()``
    on the raw bytes.  Avoids the ``bytes → str → bytes`` round-trip that
    ``fast_dumps()`` would introduce.
    """
    if _orjson is not None:
        return _orjson.dumps(obj)
    return _json_stdlib.dumps(obj, ensure_ascii=False).encode("utf-8")
