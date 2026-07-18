"""
Filter engine for EVTX events.

FilterConfig is a plain dict (fully picklable) so it can be sent to
ProcessPoolExecutor worker processes without serialization issues.

Filter fields:
  event_ids          list[int]  | None  — exact IDs to include
  exclude_event_ids  list[int]  | None  — exact IDs to exclude
  sources            list[str]  | None  — provider name or channel substring match
  levels             list[int]  | None  — 0=LogAlways 1=Critical 2=Error 3=Warn 4=Info 5=Verbose
  date_from          str        | None  — ISO timestamp, inclusive
  date_to            str        | None  — ISO timestamp, inclusive
  users              list[str]  | None  — substring match across user fields
  computers          list[str]  | None  — substring match on Computer
  task_categories    list[int]  | None  — exact Task ID match
  text_search        list[str]  | None  — terms to search across all event text
  search_mode        str        — 'AND' | 'OR' | 'NOT'  (default: 'AND')
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Callable

from evtx_tool.core._json_compat import fast_loads, fast_dumps


# ── Values-only searchable-text extraction ────────────────────────────────────
# Text search is VALUES-ONLY (like Event Viewer / Timeline Explorer / Sigma):
# it matches the actual data values an examiner types (a user, IP, SID, path,
# command) — NOT field names.  A single shared extractor is used by BOTH the
# normal-mode search and the Juggernaut ``ed_values`` column so the same query
# returns the same events in either mode, and so search reaches EVERY value in
# the EventData/UserData (including nested and named <Data Name=…> elements),
# not just the handful of pre-extracted metadata columns.

def _walk_searchable_values(obj, out: list) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            # '#attributes' holds field-name labels (e.g. <Data Name="X">), not
            # data values — skip it so search stays values-only.  '#text' IS the
            # element's value and is recursed into normally.
            if k == "#attributes":
                continue
            _walk_searchable_values(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _walk_searchable_values(v, out)
    elif obj is not None:
        out.append(str(obj))


def flatten_searchable_values(event_data) -> list[str]:
    """Return every scalar VALUE in *event_data* (recursively; field names
    excluded).  Shared by normal-mode search and the JM ed_values column."""
    out: list[str] = []
    _walk_searchable_values(event_data, out)
    return out


# ── Flattened field map for field-CONDITIONS (nested-aware) ───────────────────
# Field conditions (Advanced filter / profile "conditions") look a field up by
# NAME.  EventData can nest fields inside a container element (e.g.
# {"RmSessionEvent": {"RmSessionId": 0}}) or use named <Data Name="X"> elements.
# This flattens all of that into one {name: value} map so a condition on a
# nested field name still resolves.  The SAME function feeds normal-mode
# _conditions_pass and the JM ed_flat_json column, so conditions behave
# identically in both modes and never miss a nested field.

def _flatten_fields_into(obj, flat: dict) -> None:
    if not isinstance(obj, dict):
        return
    for k, v in obj.items():
        if isinstance(k, str) and (k.startswith("#") or k.startswith("@")):
            continue  # XML metadata (#text/#attributes/@…), not a field
        if k == "Data" and isinstance(v, list):
            # Named-Data list: [{"#attributes":{"Name":X}, "#text":val}, …]
            for item in v:
                if isinstance(item, dict):
                    nm = (item.get("#attributes") or {}).get("Name")
                    if nm:
                        flat[str(nm)] = item.get("#text", "")
                    else:
                        _flatten_fields_into(item, flat)
        elif isinstance(v, dict):
            # Container element: hoist its #text (if any) under the container
            # name, then recurse so the child fields become top-level entries.
            txt = v.get("#text")
            if txt is not None:
                flat[k] = txt
            _flatten_fields_into(v, flat)
        else:
            flat[k] = v


def flatten_fields(event_data) -> dict:
    """Flatten nested/named EventData into a flat {field_name: value} map for
    field-condition lookups (parity across normal mode and Juggernaut mode)."""
    flat: dict = {}
    _flatten_fields_into(event_data, flat)
    return flat


# ── Event ID expression parser (ELE-style) ────────────────────────────────────

def parse_event_id_expression(expr: str) -> tuple[set[int], set[int]]:
    """
    Parse Event Log Explorer-style event ID expressions.

    Syntax examples:
        ``1-19,100,250-450``   → include IDs 1-19, 100, 250-450
        ``!10,255``            → exclude IDs 10, 255
        ``1-19,100,250-450!10,255``  → include the ranges, but exclude 10 and 255

    Parameters
    ----------
    expr : str
        Raw expression string.

    Returns
    -------
    (include_ids, exclude_ids) : tuple[set[int], set[int]]
        Both sets may be empty.  When *include_ids* is empty it means
        "no include restriction" (all IDs pass unless excluded).
    """
    if not expr or not expr.strip():
        return set(), set()

    # Split on '!' — left part is includes, right parts are excludes
    parts = expr.split("!")
    include_part = parts[0].strip()
    exclude_part = ",".join(parts[1:]).strip() if len(parts) > 1 else ""

    def _parse_ids(s: str) -> set[int]:
        ids: set[int] = set()
        for token in s.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                try:
                    lo, hi = token.split("-", 1)
                    ids.update(range(int(lo.strip()), int(hi.strip()) + 1))
                except (ValueError, TypeError):
                    pass
            else:
                try:
                    ids.add(int(token))
                except ValueError:
                    pass
        return ids

    return _parse_ids(include_part), _parse_ids(exclude_part)


@lru_cache(maxsize=256)
def _parse_eid_expr_cached(expr: str) -> "tuple[frozenset, frozenset]":
    """Memoised parse for the per-event filter path.  passes_filter() runs once
    per event, so re-parsing an expression like "1-65535" (a 65k-element set)
    for every event was O(events x range).  Returns frozensets (immutable) so a
    caller can never corrupt the shared cache entry."""
    inc, exc = parse_event_id_expression(expr)
    return frozenset(inc), frozenset(exc)


def validate_event_id_expression(expr: str) -> list[str]:
    """Return the list of unparseable tokens in ``expr`` (empty when valid).

    Mirrors the token rules of ``parse_event_id_expression`` so the FilterDialog
    can surface a clear error message before silently dropping bad tokens.  A
    token is *invalid* when:

      - it is a range (contains ``-``) whose endpoints are not both integers
      - it is a single value that is not an integer

    Empty / whitespace-only expressions are treated as "no filter" and return
    an empty list (valid).

    Examples
    --------
    >>> validate_event_id_expression("1-19,100,250-450")
    []
    >>> validate_event_id_expression("1=1")
    ['1=1']
    >>> validate_event_id_expression("1-19,abc,100-xyz")
    ['abc', '100-xyz']
    """
    if not expr or not expr.strip():
        return []

    invalid: list[str] = []
    # parse_event_id_expression splits on '!' (left = include, right = exclude).
    # The validator does not care which side a token came from — every token
    # must parse to an integer or an integer range either way.
    for segment in expr.split("!"):
        segment = segment.strip()
        if not segment:
            continue
        for token in segment.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                lo, _, hi = token.partition("-")
                try:
                    int(lo.strip())
                    int(hi.strip())
                except (ValueError, TypeError):
                    invalid.append(token)
            else:
                try:
                    int(token)
                except ValueError:
                    invalid.append(token)
    return invalid


# ── Default (pass-all) filter ─────────────────────────────────────────────────


def empty_filter() -> dict:
    """Return a filter config that passes all events."""
    return {
        "event_ids": None,
        "exclude_event_ids": None,
        "sources": None,
        "levels": None,
        "date_from": None,
        "date_to": None,
        "users": None,
        "computers": None,
        "task_categories": None,
        "text_search": None,
        "search_mode": "AND",
    }


def merge_filters(base: dict, override: dict) -> dict:
    """Merge two filter configs. Override values replace base values when set."""
    result = base.copy()
    for key, val in override.items():
        if val is not None:
            if key in (
                "event_ids", "exclude_event_ids", "sources", "levels",
                "users", "computers", "task_categories", "text_search"
            ) and isinstance(result.get(key), list) and isinstance(val, list):
                # Union list fields (text_search preserves duplicates via set)
                combined = list(set(result[key] + val))
                result[key] = combined
            else:
                result[key] = val
    return result


# ── Timestamp parsing (fast, no external deps) ────────────────────────────────

def _keywords_int(event: dict) -> int:
    """Parse the event Keywords hex string to int (0 on failure)."""
    try:
        return int(str(event.get("keywords", "") or "0"), 16)
    except (ValueError, TypeError):
        return 0


# Keywords bits for audit outcome (top nibble at hex position 5 of the 64-bit
# value): bit 53 = Audit Success, bit 52 = Audit Failure.  Matches JM
# (filter_sql.py) and the normal-mode view (models.py) exactly.
_AUDIT_SUCCESS_BIT = 0x0020000000000000
_AUDIT_FAILURE_BIT = 0x0010000000000000


def _level_passes(event: dict, levels) -> bool:
    """True if the event matches ANY selected level.  Accepts level ints,
    numeric strings, level NAME strings (the filter dialog emits names), and the
    keyword-based "Audit Success" / "Audit Failure" outcomes — so parse-time /
    CLI level filtering matches JM and the GUI view (was int-only, which
    silently returned nothing for name-string and audit-outcome levels)."""
    ev_name = event.get("level_name", "")
    ev_int  = event.get("level", 4)
    audit_names: set[str] = set()
    for lv in levels:
        if lv == ev_name or lv == ev_int:
            return True
        if isinstance(lv, str):
            ls = lv.strip()
            if ls.isdigit() and int(ls) == ev_int:
                return True
            audit_names.add(ls.lower())
    if "audit success" in audit_names and (_keywords_int(event) & _AUDIT_SUCCESS_BIT):
        return True
    if "audit failure" in audit_names and (_keywords_int(event) & _AUDIT_FAILURE_BIT):
        return True
    return False


def _parse_ts(ts_str: str | None) -> datetime | None:
    if not ts_str:
        return None
    # Strip timezone suffix robustly: remove Z, and strip +HH:MM / -HH:MM offsets
    # Also strip sub-second precision. Keep only the first 19 chars of the datetime portion.
    import re as _re
    ts_clean = _re.sub(r"[Zz]$", "", ts_str)          # strip trailing Z
    ts_clean = _re.sub(r"[+-]\d{2}:\d{2}$", "", ts_clean)  # strip ±HH:MM
    ts_clean = ts_clean.split(".")[0][:19]             # strip microseconds, cap at 19 chars
    try:
        return datetime.strptime(ts_clean, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None


def _date_mode(fc: dict) -> str:
    """Match filter_sql.py: derive the date-comparison mode from the dialog's
    date/time/separate/specific-day flags.  Defaults to full-range 'range' when
    no flags are set (the common date_from/date_to case), preserving prior
    behaviour."""
    date_en = bool(fc.get("date_enabled"))
    time_en = bool(fc.get("time_enabled"))
    sep_en  = bool(fc.get("separately_enabled"))
    spec_en = bool(fc.get("specific_day_enabled"))
    if spec_en or (date_en and time_en and not sep_en):
        return "range"
    if date_en and time_en and sep_en:
        return "separate"
    if date_en and not time_en:
        return "date_only"
    if time_en and not date_en:
        return "time_only"
    return "range"


def _date_in_range(event: dict, fc: dict) -> bool:
    """True if the event's timestamp is inside the date/time bounds, honouring
    the sub-mode (range / date_only / time_only / separate).  Undatable events
    return False.  Mirrors filter_sql.py's SUBSTRING comparisons using datetime
    parts, so parse-time / CLI date filtering matches JM and the GUI view
    (which previously only did full-range comparison)."""
    df = fc.get("date_from") or ""
    dt = fc.get("date_to") or ""
    ets = _parse_ts(event.get("timestamp"))
    if ets is None:
        return False
    mode = _date_mode(fc)
    if mode == "date_only":
        ed = ets.date()
        if len(df) >= 10:
            fd = _parse_ts(df[:10] + "T00:00:00")
            if fd and ed < fd.date():
                return False
        if len(dt) >= 10:
            td = _parse_ts(dt[:10] + "T00:00:00")
            if td and ed > td.date():
                return False
        return True
    if mode == "time_only":
        et = ets.time()
        tf = df[11:19] if len(df) >= 19 else "00:00:00"
        tt = dt[11:19] if len(dt) >= 19 else "23:59:59"
        ff = _parse_ts("2000-01-01T" + tf)
        ftt = _parse_ts("2000-01-01T" + tt)
        if ff and et < ff.time():
            return False
        if ftt and et > ftt.time():
            return False
        return True
    if mode == "separate":
        ed, et = ets.date(), ets.time()
        if len(df) >= 10:
            fd = _parse_ts(df[:10] + "T00:00:00")
            if fd and ed < fd.date():
                return False
        if len(dt) >= 10:
            td = _parse_ts(dt[:10] + "T00:00:00")
            if td and ed > td.date():
                return False
        if len(df) >= 19:
            ff = _parse_ts("2000-01-01T" + df[11:19])
            if ff and et < ff.time():
                return False
        if len(dt) >= 19:
            ftt = _parse_ts("2000-01-01T" + dt[11:19])
            if ftt and et > ftt.time():
                return False
        return True
    # "range" — full second-granularity comparison
    if df:
        fts = _parse_ts(df)
        if fts and ets < fts:
            return False
    if dt:
        tts = _parse_ts(dt)
        if tts and ets > tts:
            return False
    return True


def _relative_passes(event: dict, fc: dict) -> bool:
    """Handle relative_days / relative_hours ("last N days/hours from now").
    Was ignored at parse time / CLI while JM honoured it.  Returns True when no
    relative filter is set."""
    try:
        rel_days = int(fc.get("relative_days", 0) or 0)
    except (TypeError, ValueError):
        rel_days = 0
    try:
        rel_hours = int(fc.get("relative_hours", 0) or 0)
    except (TypeError, ValueError):
        rel_hours = 0
    if rel_days <= 0 and rel_hours <= 0:
        return True
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(hours=rel_days * 24 + rel_hours)
    ets = _parse_ts(event.get("timestamp"))
    recent = ets is not None and ets >= cutoff
    return (not recent) if fc.get("relative_exclude") else recent


# ── Core filter predicate ─────────────────────────────────────────────────────

# ── Custom condition evaluation ────────────────────────────────────────────────
# Profile editor + advanced filter dialog both write conditions of the shape:
#   {"name": <field>, "operator": <op>, "value": <user-typed value>}
#
# These conditions used to be silently dropped at PARSE TIME because
# compile_filter() and passes_filter() didn't know about them.  Result: a
# profile that said "DriverName != msmouse.inf" got applied to the live
# filter post-parse but not to the parse-time pre-filter, so msmouse.inf
# events still ended up in the dataset.  The two checks below close that gap
# and re-use the JM/SQL mode's symbolic + hex/decimal expansion table so
# parse-time conditions behave EXACTLY the same as their live-filter
# counterpart (no surprises about which form of the value matches).
#
# A small subset of fields is "dual-source" — the same logical value lives
# in both event_data AND a top-level System field (ProcessId ↔ process_id,
# ThreadId ↔ thread_id).  Mirror that here so a profile-defined condition on
# ProcessId matches regardless of which layer holds the PID.
_PARSE_TIME_DUAL_SOURCE: dict[str, str] = {
    "ProcessId": "process_id",
    "ThreadId":  "thread_id",
}


def _conditions_pass(event: dict, conditions: "list[dict]", cs: bool) -> bool:
    """Return True iff *event* satisfies every condition (AND-combined).

    Mirrors models.py ``_passes_advanced`` conditions logic but works on a
    plain event dict at parse time (no Qt proxy state required).  Supports:

      * Field lookup: top-level event field first, then event_data sub-field
      * Dual-source PID/TID lookup
      * Hex/decimal expansion + symbolic aliases (via filter_sql)
      * Operators: contains, equals, starts with, ends with, not contains,
        not equals, regex, greater than, less than
      * Negative operators (``not equals`` / ``not contains``) hold for ALL
        sources — i.e. the value must NOT match in ANY source.

    Perf note: this runs once per event during parse-time pre-filtering, so
    the body avoids defining helper closures inside the loop and inlines the
    any/all-of-candidates checks directly.
    """
    if not conditions:
        return True

    # Lazy module-level import — kept here (not at file top) to avoid any
    # risk of a circular import with core.heavyweight.filter_sql, which
    # itself lazy-imports parse_event_id_expression from this module.  After
    # first call Python's sys.modules cache makes this a single dict lookup.
    try:
        from evtx_tool.core.heavyweight.filter_sql import expand_condition_value
    except Exception:
        def expand_condition_value(_n: str, v: str) -> list[str]:
            return [v]

    import re as _re

    ed = event.get("event_data")
    if not isinstance(ed, dict):
        ed = {}
    # Nested-aware field map so a condition on a field nested inside a container
    # (e.g. RmSessionId under RmSessionEvent) still resolves — identical to the
    # JM ed_flat_json column, so field conditions match in both modes.
    ed_flat = flatten_fields(ed)

    _low = (lambda s: s) if cs else str.lower

    for cond in conditions:
        name = cond.get("name", "")
        if not name:
            continue
        op = cond.get("operator", "contains")
        raw_val = cond.get("value", "")
        cv = _low(str(raw_val or ""))

        # Build candidate values for this field — primary + dual-source.
        # Use an explicit None check (not ``primary or ""``): a real field value
        # of 0 / False / "" is falsy but must still be matchable (e.g. a
        # condition "RmSessionId equals 0"), and JM (json_extract_string)
        # preserves it — so normal mode must too.
        primary = event.get(name)
        if primary is None:
            primary = ed_flat.get(name)
        candidates: list[str] = [_low(str(primary) if primary is not None else "")]
        dual = _PARSE_TIME_DUAL_SOURCE.get(name)
        if dual is not None:
            candidates.append(_low(str(event.get(dual, "") or "")))

        # Pre-compute value variants for known fields (hex/decimal + symbolic)
        variants: "frozenset[str] | None" = None
        if op in ("equals", "not equals", "contains", "not contains"):
            _v = expand_condition_value(name, raw_val)
            if len(_v) > 1:
                if not cs:
                    _v = [x.lower() for x in _v]
                variants = frozenset(_v)

        # ── Operator dispatch (inlined any/all to avoid closures in loop) ──
        if op == "contains":
            if variants is not None:
                # Any candidate contains any variant
                hit = False
                for fv in candidates:
                    for v in variants:
                        if v in fv:
                            hit = True
                            break
                    if hit:
                        break
                if not hit:
                    return False
            else:
                hit = False
                for fv in candidates:
                    if cv in fv:
                        hit = True
                        break
                if not hit:
                    return False
        elif op == "equals":
            if variants is not None:
                hit = False
                for fv in candidates:
                    if fv in variants:
                        hit = True
                        break
                if not hit:
                    return False
            else:
                hit = False
                for fv in candidates:
                    if fv == cv:
                        hit = True
                        break
                if not hit:
                    return False
        elif op == "starts with":
            hit = False
            for fv in candidates:
                if fv.startswith(cv):
                    hit = True
                    break
            if not hit:
                return False
        elif op == "ends with":
            hit = False
            for fv in candidates:
                if fv.endswith(cv):
                    hit = True
                    break
            if not hit:
                return False
        elif op == "not contains":
            # Hold for ALL sources — if the (any variant of the) value appears
            # in ANY candidate, the condition fails.
            if variants is not None:
                for fv in candidates:
                    for v in variants:
                        if v in fv:
                            return False
            else:
                for fv in candidates:
                    if cv in fv:
                        return False
        elif op == "not equals":
            if variants is not None:
                for fv in candidates:
                    if fv in variants:
                        return False
            else:
                for fv in candidates:
                    if fv == cv:
                        return False
        elif op == "regex":
            try:
                pat = _re.compile(raw_val, 0 if cs else _re.IGNORECASE)
            except _re.error:
                # Invalid regex: drop the event (matches the proxy's
                # behaviour of treating an unparseable regex as no match).
                return False
            hit = False
            for fv in candidates:
                if pat.search(fv) is not None:
                    hit = True
                    break
            if not hit:
                return False
        elif op == "greater than":
            hit = False
            try:
                target = float(raw_val)
            except (ValueError, TypeError):
                return False  # non-numeric threshold → no row matches
            for fv in candidates:
                try:
                    if float(fv) > target:
                        hit = True
                        break
                except (ValueError, TypeError):
                    continue
            if not hit:
                return False
        elif op == "less than":
            hit = False
            try:
                target = float(raw_val)
            except (ValueError, TypeError):
                return False
            for fv in candidates:
                try:
                    if float(fv) < target:
                        hit = True
                        break
                except (ValueError, TypeError):
                    continue
            if not hit:
                return False
        else:
            # Unknown operator — be conservative and drop the event so a
            # typo'd operator can't silently let everything through.
            return False

    return True


def passes_filter(event: dict, fc: dict) -> bool:
    """Return True if event passes all criteria in filter config fc."""

    # Event ID include list
    if fc.get("event_ids"):
        if event["event_id"] not in fc["event_ids"]:
            return False

    # Event ID exclude list
    if fc.get("exclude_event_ids"):
        if event["event_id"] in fc["exclude_event_ids"]:
            return False

    # Event ID expression (ELE-style ranges/exclusions, e.g. "1-19,100!10,255").
    # The advanced-filter dialog stores its event-ID input here; JM honours it —
    # normal mode must too, or the filter is silently ignored (all events pass).
    expr = fc.get("event_id_expr")
    if isinstance(expr, str) and expr:  # str guard: a malformed non-str config is skipped, not crashed
        inc_ids, exc_ids = _parse_eid_expr_cached(expr)  # memoised — see helper
        eid = event["event_id"]
        if inc_ids:
            in_inc = eid in inc_ids
            if fc.get("event_id_exclude", False):
                if in_inc:
                    return False
            elif not in_inc:
                return False
        if exc_ids and eid in exc_ids:
            return False

    # Level filter (use truthiness so empty list [] means "no filter").
    # Handles level ints, name strings, and Audit Success/Failure keywords.
    if fc.get("levels"):
        if not _level_passes(event, fc["levels"]):
            return False

    # Source/Provider/Channel filter (honors source_exclude — parity with
    # filter_sql.py / models.py view; previously exclude was silently ignored)
    if fc.get("sources"):
        provider = (event.get("provider", "") or "").lower()
        channel = (event.get("channel", "") or "").lower()
        hit = any(s.lower() in provider or s.lower() in channel for s in fc["sources"])
        if fc.get("source_exclude"):
            if hit:
                return False
        elif not hit:
            return False

    # Category (channel-name) filter (honors category_exclude). Distinct from
    # task_categories (numeric Task). Set by the advanced dialog and by
    # build_combined_filter() from profile channels — was entirely unhandled
    # here, so profile/CLI channel restrictions leaked through.
    if fc.get("categories"):
        channel = (event.get("channel", "") or "").lower()
        hit = any(str(c).lower() in channel for c in fc["categories"])
        if fc.get("category_exclude"):
            if hit:
                return False
        elif not hit:
            return False

    # Date/time filter (honors date_exclude and the date/time/separate sub-modes)
    if fc.get("date_from") or fc.get("date_to"):
        in_range = _date_in_range(event, fc)
        if fc.get("date_exclude"):
            if in_range:
                return False  # exclude events inside the range; undatable pass
        elif not in_range:
            return False       # include mode: undatable events excluded

    # Relative time filter ("last N days/hours")
    if not _relative_passes(event, fc):
        return False

    # User/SID filter (honors user_exclude)
    if fc.get("users"):
        ed = event.get("event_data", {}) or {}
        user_str = " ".join(filter(None, [
            str(ed.get("SubjectUserName", "") or ""),
            str(ed.get("TargetUserName", "") or ""),
            str(ed.get("SubjectUserSid", "") or ""),
            str(ed.get("TargetUserSid", "") or ""),
            str(ed.get("UserName", "") or ""),
            str(event.get("user_id", "") or ""),
        ])).lower()
        hit = any(u.lower() in user_str for u in fc["users"])
        if fc.get("user_exclude"):
            if hit:
                return False
        elif not hit:
            return False

    # Computer filter (honors computer_exclude)
    if fc.get("computers"):
        computer = (event.get("computer", "") or "").lower()
        hit = any(c.lower() in computer for c in fc["computers"])
        if fc.get("computer_exclude"):
            if hit:
                return False
        elif not hit:
            return False

    # Task category filter (numeric Task; JM has no exclude for this field)
    if fc.get("task_categories"):
        if event.get("task", 0) not in fc["task_categories"]:
            return False

    # Text search filter (honors text_exclude, text_regex, case_sensitive)
    if fc.get("text_search"):
        terms: list[str] = fc["text_search"]
        mode: str = fc.get("search_mode", "AND").upper()
        matched = _text_search_matches(
            event, terms, mode,
            regex=bool(fc.get("text_regex", False)),
            case_sensitive=bool(fc.get("case_sensitive", False)),
        )
        # text_exclude is ignored when mode == "NOT" (NOT already IS the
        # exclusion) — matches filter_sql.py's `text_exclude and mode != "NOT"`.
        if fc.get("text_exclude") and mode != "NOT":
            if matched:
                return False
        elif not matched:
            return False

    # Custom conditions (profile-defined or advanced-dialog).  Without this
    # check, profile conditions silently leak through parse-time filtering —
    # see _conditions_pass docstring.
    conds = fc.get("conditions")
    if conds:
        if not _conditions_pass(event, conds, bool(fc.get("case_sensitive", False))):
            return False

    return True


def _text_search_matches(event: dict, terms: list[str], mode: str,
                         regex: bool = False, case_sensitive: bool = False) -> bool:
    """Values-only text-search match, honouring *regex* and *case_sensitive*.

    Scope matches Juggernaut mode's SEARCH_TEXT_EXPR_FULL (metadata columns +
    the ed_values value blob — field NAMES excluded).  Previously this ignored
    both the regex and case-sensitive flags (always a case-insensitive substring
    match), so a regex search matched nothing and a case-sensitive search
    matched case-insensitively — diverging from JM and the GUI view.
    """
    import re as _re

    # Build the fragment list ONCE (raw case preserved).
    fragments: list[str] = [
        str(event.get("event_id", "")),
        event.get("channel", "") or "",
        event.get("provider", "") or "",
        event.get("computer", "") or "",
        event.get("level_name", "") or "",
        event.get("user_id", "") or "",
        event.get("source_file", "") or "",
    ]
    ed = event.get("event_data", {}) or {}
    if ed:
        # Every EventData value (recursively, all nesting), field names excluded.
        fragments.extend(flatten_searchable_values(ed))

    if not case_sensitive:
        fragments = [f.lower() for f in fragments]

    if regex:
        flags = 0 if case_sensitive else _re.IGNORECASE
        # Compile each term; an invalid pattern matches nothing (fail-closed,
        # consistent with the dialog's regex validation rejecting bad patterns).
        matchers = []
        for t in terms:
            try:
                matchers.append(_re.compile(t if case_sensitive else t.lower(), flags))
            except _re.error:
                matchers.append(None)

        def _term_hit(i: int) -> bool:
            pat = matchers[i]
            return pat is not None and any(pat.search(f) for f in fragments)
    else:
        _terms = terms if case_sensitive else [t.lower() for t in terms]

        def _term_hit(i: int) -> bool:
            t = _terms[i]
            return any(t in f for f in fragments)

    idxs = range(len(terms))
    if mode == "OR":
        return any(_term_hit(i) for i in idxs)
    if mode == "NOT":
        return not any(_term_hit(i) for i in idxs)
    # AND (default): every term must hit some fragment
    return all(_term_hit(i) for i in idxs)


def _event_to_text(event: dict) -> str:
    """Flatten all event fields into a single searchable string."""
    parts = [
        str(event.get("event_id", "")),
        event.get("channel", ""),
        event.get("provider", ""),
        event.get("computer", ""),
        event.get("level_name", ""),
        event.get("user_id", ""),
        event.get("timestamp", ""),
    ]
    ed = event.get("event_data", {}) or {}
    if isinstance(ed, dict):
        parts.extend(str(v) for v in ed.values() if v is not None)
    return " ".join(parts).lower()


# ── Compiled filter (perf fix #10) ────────────────────────────────────────────
# Build a single callable from the filter config so per-event overhead is
# minimized. The engine calls compile_filter() once per run, then uses the
# returned callable for every event instead of calling passes_filter().

def compile_filter(fc: dict) -> Callable[[dict], bool]:
    """
    Pre-compile a filter config into a fast callable.

    Reads the filter config once, builds a list of check functions for only the
    active conditions, and returns a combined callable. This eliminates repeated
    fc.get() dict lookups on every event.

    Falls back to passes_filter() if fc is effectively empty (no conditions).
    """
    checks: list[Callable[[dict], bool]] = []

    # Event ID include
    if fc.get("event_ids"):
        _include_ids = set(fc["event_ids"])
        checks.append(lambda ev, _ids=_include_ids: ev["event_id"] in _ids)

    # Event ID exclude
    if fc.get("exclude_event_ids"):
        _exclude_ids = set(fc["exclude_event_ids"])
        checks.append(lambda ev, _ids=_exclude_ids: ev["event_id"] not in _ids)

    # Event ID expression (ELE-style ranges/exclusions) — was silently ignored
    # at parse time / CLI while JM honoured it.
    _eid_expr = fc.get("event_id_expr")
    if isinstance(_eid_expr, str) and _eid_expr:  # str guard (see passes_filter)
        _inc_ids, _exc_ids = _parse_eid_expr_cached(_eid_expr)
        _eid_excl = bool(fc.get("event_id_exclude", False))
        def _check_eid_expr(ev, _inc=_inc_ids, _exc=_exc_ids, _ex=_eid_excl):
            eid = ev["event_id"]
            if _inc:
                in_inc = eid in _inc
                if _ex:
                    if in_inc:
                        return False
                elif not in_inc:
                    return False
            if _exc and eid in _exc:
                return False
            return True
        checks.append(_check_eid_expr)

    # Level (ints, name strings, and Audit Success/Failure keyword outcomes)
    if fc.get("levels"):
        _levels = list(fc["levels"])
        checks.append(lambda ev, _lvls=_levels: _level_passes(ev, _lvls))

    # Source/Provider/Channel (honors source_exclude)
    if fc.get("sources"):
        _sources_lower = [s.lower() for s in fc["sources"]]
        _src_excl = bool(fc.get("source_exclude"))
        def _check_source(ev, _srcs=_sources_lower, _ex=_src_excl):
            prov = (ev.get("provider", "") or "").lower()
            chan = (ev.get("channel", "") or "").lower()
            hit = any(s in prov or s in chan for s in _srcs)
            return (not hit) if _ex else hit
        checks.append(_check_source)

    # Category (channel-name) (honors category_exclude). Distinct from
    # task_categories; set by the dialog and by profile channels.
    if fc.get("categories"):
        _cats_lower = [str(c).lower() for c in fc["categories"]]
        _cat_excl = bool(fc.get("category_exclude"))
        def _check_category(ev, _cats=_cats_lower, _ex=_cat_excl):
            chan = (ev.get("channel", "") or "").lower()
            hit = any(c in chan for c in _cats)
            return (not hit) if _ex else hit
        checks.append(_check_category)

    # Date/time (honors date_exclude and the date/time/separate sub-modes)
    if fc.get("date_from") or fc.get("date_to"):
        _date_excl = bool(fc.get("date_exclude"))
        def _check_date(ev, _fc=fc, _ex=_date_excl):
            in_range = _date_in_range(ev, _fc)
            return (not in_range) if _ex else in_range
        checks.append(_check_date)

    # Relative time filter ("last N days/hours")
    if (fc.get("relative_days") or fc.get("relative_hours")):
        checks.append(lambda ev, _fc=fc: _relative_passes(ev, _fc))

    # User/SID (honors user_exclude)
    if fc.get("users"):
        _users_lower = [u.lower() for u in fc["users"]]
        _usr_excl = bool(fc.get("user_exclude"))
        def _check_user(ev, _usrs=_users_lower, _ex=_usr_excl):
            ed = ev.get("event_data", {}) or {}
            user_str = " ".join(filter(None, [
                str(ed.get("SubjectUserName", "") or ""),
                str(ed.get("TargetUserName", "") or ""),
                str(ed.get("SubjectUserSid", "") or ""),
                str(ed.get("TargetUserSid", "") or ""),
                str(ed.get("UserName", "") or ""),
                str(ev.get("user_id", "") or ""),
            ])).lower()
            hit = any(u in user_str for u in _usrs)
            return (not hit) if _ex else hit
        checks.append(_check_user)

    # Computer (honors computer_exclude)
    if fc.get("computers"):
        _comps_lower = [c.lower() for c in fc["computers"]]
        _comp_excl = bool(fc.get("computer_exclude"))
        def _check_computer(ev, _cs=_comps_lower, _ex=_comp_excl):
            comp = (ev.get("computer", "") or "").lower()
            hit = any(c in comp for c in _cs)
            return (not hit) if _ex else hit
        checks.append(_check_computer)

    # Task category (numeric Task; JM has no exclude for this field)
    if fc.get("task_categories"):
        _tasks = set(fc["task_categories"])
        checks.append(lambda ev, _t=_tasks: ev.get("task", 0) in _t)

    # Text search (honors text_exclude, text_regex, case_sensitive)
    if fc.get("text_search"):
        _terms = fc["text_search"]
        _mode = fc.get("search_mode", "AND").upper()
        _txt_excl = bool(fc.get("text_exclude"))
        _txt_rx = bool(fc.get("text_regex", False))
        _txt_cs = bool(fc.get("case_sensitive", False))
        def _check_text(ev, _t=_terms, _m=_mode, _ex=_txt_excl, _rx=_txt_rx, _cs=_txt_cs):
            matched = _text_search_matches(ev, _t, _m, regex=_rx, case_sensitive=_cs)
            # NOT mode already excludes — ignore text_exclude then (parity w/ JM).
            return (not matched) if (_ex and _m != "NOT") else matched
        checks.append(_check_text)

    # Custom conditions (profile-defined or advanced-dialog).  Closes the
    # parse-time leak where conditions like "DriverName != msmouse.inf" were
    # silently dropped — see _conditions_pass docstring.
    if fc.get("conditions"):
        _conds = fc["conditions"]
        _cs    = bool(fc.get("case_sensitive", False))
        checks.append(lambda ev, _c=_conds, _s=_cs: _conditions_pass(ev, _c, _s))

    # No active conditions → pass everything
    if not checks:
        return lambda ev: True

    # Single condition → return it directly (avoid all() overhead)
    if len(checks) == 1:
        return checks[0]

    # Multiple conditions → short-circuit AND
    def _combined(ev, _checks=checks):
        for check in _checks:
            if not check(ev):
                return False
        return True
    return _combined


# ── Filter config serialization ───────────────────────────────────────────────

def filter_to_dict(fc: dict) -> dict:
    """Ensure filter config is JSON-serializable."""
    return {k: v for k, v in fc.items()}


def filter_from_dict(d: dict) -> dict:
    """Load filter from dict, filling missing keys with defaults."""
    base = empty_filter()
    base.update(d)
    return base


def save_filter(fc: dict, filepath: str) -> None:
    """Save filter config to JSON file."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(fast_dumps(fc, indent=2))


def load_filter(filepath: str) -> dict:
    """Load filter config from JSON file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return filter_from_dict(fast_loads(f.read()))


# ── Profile → filter conversion ────────────────────────────────────────────────

def profile_to_filter(profile: dict) -> dict:
    """Convert a DFIR profile dict to a FilterConfig dict."""
    fc = empty_filter()
    if profile.get("event_ids"):
        fc["event_ids"] = [int(e) for e in profile["event_ids"]]
    if profile.get("sources"):
        fc["sources"] = profile["sources"]
    if profile.get("keywords"):
        fc["text_search"] = profile["keywords"]
        fc["search_mode"] = "OR"
    return fc


def build_combined_filter(base_filter: dict, profiles: list[dict]) -> dict:
    """
    Combine a base filter with multiple profiles.
    Profile event_ids and sources are unioned. Base filter restrictions are applied on top.
    Extended profile fields (channels, computers, users, levels, conditions) are merged in.
    """
    if not profiles:
        return base_filter

    # Union all profile event IDs and sources
    all_event_ids: list[int] = []
    all_sources: list[str] = []
    all_channels: list[str] = []
    all_computers: list[str] = []
    all_users: list[str] = []
    all_levels: list[str] = []
    all_conditions: list[dict] = []
    case_sensitive = False

    for p in profiles:
        all_event_ids.extend(int(e) for e in p.get("event_ids", []))
        all_sources.extend(p.get("sources", []))
        all_channels.extend(p.get("channels", []))
        all_computers.extend(p.get("computers", []))
        all_users.extend(p.get("users", []))
        all_levels.extend(p.get("levels", []))
        all_conditions.extend(p.get("conditions", []))
        if p.get("case_sensitive"):
            case_sensitive = True

    combined = base_filter.copy()

    # Profile event IDs: intersect with base filter if base has event_ids
    if all_event_ids:
        if base_filter.get("event_ids"):
            base_set = set(base_filter["event_ids"])
            combined["event_ids"] = [e for e in all_event_ids if e in base_set]
        else:
            combined["event_ids"] = list(set(all_event_ids))

    if all_sources and not base_filter.get("sources"):
        combined["sources"] = list(set(all_sources))

    # Extended fields — only set if not already constrained by base filter
    if all_channels:
        combined.setdefault("categories", list(set(all_channels)))
    if all_computers:
        combined.setdefault("computers", list(set(all_computers)))
    if all_users:
        combined.setdefault("users", list(set(all_users)))
    if all_levels:
        combined.setdefault("levels", list(set(all_levels)))
    if all_conditions:
        existing = list(combined.get("conditions") or [])
        combined["conditions"] = existing + all_conditions
    if case_sensitive:
        combined["case_sensitive"] = True

    return combined
