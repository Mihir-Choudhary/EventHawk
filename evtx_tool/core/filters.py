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
from typing import Any, Callable

from evtx_tool.core._json_compat import fast_loads, fast_dumps


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


# ── Core filter predicate ─────────────────────────────────────────────────────

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

    # Level filter (use truthiness so empty list [] means "no filter")
    if fc.get("levels"):
        if event.get("level", 4) not in fc["levels"]:
            return False

    # Source/Provider/Channel filter
    if fc.get("sources"):
        provider = event.get("provider", "").lower()
        channel = event.get("channel", "").lower()
        if not any(s.lower() in provider or s.lower() in channel for s in fc["sources"]):
            return False

    # Date range filter
    if fc.get("date_from") or fc.get("date_to"):
        event_ts = _parse_ts(event.get("timestamp"))
        if event_ts is None:
            return False  # exclude undatable events when date filter active
        if fc.get("date_from"):
            from_ts = _parse_ts(fc["date_from"])
            if from_ts and event_ts < from_ts:
                return False
        if fc.get("date_to"):
            to_ts = _parse_ts(fc["date_to"])
            if to_ts and event_ts > to_ts:
                return False

    # User/SID filter
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
        if not any(u.lower() in user_str for u in fc["users"]):
            return False

    # Computer filter
    if fc.get("computers"):
        computer = event.get("computer", "").lower()
        if not any(c.lower() in computer for c in fc["computers"]):
            return False

    # Task category filter
    if fc.get("task_categories"):
        if event.get("task", 0) not in fc["task_categories"]:
            return False

    # Text search filter
    # Perf fix #3: short-circuit on individual field values before flattening
    if fc.get("text_search"):
        terms: list[str] = fc["text_search"]
        mode: str = fc.get("search_mode", "AND").upper()
        if not _text_search_matches(event, terms, mode):
            return False

    return True


def _text_search_matches(event: dict, terms: list[str], mode: str) -> bool:
    """
    Perf fix #3: search individual event_data values first, short-circuiting
    when possible. Only falls back to full flattening when needed.
    Same match semantics as the original _event_to_text approach.
    """
    lower_terms = [t.lower() for t in terms]

    # Collect all searchable text fragments (without joining them yet)
    fragments: list[str] = [
        str(event.get("event_id", "")),
        (event.get("channel", "") or "").lower(),
        (event.get("provider", "") or "").lower(),
        (event.get("computer", "") or "").lower(),
        (event.get("level_name", "") or "").lower(),
        (event.get("user_id", "") or "").lower(),
        (event.get("timestamp", "") or "").lower(),
    ]
    ed = event.get("event_data", {}) or {}
    if isinstance(ed, dict):
        for v in ed.values():
            if v is not None:
                fragments.append(str(v).lower())

    if mode == "AND":
        # Every term must appear in at least one fragment
        for term in lower_terms:
            found = False
            for frag in fragments:
                if term in frag:
                    found = True
                    break
            if not found:
                return False
        return True
    elif mode == "OR":
        # Any term in any fragment = match
        for term in lower_terms:
            for frag in fragments:
                if term in frag:
                    return True
        return False
    elif mode == "NOT":
        # No term should appear in any fragment
        for term in lower_terms:
            for frag in fragments:
                if term in frag:
                    return False
        return True
    return True


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

    # Level
    if fc.get("levels"):
        _levels = set(fc["levels"])
        checks.append(lambda ev, _lvls=_levels: ev.get("level", 4) in _lvls)

    # Source/Provider/Channel
    if fc.get("sources"):
        _sources_lower = [s.lower() for s in fc["sources"]]
        def _check_source(ev, _srcs=_sources_lower):
            prov = (ev.get("provider", "") or "").lower()
            chan = (ev.get("channel", "") or "").lower()
            return any(s in prov or s in chan for s in _srcs)
        checks.append(_check_source)

    # Date range
    if fc.get("date_from") or fc.get("date_to"):
        _from_ts = _parse_ts(fc.get("date_from")) if fc.get("date_from") else None
        _to_ts = _parse_ts(fc.get("date_to")) if fc.get("date_to") else None
        def _check_date(ev, _ft=_from_ts, _tt=_to_ts):
            ets = _parse_ts(ev.get("timestamp"))
            if ets is None:
                return False
            if _ft and ets < _ft:
                return False
            if _tt and ets > _tt:
                return False
            return True
        checks.append(_check_date)

    # User/SID
    if fc.get("users"):
        _users_lower = [u.lower() for u in fc["users"]]
        def _check_user(ev, _usrs=_users_lower):
            ed = ev.get("event_data", {}) or {}
            user_str = " ".join(filter(None, [
                str(ed.get("SubjectUserName", "") or ""),
                str(ed.get("TargetUserName", "") or ""),
                str(ed.get("SubjectUserSid", "") or ""),
                str(ed.get("TargetUserSid", "") or ""),
                str(ed.get("UserName", "") or ""),
                str(ev.get("user_id", "") or ""),
            ])).lower()
            return any(u in user_str for u in _usrs)
        checks.append(_check_user)

    # Computer
    if fc.get("computers"):
        _comps_lower = [c.lower() for c in fc["computers"]]
        def _check_computer(ev, _cs=_comps_lower):
            comp = (ev.get("computer", "") or "").lower()
            return any(c in comp for c in _cs)
        checks.append(_check_computer)

    # Task category
    if fc.get("task_categories"):
        _tasks = set(fc["task_categories"])
        checks.append(lambda ev, _t=_tasks: ev.get("task", 0) in _t)

    # Text search
    if fc.get("text_search"):
        _terms = fc["text_search"]
        _mode = fc.get("search_mode", "AND").upper()
        checks.append(lambda ev, _t=_terms, _m=_mode: _text_search_matches(ev, _t, _m))

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
