"""
FilterConfig → DuckDB SQL WHERE clause translator.

Converts the Python filter config dict (used by ``compile_filter`` in normal
mode) into a parameterized SQL WHERE clause for DuckDB.  Every user value uses
``?`` placeholders — **never** f-string interpolation.

DuckDB dialect differences from SQLite:
  • json_extract_string(col, '$.key')   vs  json_extract(col, '$.key')
  • TRY_CAST(x AS DOUBLE)               vs  CAST(x AS REAL)
  • regexp_matches(col, pat)            vs  REGEXP(pat, col) UDF
  • CONTAINS(col, term)                 vs  INSTR(col, term) > 0
  • Timestamps stored as TEXT (ISO-8601) — text comparison still works identically

Architecture 1 (Arrow table) note
──────────────────────────────────
The DuckDB connection in _FilterThread operates on an in-memory Arrow table that
contains only metadata columns.  Two columns present in the old SQLite schema are
NOT available:

  • search_text      — was a SQLite STORED GENERATED COLUMN; replaced here by
                       SEARCH_TEXT_EXPR, a DuckDB expression that produces the
                       same concatenated lower-case blob at query time.
  • event_data_json  — kept on disk in Parquet; lazy-loaded only for the
                       selected row.  ``conditions`` clauses that reference it
                       are stripped in ArrowTableModel.apply_filter() before
                       this function is called.
"""

from __future__ import annotations

import logging
import re as _re
from typing import Any

logger = logging.getLogger(__name__)

# ── Search-text expression ─────────────────────────────────────────────────────
# Replaces the old SQLite STORED GENERATED COLUMN `search_text`.
# Produces a single lower-cased blob from all indexed metadata columns.
# Used by _term_clause() for both plain-text and regex text searches.
# Also imported by heavyweight_model._ARROW_SEARCH_EXPR so there is one
# canonical definition.
# Raw (NON-lowered) concat.  ed_values holds every EventData VALUE (values-only),
# loaded into the Arrow table so the quick/Phase-1 search covers all data values.
# ed_subject_user etc. are subsumed by ed_values but kept for clarity/back-compat.
_SEARCH_TEXT_RAW: str = (
    "CAST(event_id AS VARCHAR) || ' ' || "
    # Timestamps are stored as "YYYY-MM-DD HH:MM:SS.ffffff".  An analyst
    # pasting the ISO form the raw EVTX (and most other tooling) uses --
    # "YYYY-MM-DDTHH:MM:SS.ffffffZ" -- matched NOTHING.  Both renderings are
    # in the blob so either one finds the event.
    "replace(COALESCE(timestamp_utc, ''), ' ', 'T') || 'Z' || ' ' || "
    "CAST(record_id AS VARCHAR) || ' ' || "
    "COALESCE(level_name,      '') || ' ' || "
    "COALESCE(channel,         '') || ' ' || "
    "COALESCE(provider,        '') || ' ' || "
    "COALESCE(event_source_name, '') || ' ' || "
    "COALESCE(computer,        '') || ' ' || "
    "COALESCE(user_id,         '') || ' ' || "
    "COALESCE(source_file,     '') || ' ' || "
    "COALESCE(timestamp_utc,   '') || ' ' || "
    "COALESCE(keywords,        '') || ' ' || "
    "COALESCE(correlation_id,  '') || ' ' || "
    "CAST(COALESCE(task, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(opcode, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(process_id, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(thread_id, 0) AS VARCHAR) || ' ' || "
    "COALESCE(ed_subject_user, '') || ' ' || "
    "COALESCE(ed_target_user,  '') || ' ' || "
    "COALESCE(ed_ip_address,   '') || ' ' || "
    "COALESCE(ed_new_process,  '') || ' ' || "
    "COALESCE(ed_values,       '')"
)
# Default (case-insensitive) form wraps the raw concat in lower().  The RAW form
# is used for case-SENSITIVE search — otherwise the blob would be pre-lowered and
# a case-sensitive term could never match (it silently returned zero rows).
SEARCH_TEXT_EXPR: str = f"lower({_SEARCH_TEXT_RAW})"

# ── Full-text expression for Phase 2 Parquet search ────────────────────────────
# Like SEARCH_TEXT_EXPR but values-only via ed_values (NOT event_data_json) so a
# search for "logon" hits events whose DATA contains logon, not every event that
# merely has a LogonType field.  Runs only in text_config_to_parquet_sql().
_SEARCH_TEXT_RAW_FULL: str = (
    "CAST(event_id AS VARCHAR) || ' ' || "
    # Timestamps are stored as "YYYY-MM-DD HH:MM:SS.ffffff".  An analyst
    # pasting the ISO form the raw EVTX (and most other tooling) uses --
    # "YYYY-MM-DDTHH:MM:SS.ffffffZ" -- matched NOTHING.  Both renderings are
    # in the blob so either one finds the event.
    "replace(COALESCE(timestamp_utc, ''), ' ', 'T') || 'Z' || ' ' || "
    "CAST(record_id AS VARCHAR) || ' ' || "
    "COALESCE(level_name,      '') || ' ' || "
    "CAST(COALESCE(level, 0) AS VARCHAR) || ' ' || "
    "COALESCE(channel,         '') || ' ' || "
    "COALESCE(provider,        '') || ' ' || "
    "COALESCE(event_source_name, '') || ' ' || "
    "COALESCE(computer,        '') || ' ' || "
    "COALESCE(user_id,         '') || ' ' || "
    "COALESCE(source_file,     '') || ' ' || "
    "COALESCE(timestamp_utc,   '') || ' ' || "
    "COALESCE(keywords,        '') || ' ' || "
    "COALESCE(correlation_id,  '') || ' ' || "
    "CAST(COALESCE(task, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(opcode, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(process_id, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(thread_id, 0) AS VARCHAR) || ' ' || "
    "CAST(COALESCE(qualifiers, 0) AS VARCHAR) || ' ' || "
    # ed_values = every EventData VALUE, with XML line-split backslashes
    # collapsed.  event_data_json = the COMPLETE nested structure: container
    # keys, leaf names, values and attributes.
    #
    # Not ed_flat_json: it flattens the outer container away, so an event whose
    # data sits under e.g. "data_0x8000003F" kept only the leaf names and that
    # container name was unsearchable.  event_data_json is the only field that
    # skips nothing, and "nothing is skipped" is the contract here.
    "COALESCE(ed_values,       '') || ' ' || "
    "COALESCE(event_data_json, '')"
)
SEARCH_TEXT_EXPR_FULL: str = f"lower({_SEARCH_TEXT_RAW_FULL})"

# Only alphanumeric, underscore, dot, and hyphen are allowed in a json_extract
# path key ($.key).  Single quotes, braces, or spaces would break the SQL
# literal and potentially cause a syntax error crash.
_SAFE_JSON_KEY_RE = _re.compile(r"^[\w.\-]+$")

# Top-level Arrow/Parquet columns that exist as real SQL columns in the
# DuckDB table — NOT inside event_data_json.  Conditions on these names
# must reference the column directly instead of going through
# json_extract_string(event_data_json, '$.name'), which would always
# return NULL for them.
_TOP_LEVEL_COLS: frozenset[str] = frozenset({
    "event_id", "level", "level_name", "channel", "provider",
    "event_source_name",
    "computer", "user_id", "timestamp_utc", "source_file",
    "record_id", "task",
    # System/Execution PID/TID — decimal integers stored as top-level columns.
    # Distinct from the event_data ProcessId/ThreadId fields (often hex strings).
    "process_id", "thread_id",
    "ed_subject_user", "ed_target_user", "ed_ip_address", "ed_new_process",
    # System-header columns that live as real Parquet columns — NOT inside
    # event_data.  Without these a condition on e.g. "correlation_id" / "opcode"
    # / "keywords" went through json_extract(ed_flat_json, …) → always NULL → the
    # condition matched ZERO rows in JM while normal mode matched correctly.
    "keywords", "correlation_id", "opcode", "qualifiers",
})

# Fields where Windows stores numeric values as hex strings ("0x790") in
# event_data while users naturally type the decimal form ("1936") — or
# vice versa.  Equality / contains comparisons on these fields are expanded
# into an IN-clause covering both representations so the user does not
# have to know whether the underlying data is hex or decimal.
#
# WHY THIS IS A CURATED LIST (not universal):
#
#   Adversarial tests (see git log for the audit) confirmed that "universal"
#   hex/decimal expansion DOES produce false positives on plain string
#   fields.  A user typing computer="1234" had a 1234-named host AND a
#   "0x4d2"-named host both match — because 0x4d2 = decimal 1234 and the
#   universal expansion added it to the IN-clause.  Similarly contains "100"
#   would match "PC0x64".  Hostnames and usernames are pathological
#   string-typed fields where a numeric-looking value the user types must
#   be treated literally.
#
#   The safe rule: expand only when we KNOW the field stores numerics in
#   one of the two forms.  When a new field needs the same treatment, add
#   it here — it's a one-line change.  Custom / undocumented fields stay
#   literal until someone teaches us about them; that's better than silent
#   false positives.
# A few event_data field names have a TOP-LEVEL column equivalent that holds
# the same logical value at a different storage layer:
#
#   ProcessId   — event_data field (per-event-type; sometimes absent),
#                 AND the top-level `process_id` column extracted from
#                 <Execution ProcessID=…/> by the parser.
#   ThreadId    — same pattern with `thread_id`.
#
# Many events store the PID only in <Execution> (no event_data ProcessId
# field exists for them — e.g. LessPrivilegedAppContainer error 1).  Users
# filtering ``ProcessId = 18932`` don't know which layer holds the value
# for any given event type — they want "events whose PID is 18932".  The
# condition is therefore expanded into an OR across BOTH sources so the
# user gets matches regardless of which layer the value lives in.
_FIELD_DUAL_SOURCE: dict[str, str] = {
    "ProcessId": "process_id",
    "ThreadId":  "thread_id",
}

_HEX_DEC_FIELDS: frozenset[str] = frozenset({
    # ── Top-level columns (decimal int) ────────────────────────────────
    "process_id", "thread_id", "record_id",
    # ── event_data — hex strings in the EVTX XML ─────────────────────────
    # Process / thread IDs
    "ProcessId", "NewProcessId", "ParentProcessId", "SubjectProcessId",
    "CallerProcessId", "ClientProcessId",
    "ThreadId", "NewThreadId",
    # Logon IDs
    "TargetLogonId", "SubjectLogonId",
    "LinkedLogonId", "TargetLinkedLogonId",
    # Handle / Object
    "HandleId", "ObjectHandle",
    # Mask / type — these CAN be searched by exact value (less common but valid)
    "AccessMask", "TokenElevationType",
    # Process token info
    "MandatoryLabel",
})


def _norm(s: str) -> str:
    """Trim + lower a string defensively (None → '')."""
    return (s or "").strip().lower()


# ── Logon Type number ↔ symbolic name ──────────────────────────────────────────
# Windows EVTX stores LogonType as a number string ("3"); users typically read
# Event Viewer's resolved name ("Network", "RemoteInteractive") and type that.
# Aliases include common shorthand ("RDP" → 10) so the obvious forensic search
# "show me all RDP logons" works as expected.
_LOGON_TYPE_PAIRS = (
    ("2",  ("interactive",)),
    ("3",  ("network",)),
    ("4",  ("batch",)),
    ("5",  ("service",)),
    ("7",  ("unlock",)),
    ("8",  ("networkcleartext",)),
    ("9",  ("newcredentials",)),
    ("10", ("remoteinteractive", "rdp")),
    ("11", ("cachedinteractive",)),
    ("12", ("cachedremoteinteractive",)),
    ("13", ("cachedunlock",)),
)
# Lookup tables built lazily on import.  Both directions point into the same
# group set so any synonym fans out to every other form (number AND every name).
_LOGON_TYPE_GROUPS: dict[str, frozenset[str]] = {}
for _n, _names in _LOGON_TYPE_PAIRS:
    _group = frozenset({_n, *_names})
    _LOGON_TYPE_GROUPS[_n] = _group
    for _alias in _names:
        _LOGON_TYPE_GROUPS[_alias] = _group


# ── Windows message reference codes ────────────────────────────────────────────
# Windows stores certain boolean / enum event_data fields as a %%NNNN reference
# pointing into the provider's message catalog.  Event Viewer resolves them to
# text ("Yes" / "No" / "TokenElevationTypeFull"), so users typing those resolved
# values silently fail to match raw %%-codes in the JSON blob.
_YESNO_GROUPS = {
    "%%1842": frozenset({"%%1842", "yes", "true", "1"}),
    "%%1843": frozenset({"%%1843", "no",  "false", "0"}),
}
for _alias in ("yes", "true", "1"):
    _YESNO_GROUPS[_alias] = _YESNO_GROUPS["%%1842"]
for _alias in ("no", "false", "0"):
    _YESNO_GROUPS[_alias] = _YESNO_GROUPS["%%1843"]

_TOKEN_ELEV_GROUPS = {
    "%%1936": frozenset({"%%1936", "default", "tokenelevationtypedefault"}),
    "%%1937": frozenset({"%%1937", "full",    "tokenelevationtypefull"}),
    "%%1938": frozenset({"%%1938", "limited", "tokenelevationtypelimited"}),
}
for _grp in list(_TOKEN_ELEV_GROUPS.values()):
    for _alias in _grp:
        _TOKEN_ELEV_GROUPS[_alias] = _grp


# Per-field symbolic-alias maps.  Each entry: field name → {value → group set}.
# Looking up the user's typed value in the inner dict returns all equivalent
# representations to OR into the SQL clause.
_SYMBOLIC_ALIAS_MAP: dict[str, dict[str, frozenset[str]]] = {
    "LogonType":          _LOGON_TYPE_GROUPS,
    "ElevatedToken":      _YESNO_GROUPS,
    "VirtualAccount":     _YESNO_GROUPS,
    "TokenElevationType": _TOKEN_ELEV_GROUPS,
}


def _expand_symbolic_value(field: str, val: str) -> list[str]:
    """Return symbolic aliases for *val* under *field*.

    Returns ``[val]`` (single-element) when no aliases apply, so the caller
    can decide between the IN-clause branch (len > 1) and the simple equals
    branch.  Lookup is case-insensitive.
    """
    table = _SYMBOLIC_ALIAS_MAP.get(field)
    if table is None:
        return [val]
    key = _norm(val)
    group = table.get(key)
    if group is None:
        return [val]
    # Always include the user's original form too in case it differs from
    # the canonical lowercase one (it usually doesn't after lowering).
    return sorted({val, *group})


def expand_condition_value(field: str, val: str) -> list[str]:
    """Return every representation of *val* the user might mean for *field*.

    Two layers, applied in priority order:

      1. **Field-specific symbolic aliases** (LogonType ↔ "Network" / "RDP";
         ElevatedToken ↔ "Yes" / "%%1842"; TokenElevationType ↔ "Full" /
         "%%1937"; …) — explicit lookup tables for fields whose stored value
         is a completely different STRING from what the user types.

      2. **Hex/decimal expansion** — applied ONLY to ``_HEX_DEC_FIELDS``
         (curated list of fields known to store numerics in hex form).  An
         earlier version applied this UNIVERSALLY and adversarial testing
         exposed real false positives:

         * ``computer = "1234"`` also matched a host named ``"0x4d2"``
           (=decimal 1234) because both were added to the IN-clause.
         * ``contains "100"`` also matched ``"PC0x64"`` because the
           expansion added ``"0x64"`` (=decimal 100) to the OR chain.

         Hostnames, usernames, channels, and other string-typed fields
         can legitimately contain numeric-looking values that must be
         treated literally.  The curated list is the safe rule: expand
         only when we KNOW the field stores numerics.

      3. **Everything else** — return ``[val]`` unchanged.  Literal match.

    Result: typing ``1936`` on ``ProcessId`` correctly matches ``0x790``;
    typing ``1234`` on ``computer`` correctly does NOT match ``0x4d2``.
    """
    # Layer 1 — symbolic alias table
    if field in _SYMBOLIC_ALIAS_MAP:
        return _expand_symbolic_value(field, val)

    # Layer 2 — hex/decimal expansion for known hex-storage fields only.
    # Adding a new field is a one-line edit to _HEX_DEC_FIELDS.
    if field in _HEX_DEC_FIELDS:
        return _expand_hex_dec_value(val)

    # Layer 3 — no expansion. Literal match.
    return [val]


# Hex widths commonly used by Windows when padding PIDs / LogonIds / handles:
#   * unpadded canonical form (e.g. "0x790")
#   * 4-digit  — uncommon but seen on some custom providers
#   * 8-digit  — int32 padding (e.g. AccessMask "0x000F0007")
#   * 16-digit — int64 padding (e.g. Keywords "0x8020000000000000")
# All four are added to the variant set so a user typing "1936" still matches
# a stored "0x00000790" — adversarial testing exposed this gap.
_HEX_PAD_WIDTHS: tuple[int, ...] = (4, 8, 16)


def _expand_hex_dec_value(val: str) -> list[str]:
    """Return the value plus its alternate hex/decimal representation(s).

    Windows EVTX stores PIDs, ThreadIds and LogonIds as hex strings such as
    ``"0x790"`` inside ``event_data_json``, while users typing into the
    Conditions dialog naturally enter ``"1936"`` (and vice-versa).  This
    helper produces every variant so the SQL IN-clause will hit a match
    regardless of which representation was typed.

    **Padding variants are included.**  Some Windows components emit
    zero-padded hex (``"0x000F0007"`` for an AccessMask, ``"0x00000790"`` for
    a 32-bit PID).  The variant set therefore also includes ``"0x0790"``,
    ``"0x00000790"`` and ``"0x0000000000000790"`` for the value 1936 so the
    IN-clause matches regardless of how the source field padded the value.

    Conservative rule for plain numerics without a ``0x`` prefix: only the
    decimal interpretation is expanded.  ``"790"`` becomes ``["790",
    "0x790", ...]`` (i.e. user's literal 790 AND its hex-spelled equivalents
    at multiple widths), while ``"0x790"`` becomes ``["0x790", "1936", ...]``.
    Never tries to interpret a plain unprefixed string as hex first, since
    that would make every decimal silently match a different number.

    Returns deduplicated strings in deterministic (sorted) order so the SQL
    parameter list is stable across calls.
    """
    val = (val or "").strip()
    if not val:
        return [val]

    variants: set[str] = {val}

    def _add_hex_forms(n: int) -> None:
        """Add every reasonable hex spelling of *n* to the variant set."""
        hex_lo = f"{n:x}"
        hex_up = f"{n:X}"
        # Unpadded canonical form
        variants.add(f"0x{hex_lo}")
        variants.add(f"0x{hex_up}")
        # Zero-padded variants — only when the natural width is short
        # enough that padding produces a different string.
        for width in _HEX_PAD_WIDTHS:
            if len(hex_lo) < width:
                variants.add("0x" + hex_lo.zfill(width))
                variants.add("0x" + hex_up.zfill(width))

    # Decimal interpretation: succeeds for "1936" / "-5" / "+12".
    # Negative or signed values are skipped — PIDs are unsigned.
    try:
        n = int(val)
        if n >= 0:
            variants.add(str(n))
            _add_hex_forms(n)
    except ValueError:
        pass

    # Hex interpretation: only when prefixed.  Without this guard "790"
    # would also be parsed as 0x790 = 1936 and silently match unrelated rows.
    low = val.lower()
    if low.startswith("0x"):
        try:
            n = int(val, 16)
            if n >= 0:
                variants.add(str(n))
                _add_hex_forms(n)
        except ValueError:
            pass

    return sorted(variants)

# Windows Event Log level name → integer ID
_LEVEL_NAME_TO_ID: dict[str, int] = {
    "LogAlways":   0,
    "Critical":    1,
    "Error":       2,
    "Warning":     3,
    "Information": 4,
    "Verbose":     5,
}


def _escape_like(s: str) -> str:
    """Escape LIKE/ILIKE special characters in a user-supplied value.

    DuckDB LIKE treats ``%`` (any sequence), ``_`` (any single char), and the
    configured ESCAPE char as special.  User input must be sanitised so that
    e.g. ``SERVER%01`` matches literally instead of acting as a wildcard.
    """
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _level_to_int(x) -> "int | None":
    """Convert a level name or numeric value to int. Returns None for unrecognised values."""
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        if x in _LEVEL_NAME_TO_ID:
            return _LEVEL_NAME_TO_ID[x]
        try:
            return int(x)
        except ValueError:
            return None  # e.g. "Audit Success", "Audit Failure" — not a level int
    return None


def filter_config_to_sql(fc: dict) -> tuple[str, list[Any]]:
    """
    Convert a FilterConfig dict to ``(where_clause, params)``.

    Returns ``("1=1", [])`` when no filters are active.
    """
    if not fc:
        return "1=1", []

    clauses: list[str] = []
    params: list[Any] = []

    cs = fc.get("case_sensitive", False)

    def _like_op() -> str:
        """Return LIKE (case-sensitive) or ILIKE (case-insensitive).

        Using DuckDB's native ILIKE instead of lower(col) LIKE lower(val) avoids
        the per-row lower() call and lets DuckDB use vectorised collation paths.
        Zone maps and bloom filters still apply on the raw column value.
        """
        return "LIKE" if cs else "ILIKE"

    # Keep _lw / _lv for CONTAINS() and json_extract paths that still need lowercasing.
    def _lw(col: str) -> str:
        return col if cs else f"lower({col})"

    def _lv(val: str) -> str:
        return val if cs else val.lower()

    # ── event_ids ─────────────────────────────────────────────────────────
    if fc.get("event_ids"):
        ph = ", ".join("?" * len(fc["event_ids"]))
        clauses.append(f"event_id IN ({ph})")
        params.extend(int(x) for x in fc["event_ids"])

    if fc.get("exclude_event_ids"):
        ph = ", ".join("?" * len(fc["exclude_event_ids"]))
        clauses.append(f"event_id NOT IN ({ph})")
        params.extend(int(x) for x in fc["exclude_event_ids"])

    # ── event_id_expr (ELE-style) ─────────────────────────────────────────
    expr = fc.get("event_id_expr", "")
    if expr:
        try:
            from evtx_tool.core.filters import parse_event_id_expression
            inc_ids, exc_ids = parse_event_id_expression(expr)
            is_exclude_mode = fc.get("event_id_exclude", False)

            if inc_ids:
                ph = ", ".join("?" * len(inc_ids))
                if is_exclude_mode:
                    clauses.append(f"event_id NOT IN ({ph})")
                else:
                    clauses.append(f"event_id IN ({ph})")
                params.extend(sorted(inc_ids))
            if exc_ids:
                ph = ", ".join("?" * len(exc_ids))
                clauses.append(f"event_id NOT IN ({ph})")
                params.extend(sorted(exc_ids))
        except Exception as exc:
            logger.warning("filter_sql: failed to parse event_id_expr %r: %s", expr, exc)

    # ── levels ────────────────────────────────────────────────────────────
    if fc.get("levels"):
        level_ints = [v for x in fc["levels"] if (v := _level_to_int(x)) is not None]
        # Collect level names that have no integer mapping (e.g. "Audit Success",
        # "Audit Failure" — Windows keyword-based levels, not ETW integer levels).
        level_names_only = [
            x for x in fc["levels"]
            if isinstance(x, str) and _level_to_int(x) is None
        ]
        # Skip the clause when ALL standard + keyword levels are present — that
        # is equivalent to "no level filter".  The dialog has 8 checkboxes
        # (6 standard + Audit Success + Audit Failure) and returns [] when all
        # are checked; but if a profile passes all 8, skip the filter.
        _ALL_STANDARD = frozenset([0, 1, 2, 3, 4, 5])
        all_ints_present = (set(level_ints) == _ALL_STANDARD)
        all_names_present = (
            set(level_names_only) >= {"Audit Success", "Audit Failure"}
        )
        # Only skip if BOTH integer levels and keyword levels cover everything
        if not (all_ints_present and (all_names_present or not level_names_only)):
            sub_parts: list[str] = []
            sub_params: list[Any] = []
            if level_ints and set(level_ints) != _ALL_STANDARD:
                ph = ", ".join("?" * len(level_ints))
                sub_parts.append(f"level IN ({ph})")
                sub_params.extend(level_ints)
            # Audit Success / Audit Failure are NOT stored in level_name —
            # they're encoded in the Keywords bitfield (bits 53 and 52 of the
            # 64-bit hex value).  A plain ``level_name IN ('Audit Success',
            # 'Audit Failure')`` clause silently matches zero rows because no
            # row ever has those literal level_name values.  Detect bit 53
            # (Audit Success) and bit 52 (Audit Failure) via a SUBSTRING on
            # the hex string — char 5 (1-indexed) of "0xHHHHHHHHHHHHHHHH" is
            # the audit-flag nibble.
            #   bit 1 of that nibble = Audit Success  → digits 2,3,6,7,A-F-with-bit1
            #   bit 0 of that nibble = Audit Failure  → digits 1,3,5,7,9,B,D,F
            _other_names: list[str] = []
            _audit_clauses: list[str] = []
            for n in level_names_only:
                _n_low = (n or "").strip().lower()
                if _n_low == "audit success":
                    _audit_clauses.append(
                        "LOWER(SUBSTRING(COALESCE(keywords, ''), 5, 1)) "
                        "IN ('2','3','6','7','a','b','e','f')"
                    )
                elif _n_low == "audit failure":
                    _audit_clauses.append(
                        "LOWER(SUBSTRING(COALESCE(keywords, ''), 5, 1)) "
                        "IN ('1','3','5','7','9','b','d','f')"
                    )
                else:
                    _other_names.append(n)
            if _audit_clauses:
                sub_parts.append("(" + " OR ".join(_audit_clauses) + ")")
            if _other_names:
                # Any remaining custom level-name (e.g. a profile-defined
                # vendor-specific level) still uses the literal column compare.
                ph = ", ".join("?" * len(_other_names))
                sub_parts.append(f"level_name IN ({ph})")
                sub_params.extend(_other_names)
            if sub_parts:
                clauses.append(f"({' OR '.join(sub_parts)})")
                params.extend(sub_params)

    # ── date_from / date_to ───────────────────────────────────────────────
    # timestamp_utc is stored as text 'YYYY-MM-DD HH:MM:SS'; SUBSTRING works.
    # Mode is determined by the same checkbox flags used by the normal-mode filter:
    #   date_only  → compare SUBSTRING(timestamp_utc, 1, 10)  (YYYY-MM-DD)
    #   time_only  → compare SUBSTRING(timestamp_utc, 12, 8)  (HH:MM:SS)
    #   separate   → both date portion AND time portion independently
    #   range      → full timestamp_utc text comparison (existing behaviour)
    date_exclude = fc.get("date_exclude", False)
    _date_en     = bool(fc.get("date_enabled"))
    _time_en     = bool(fc.get("time_enabled"))
    _sep_en      = bool(fc.get("separately_enabled"))
    _spec_en     = bool(fc.get("specific_day_enabled"))
    date_from_raw = fc.get("date_from") or ""
    date_to_raw   = fc.get("date_to")   or ""

    if date_from_raw or date_to_raw:
        # Normalise to 'YYYY-MM-DD HH:MM:SS' (strip Z / T separator)
        def _norm(s: str) -> str:
            return s.replace("Z", "").replace("T", " ")[:19]

        df = _norm(date_from_raw) if date_from_raw else ""
        dt = _norm(date_to_raw)   if date_to_raw   else ""

        # Determine mode from checkbox flags
        if _spec_en or (_date_en and _time_en and not _sep_en):
            _dt_mode = "range"
        elif _date_en and _time_en and _sep_en:
            _dt_mode = "separate"
        elif _date_en and not _time_en:
            _dt_mode = "date_only"
        elif _time_en and not _date_en:
            _dt_mode = "time_only"
        else:
            _dt_mode = "range"  # fallback

        # ── Timezone correction ──────────────────────────────────────────
        # The filter dialog emits date_from/date_to in the user's display
        # timezone (e.g. "2025-09-26 00:00:00" means midnight IST when the
        # user views timestamps in IST).  timestamp_utc is stored in UTC.
        # Convert the user's boundary values from the display TZ to UTC so
        # the SQL comparison matches what the user sees in the table.
        try:
            from evtx_tool.gui.models import _tz_state
            from datetime import datetime as _dt_cls, timezone as _tz, timedelta as _td

            _mode = _tz_state.get("mode", "utc")
            _disp_tz = None       # None = UTC, no conversion needed
            _use_system_local = False
            if _mode == "local":
                # Do NOT freeze today's UTC offset into a fixed-offset tzinfo.
                # The boundary belongs to the LOG's date, not to today, and in
                # a DST zone those differ: filtering January logs while sitting
                # in July (EDT) converted midnight to 04:00Z while the table
                # displayed it as 05:00Z — a silent one-hour disagreement
                # between what is filtered and what is shown, i.e. events
                # landing on the wrong day of the timeline.
                # A naive datetime passed to astimezone() is interpreted as
                # system local time and resolved with the rules in force ON
                # THAT DATE, which is what the display already does.
                _use_system_local = True
            elif _mode == "specific":
                try:
                    from zoneinfo import ZoneInfo
                    _disp_tz = ZoneInfo(_tz_state.get("specific", "UTC"))
                except Exception:
                    pass
            elif _mode == "custom":
                _disp_tz = _tz(offset=_td(minutes=_tz_state.get("custom_offset_min", 0)))

            if _disp_tz is not None or _use_system_local:
                def _to_utc(s: str) -> str:
                    """Re-interpret a 'YYYY-MM-DD HH:MM:SS' string from display TZ as UTC."""
                    if not s or len(s) < 19:
                        return s
                    try:
                        naive = _dt_cls.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
                        if _use_system_local:
                            # naive -> treated as system local, DST resolved
                            # for the boundary's own date.
                            utc_dt = naive.astimezone(_tz.utc)
                        else:
                            utc_dt = naive.replace(tzinfo=_disp_tz).astimezone(_tz.utc)
                        return utc_dt.strftime("%Y-%m-%d %H:%M:%S")
                    except Exception:
                        return s
                df = _to_utc(df) if df else ""
                dt = _to_utc(dt) if dt else ""
                # Force to "range" mode.  date_only / time_only / separate use
                # SUBSTRING(timestamp_utc, ...) to compare just the date or
                # time portion, but after TZ conversion those portions are in
                # UTC — not the user's display timezone.  The full timestamp
                # comparison is always correct after conversion.
                if _dt_mode in ("date_only", "time_only", "separate"):
                    _dt_mode = "range"
        except Exception as _exc:
            logger.debug("filter_sql: timezone correction skipped: %s", _exc)

        date_parts: list[str] = []

        if _dt_mode == "date_only":
            if df and len(df) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) >= ?")
                params.append(df[:10])
            if dt and len(dt) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) <= ?")
                params.append(dt[:10])

        elif _dt_mode == "time_only":
            _tf = df[11:19] if len(df) >= 19 else ("00:00:00" if df else "")
            _tt = dt[11:19] if len(dt) >= 19 else ("23:59:59" if dt else "")
            if _tf:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) >= ?")
                params.append(_tf)
            if _tt:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) <= ?")
                params.append(_tt)

        elif _dt_mode == "separate":
            # Date range AND time-of-day range applied independently
            if df and len(df) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) >= ?")
                params.append(df[:10])
            if dt and len(dt) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 10) <= ?")
                params.append(dt[:10])
            _tf = df[11:19] if len(df) >= 19 else ""
            _tt = dt[11:19] if len(dt) >= 19 else ""
            if _tf:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) >= ?")
                params.append(_tf)
            if _tt:
                date_parts.append("SUBSTRING(timestamp_utc, 12, 8) <= ?")
                params.append(_tt)

        else:  # "range" — full timestamp comparison
            # Compare on the second-truncated SUBSTRING: timestamp_utc now
            # carries microseconds ('...SS.ffffff'), and a raw string compare
            # against a seconds-granularity boundary would EXCLUDE events
            # inside the boundary second on the upper bound.  SUBSTRING keeps
            # the filter's second-granularity semantics unchanged.
            if df and len(df) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 19) >= ?")
                params.append(df)
            elif date_from_raw:
                logger.warning("filter_sql: ignoring malformed date_from %r", date_from_raw)
            if dt and len(dt) >= 10:
                date_parts.append("SUBSTRING(timestamp_utc, 1, 19) <= ?")
                params.append(dt)
            elif date_to_raw:
                logger.warning("filter_sql: ignoring malformed date_to %r", date_to_raw)

        if date_parts:
            combined = " AND ".join(date_parts)
            clauses.append(f"NOT ({combined})" if date_exclude else f"({combined})")

    # ── relative_days / relative_hours ────────────────────────────────────
    try:
        rel_days = int(fc.get("relative_days", 0) or 0)
    except (TypeError, ValueError):
        logger.warning("filter_sql: ignoring non-numeric relative_days %r", fc.get("relative_days"))
        rel_days = 0
    try:
        rel_hours = int(fc.get("relative_hours", 0) or 0)
    except (TypeError, ValueError):
        logger.warning("filter_sql: ignoring non-numeric relative_hours %r", fc.get("relative_hours"))
        rel_hours = 0
    if rel_days > 0 or rel_hours > 0:
        total_hours = rel_days * 24 + rel_hours
        rel_exclude = fc.get("relative_exclude", False)
        # DuckDB: use CURRENT_TIMESTAMP - INTERVAL
        cutoff_expr = f"(CURRENT_TIMESTAMP - INTERVAL '{total_hours} hours')::VARCHAR"
        if rel_exclude:
            clauses.append(f"timestamp_utc < {cutoff_expr}")
        else:
            clauses.append(f"timestamp_utc >= {cutoff_expr}")

    # ── computers ─────────────────────────────────────────────────────────
    if fc.get("computers"):
        comp_exclude = fc.get("computer_exclude", False)
        op = _like_op()
        sub = " OR ".join(f"computer {op} ? ESCAPE '\\'" for _ in fc["computers"])
        params.extend(f"%{_escape_like(c)}%" for c in fc["computers"])
        clause = f"({sub})"
        clauses.append(f"NOT {clause}" if comp_exclude else clause)

    # ── sources ───────────────────────────────────────────────────────────
    if fc.get("sources"):
        src_exclude = fc.get("source_exclude", False)
        op = _like_op()
        sub_parts = []
        for s in fc["sources"]:
            sub_parts.append(f"provider {op} ? ESCAPE '\\'")
            sub_parts.append(f"channel {op} ? ESCAPE '\\'")
            _es = _escape_like(s)
            params.extend([f"%{_es}%", f"%{_es}%"])
        clause = f"({' OR '.join(sub_parts)})"
        clauses.append(f"NOT {clause}" if src_exclude else clause)

    # ── categories (channel names) ────────────────────────────────────────
    if fc.get("categories"):
        cat_exclude = fc.get("category_exclude", False)
        op = _like_op()
        sub = " OR ".join(f"channel {op} ? ESCAPE '\\'" for _ in fc["categories"])
        params.extend(f"%{_escape_like(c)}%" for c in fc["categories"])
        clause = f"({sub})"
        clauses.append(f"NOT {clause}" if cat_exclude else clause)

    # ── users ──────────────────────────────────────────────────────────────
    # Checks user_id (System/Security header SID), ed_subject_user
    # (SubjectUserName), ed_target_user (TargetUserName), and the two SID
    # columns ed_subject_sid / ed_target_sid — all pre-extracted Arrow columns.
    # Matches the normal-mode filter (filters.py), which searches the same six
    # identity fields, so a SID user-filter no longer under-matches in JM.
    if fc.get("users"):
        usr_exclude = fc.get("user_exclude", False)
        op = _like_op()
        sub_parts = []
        for u in fc["users"]:
            _eu = _escape_like(u)
            for col in ("ed_subject_user", "ed_target_user", "user_id",
                        "ed_subject_sid", "ed_target_sid"):
                sub_parts.append(f"{col} {op} ? ESCAPE '\\'")
                params.append(f"%{_eu}%")
        clause = f"({' OR '.join(sub_parts)})"
        clauses.append(f"NOT {clause}" if usr_exclude else clause)

    # ── task_categories ───────────────────────────────────────────────────
    if fc.get("task_categories"):
        task_ints = []
        for x in fc["task_categories"]:
            try:
                task_ints.append(int(x))
            except (ValueError, TypeError):
                logger.warning("filter_sql: skipping non-numeric task_category %r", x)
        if task_ints:
            ph = ", ".join("?" * len(task_ints))
            clauses.append(f"task IN ({ph})")
            params.extend(task_ints)

    # ── text_search ───────────────────────────────────────────────────────
    text_terms = fc.get("text_search")
    if text_terms:
        if isinstance(text_terms, str):
            text_terms = [text_terms]

        mode = fc.get("search_mode", "AND").upper()
        text_regex = fc.get("text_regex", False)
        text_exclude = fc.get("text_exclude", False)

        # Case-SENSITIVE search runs against the RAW (non-lowered) blob; the
        # lower()-wrapped expression would pre-lower the data so an upper-case
        # term could never match.
        _texpr = _SEARCH_TEXT_RAW if cs else SEARCH_TEXT_EXPR

        def _term_clause(term: str) -> str:
            if text_regex:
                # DuckDB native: regexp_matches(expr, pattern [, flags])
                # 'i' flag = case-insensitive; omit for case-sensitive.
                if cs:
                    params.append(term)
                    return f"regexp_matches({_texpr}, ?)"
                else:
                    params.append(term.lower())
                    return f"regexp_matches({_texpr}, ?, 'i')"
            else:
                params.append(_lv(term))
                return f"CONTAINS({_texpr}, ?)"

        term_clauses = [_term_clause(t) for t in text_terms]
        if mode == "AND":
            combined = f"({' AND '.join(term_clauses)})"
        elif mode == "OR":
            combined = f"({' OR '.join(term_clauses)})"
        elif mode == "NOT":
            combined = f"NOT ({' OR '.join(term_clauses)})"
        else:
            combined = f"({' AND '.join(term_clauses)})"

        if text_exclude and mode != "NOT":
            combined = f"NOT {combined}"
        clauses.append(combined)

    # ── conditions (custom field operators) ────────────────────────────────
    for cond in fc.get("conditions", []):
        name = cond.get("name", "")
        if not name:
            continue

        # Build the list of SQL expressions to check.  Normally one entry.
        # For dual-source fields (ProcessId/ThreadId) we add a SECOND entry
        # referencing the top-level column, so the user finds matches
        # regardless of which storage layer holds the PID (event_data vs
        # <Execution>).  See _FIELD_DUAL_SOURCE.
        base_exprs: list[str] = []
        if name in _TOP_LEVEL_COLS:
            # Direct column reference — safe (name comes from a known allowlist).
            # CAST to VARCHAR so all string operators work uniformly even on
            # integer columns like event_id.
            base_exprs.append(f"CAST({name} AS VARCHAR)")
        elif _SAFE_JSON_KEY_RE.match(name):
            # Simple identifier — use dot notation: $.FieldName.
            # ed_flat_json (flattened field map), NOT event_data_json (which is
            # the nested original), so a condition on a field nested inside a
            # container element resolves — matching normal mode.
            base_exprs.append(f"json_extract_string(ed_flat_json, '$.{name}')")
            # Some event_data names also have a top-level column counterpart
            # (ProcessId / ThreadId) — query both.
            _dual = _FIELD_DUAL_SOURCE.get(name)
            if _dual is not None:
                base_exprs.append(f"CAST({_dual} AS VARCHAR)")
        elif '"' not in name and "\\" not in name and "\x00" not in name:
            # Field name contains spaces or other special characters but is
            # otherwise safe — use JSONPath double-quote bracket notation:
            # json_extract_string(col, '$."My Field Name"').
            # Escape single quotes (double them) so a name containing ' cannot
            # terminate the surrounding SQL string literal — otherwise the query
            # errors and the filter thread silently falls back to showing ALL
            # rows (fail-open), or the name becomes an injection vector.
            _safe_name = name.replace("'", "''")
            base_exprs.append(f'json_extract_string(ed_flat_json, \'$."{_safe_name}"\')')
        else:
            logger.warning("filter_sql: skipping condition with unsafe field name %r", name)
            continue

        op = cond.get("operator", "contains")
        val = cond.get("value", "")
        # Use the FIRST expression for backwards-compatible variable names —
        # operator branches below loop over all base_exprs and OR them.
        base_expr = base_exprs[0]
        field_expr = base_expr
        if not cs:
            field_expr = f"lower({field_expr})"
            val = val.lower()

        # Many event_data fields are stored in a form different from what the
        # user sees in Event Viewer.  expand_condition_value() handles both:
        #
        #   * Numeric values are expanded to hex AND decimal forms universally
        #     (any field — no curated list).  Typing "1936" matches "0x790"
        #     and vice-versa for ProcessId, NewProcessId, TargetLogonId,
        #     HandleId, custom Sysmon fields, third-party providers, etc.
        #   * Field-specific symbolic aliases apply where the stored form is a
        #     completely different STRING (LogonType "3" ↔ "Network" / "RDP",
        #     ElevatedToken "%%1842" ↔ "Yes" / "true", TokenElevationType
        #     "%%19xx" ↔ symbolic names).
        #
        # Returns ≥1 element; len > 1 means at least one variant was added.
        _variants: list[str] = []
        if op in ("equals", "not equals", "contains", "not contains"):
            _variants = expand_condition_value(name, val)
            if len(_variants) > 1 and not cs:
                _variants = sorted({v.lower() for v in _variants})
            elif len(_variants) <= 1:
                # No expansion applied — clear so the simple-value path runs
                _variants = []

        # Build a list of (lowered) field_exprs, one per base_expr, so each
        # operator branch below can OR across all of them.  For most fields
        # this is a single-element list; only ProcessId/ThreadId produce two.
        field_exprs: list[str] = []
        for _b in base_exprs:
            field_exprs.append(f"lower({_b})" if not cs else _b)

        def _multi_or(per_expr_sql_fmt: str, *, params_per_expr: list) -> str:
            """Build OR across every field_expr with the SAME params each time.

            ``per_expr_sql_fmt`` has one ``{f}`` placeholder where field_expr
            goes.  ``params_per_expr`` is the list of params to append PER
            field_expr (caller repeats them in the params list).
            """
            sub = " OR ".join(per_expr_sql_fmt.format(f=fe) for fe in field_exprs)
            return f"({sub})" if len(field_exprs) > 1 else sub

        n_fe = len(field_exprs)

        if op == "contains":
            if len(_variants) > 1:
                # OR every variant × every field_expr.
                sub_per_expr = " OR ".join(
                    "CONTAINS(COALESCE({f}, ''), ?)" for _ in _variants
                )
                _full = _multi_or("(" + sub_per_expr + ")", params_per_expr=_variants)
                clauses.append(_full)
                # Repeat the variant list once per field_expr
                for _ in range(n_fe):
                    params.extend(_variants)
            else:
                clauses.append(_multi_or("CONTAINS(COALESCE({f}, ''), ?)", params_per_expr=[val]))
                for _ in range(n_fe):
                    params.append(val)
        elif op == "equals":
            if len(_variants) > 1:
                ph = ", ".join("?" * len(_variants))
                clauses.append(_multi_or(f"COALESCE({{f}}, '') IN ({ph})", params_per_expr=_variants))
                for _ in range(n_fe):
                    params.extend(_variants)
            else:
                clauses.append(_multi_or("COALESCE({f}, '') = ?", params_per_expr=[val]))
                for _ in range(n_fe):
                    params.append(val)
        elif op == "starts with":
            clauses.append(_multi_or("COALESCE({f}, '') LIKE ? ESCAPE '\\'", params_per_expr=[]))
            for _ in range(n_fe):
                params.append(f"{_escape_like(val)}%")
        elif op == "ends with":
            clauses.append(_multi_or("COALESCE({f}, '') LIKE ? ESCAPE '\\'", params_per_expr=[]))
            for _ in range(n_fe):
                params.append(f"%{_escape_like(val)}")
        elif op == "not contains":
            # "not contains" must hold for ALL sources (AND), not "matches none of them" (OR)
            if len(_variants) > 1:
                sub_per_expr = " OR ".join(
                    "CONTAINS(COALESCE({f}, ''), ?)" for _ in _variants
                )
                # For each field_expr, build a NOT(...) wrapper, then AND them.
                neg_parts = [f"NOT ({sub_per_expr.format(f=fe)})" for fe in field_exprs]
                clauses.append("(" + " AND ".join(neg_parts) + ")")
                for _ in range(n_fe):
                    params.extend(_variants)
            else:
                neg_parts = [f"NOT CONTAINS(COALESCE({fe}, ''), ?)" for fe in field_exprs]
                clauses.append("(" + " AND ".join(neg_parts) + ")")
                for _ in range(n_fe):
                    params.append(val)
        elif op == "not equals":
            # Same as not-contains — must hold for every source
            if len(_variants) > 1:
                ph = ", ".join("?" * len(_variants))
                neg_parts = [f"COALESCE({fe}, '') NOT IN ({ph})" for fe in field_exprs]
                clauses.append("(" + " AND ".join(neg_parts) + ")")
                for _ in range(n_fe):
                    params.extend(_variants)
            else:
                neg_parts = [f"COALESCE({fe}, '') != ?" for fe in field_exprs]
                clauses.append("(" + " AND ".join(neg_parts) + ")")
                for _ in range(n_fe):
                    params.append(val)
        elif op == "regex":
            # DuckDB native regex — case flag applied based on cs setting.
            # Use base_exprs (without lower wrap) so the regex sees the
            # original case when cs=True; the 'i' flag handles c-i matching.
            raw_val = cond.get("value", "")
            raw_fields = [f"COALESCE({be}, '')" for be in base_exprs]
            if cs:
                sub = " OR ".join(f"regexp_matches({rf}, ?)" for rf in raw_fields)
            else:
                sub = " OR ".join(f"regexp_matches({rf}, ?, 'i')" for rf in raw_fields)
            clauses.append(f"({sub})" if len(raw_fields) > 1 else sub)
            for _ in raw_fields:
                params.append(raw_val)
        elif op == "greater than":
            # DuckDB TRY_CAST — safe equivalent of SQLite's CAST (won't crash on non-numeric)
            sub = " OR ".join(
                f"TRY_CAST({fe} AS DOUBLE) > TRY_CAST(? AS DOUBLE)" for fe in field_exprs
            )
            clauses.append(f"({sub})" if n_fe > 1 else sub)
            for _ in range(n_fe):
                params.append(val)
        elif op == "less than":
            sub = " OR ".join(
                f"TRY_CAST({fe} AS DOUBLE) < TRY_CAST(? AS DOUBLE)" for fe in field_exprs
            )
            clauses.append(f"({sub})" if n_fe > 1 else sub)
            for _ in range(n_fe):
                params.append(val)
        else:
            # Unknown operator — fail CLOSED (match no rows) to mirror normal
            # mode's _conditions_pass, which returns False.  Without this a
            # typo'd/hand-edited operator would silently pass every event in JM
            # while dropping every event in normal mode — a silent divergence.
            logger.warning("filter_sql: unknown condition operator %r — matching no rows", op)
            clauses.append("1=0")

    if not clauses:
        return "1=1", []
    return " AND ".join(clauses), params


def text_config_to_parquet_sql(fc: dict) -> "tuple[str, list[Any]]":
    """
    Build a CONTAINS / regexp_matches clause for Phase 2 Parquet-based text search.

    Uses SEARCH_TEXT_EXPR_FULL (which includes event_data_json) so that event-data
    values — file paths, process names, package names, etc. — are matched even
    though they are not present in the in-memory Arrow table.

    Called by _FilterThread._apply_with_full_text_search(); never called by
    filter_config_to_sql() (Arrow table path).
    """
    text_terms = fc.get("text_search")
    if not text_terms:
        return "1=1", []
    if isinstance(text_terms, str):
        text_terms = [text_terms]

    cs         = fc.get("case_sensitive", False)
    text_regex = fc.get("text_regex", False)
    text_excl  = fc.get("text_exclude", False)
    mode       = fc.get("search_mode", "AND").upper()
    params: list[Any] = []

    def _lv(val: str) -> str:
        return val if cs else val.lower()

    # Case-SENSITIVE search must run against the RAW (non-lowered) blob — using
    # the lower()-wrapped expression pre-lowers the data so an upper-case term
    # could never match (previously returned zero rows for e.g. "MSI" + cs).
    _expr = _SEARCH_TEXT_RAW_FULL if cs else SEARCH_TEXT_EXPR_FULL

    def _term_clause(term: str) -> str:
        if text_regex:
            # DuckDB native: regexp_matches(expr, pattern [, 'i' flag])
            if cs:
                params.append(term)
                return f"regexp_matches({_expr}, ?)"
            else:
                params.append(term.lower())
                return f"regexp_matches({_expr}, ?, 'i')"
        else:
            params.append(_lv(term))
            return f"CONTAINS({_expr}, ?)"

    term_clauses = [_term_clause(t) for t in text_terms]
    if mode == "AND":
        combined = f"({' AND '.join(term_clauses)})"
    elif mode == "OR":
        combined = f"({' OR '.join(term_clauses)})"
    elif mode == "NOT":
        combined = f"NOT ({' OR '.join(term_clauses)})"
    else:
        combined = f"({' AND '.join(term_clauses)})"

    if text_excl and mode != "NOT":
        combined = f"NOT {combined}"

    return combined, params
