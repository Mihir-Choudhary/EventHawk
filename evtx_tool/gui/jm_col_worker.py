"""
ColValueWorker — background QThread for Juggernaut Mode column filter popups.

Runs the GROUP BY COUNT(*) query on its own DuckDB connection so the main
thread is never blocked waiting for the result.  The popup is shown only
after the worker emits its finished signal.
"""

from __future__ import annotations

import logging
import os

from PySide6.QtCore import QThread, Signal

logger = logging.getLogger(__name__)


# Whitelist of col_key → SQL expression.
# Used by both ColValueWorker (JM/Arrow GROUP BY) and NormalColValueWorker
# (_ALLOWED_KEYS check only — the actual lookup uses ev.get(col_key) directly).
_COL_MAP: dict[str, str] = {
    # ── Default visible columns ────────────────────────────────────────────
    "event_id":       "CAST(event_id AS VARCHAR)",
    "level_name":     "level_name",
    "computer":       "computer",
    "channel":        "channel",
    "user_id":        "user_id",
    "source_file":    "source_file",
    # timestamp_date is intentionally absent here — its expression depends on
    # the runtime display-TZ state.  Use ``resolve_col_expr()`` instead so
    # popup values and filters BOTH show display-TZ dates that match what the
    # user sees in the event table.
    # ── Extended columns ──────────────────────────────────────────────────
    "provider":       "provider",
    "keywords":       "keywords",
    # opcode is int32 in the JM schema; cast to string for display/compare.
    "opcode":         "CAST(opcode AS VARCHAR)",
    # JM schema has no separate "log" column; channel is the display fallback.
    "log":            "channel",
    "process_id":     "CAST(process_id AS VARCHAR)",
    "thread_id":      "CAST(thread_id AS VARCHAR)",
    # processor_id / session_id have no JM counterpart — omitted intentionally.
    "correlation_id": "correlation_id",
    "record_id":      "CAST(record_id AS VARCHAR)",
}


def _tz_offset_seconds() -> int:
    """Return current display-TZ offset in seconds (0 for UTC / unknown).

    Read at every call so a TZ change is reflected on the next filter or
    popup rebuild — without this, the JM ``timestamp_date`` quick filter
    silently fell back to UTC and the popup values disagreed with the
    table's display-TZ dates.
    """
    try:
        from evtx_tool.gui.models import _tz_state
    except Exception:
        return 0
    mode = _tz_state.get("mode", "utc")
    try:
        if mode == "utc":
            return 0
        if mode == "specific":
            from zoneinfo import ZoneInfo
            from datetime import datetime as _dt
            tz = ZoneInfo(_tz_state.get("specific", "UTC") or "UTC")
            off = _dt.now(tz).utcoffset()
            return int(off.total_seconds()) if off is not None else 0
        if mode == "local":
            from datetime import datetime as _dt
            off = _dt.now().astimezone().utcoffset()
            return int(off.total_seconds()) if off is not None else 0
        if mode == "custom":
            return int(_tz_state.get("custom_offset_min", 0) or 0) * 60
    except Exception:
        return 0
    return 0


def _timestamp_date_expr() -> str:
    """DuckDB expression for the YYYY-MM-DD label in the display timezone.

    Mode-specific strategy:

      * ``utc``        — no conversion needed; return the cheap string slice.
      * ``specific``   — use DuckDB's ``AT TIME ZONE`` (ICU extension) so each
                         event's offset is computed in its OWN DST period.
                         INTERVAL arithmetic with a single offset would be off
                         by 1 hour at DST boundaries.
      * ``local``      — fixed offset from the system's CURRENT local TZ.
                         Acceptable for most forensic queries; DST-period
                         drift at the time-of-call is a known limitation.
      * ``custom``     — fixed offset by definition.

    Falls back to the UTC string slice on any error so a malformed TZ state
    cannot break the popup / quick-filter pipeline.
    """
    try:
        from evtx_tool.gui.models import _tz_state as _state
    except Exception:
        return "LEFT(CAST(timestamp_utc AS VARCHAR), 10)"
    mode = _state.get("mode", "utc")

    if mode == "utc":
        return "LEFT(CAST(timestamp_utc AS VARCHAR), 10)"

    if mode == "specific":
        tz_name = (_state.get("specific") or "UTC").replace("'", "''")
        # CAST string → naive TIMESTAMP
        # AT TIME ZONE 'UTC' → TIMESTAMPTZ (treat the naive value as UTC)
        # AT TIME ZONE '<name>' → TIMESTAMP in that zone (DST-aware per event)
        # strftime → 'YYYY-MM-DD'
        return (
            "strftime("
            "CAST(timestamp_utc AS TIMESTAMP) AT TIME ZONE 'UTC' "
            f"AT TIME ZONE '{tz_name}', "
            "'%Y-%m-%d')"
        )

    # local / custom — offset-based fallback (no per-event DST awareness).
    off = _tz_offset_seconds()
    if off == 0:
        return "LEFT(CAST(timestamp_utc AS VARCHAR), 10)"
    sign = "+" if off > 0 else "-"
    return (
        "strftime("
        f"CAST(timestamp_utc AS TIMESTAMP) {sign} INTERVAL '{abs(off)} seconds', "
        "'%Y-%m-%d')"
    )


def resolve_col_expr(col_key: str) -> str | None:
    """Return the DuckDB expression for a quick-filter column key.

    Wraps ``_COL_MAP`` so the dynamic ``timestamp_date`` expression (which
    depends on the live display-TZ state) is built fresh on every lookup.
    Returns ``None`` for unknown keys (mirrors ``_COL_MAP.get`` semantics).
    """
    if col_key == "timestamp_date":
        return _timestamp_date_expr()
    return _COL_MAP.get(col_key)


# ── No-op shim kept for any external code that imports _register_regexp ────────
def _register_regexp(con) -> None:  # noqa: D401
    """No-op for DuckDB — regexp_matches() is built-in."""
    pass


def build_cascade_where(
    exclude_col_key: str,
    quick_filters: list[dict],
) -> tuple[str | None, list]:
    """Build a DuckDB WHERE clause from active quick filters, excluding one column.

    Used by ColValueWorker so the GROUP BY only counts values that are
    actually visible in the current filtered view (cascading filter).
    The current column's own filter is excluded so the popup still shows
    all of its possible values — not just the ones already selected.

    Returns (where_sql, params), or (None, []) if nothing to cascade.
    """
    include_by_expr: dict[str, list[str]] = {}
    exclude_by_expr: dict[str, list[str]] = {}

    for f in quick_filters:
        k = f.get("key", "")
        if k == exclude_col_key:
            continue                 # skip this column's own filter
        # Use resolve_col_expr so the dynamic timestamp_date expression
        # (display-TZ aware) is picked up here too.
        expr = resolve_col_expr(k)
        if not expr:
            continue
        v = str(f.get("value", "")).lower()  # always lower — JM doesn't enforce it on insert
        if f.get("include", True):
            include_by_expr.setdefault(expr, []).append(v)
        else:
            exclude_by_expr.setdefault(expr, []).append(v)

    parts:  list[str] = []
    params: list      = []

    for expr, values in include_by_expr.items():
        placeholders = ", ".join("?" for _ in values)
        parts.append(f"LOWER(CAST({expr} AS VARCHAR)) IN ({placeholders})")
        params.extend(values)

    for expr, values in exclude_by_expr.items():
        placeholders = ", ".join("?" for _ in values)
        parts.append(f"LOWER(CAST({expr} AS VARCHAR)) NOT IN ({placeholders})")
        params.extend(values)

    if not parts:
        return None, []
    return " AND ".join(parts), params


class NormalColValueWorker(QThread):
    """Count distinct column values from an in-memory event list on a background thread.

    Used by normal (non-Juggernaut) mode so the main thread is never blocked
    waiting for the count loop to finish.  Same interface as ColValueWorker —
    emits ``finished(dict)`` with ``{value_str: count_int}``.

    ``cascade_filters`` mirrors the proxy's _quick_filters list (minus the
    current column) so only values visible in the current view are counted.
    """

    finished = Signal(dict)

    # timestamp_date is intentionally not in _COL_MAP (it's dynamic — see
    # _timestamp_date_expr).  Re-add it here so the NormalColValueWorker
    # gate still recognises it as a valid quick-filter key.
    _ALLOWED_KEYS: frozenset = frozenset({*_COL_MAP.keys(), "timestamp_date"})

    def __init__(
        self,
        events: list,
        col_key: str,
        cascade_filters: list[dict] | None = None,
        parent=None,
    ):
        super().__init__(parent)
        self._events  = events
        self._col_key = col_key
        # Pre-build O(1) lookup sets from cascade_filters —
        # mirrors filterAcceptsRow Layer 4 logic in the proxy model.
        self._cascade_excludes: dict[str, set[str]] = {}
        self._cascade_includes: dict[str, set[str]] = {}
        for f in (cascade_filters or []):
            k = f.get("key", "")
            v = str(f.get("value", ""))   # already lower-cased
            if f.get("include", True):
                self._cascade_includes.setdefault(k, set()).add(v)
            else:
                self._cascade_excludes.setdefault(k, set()).add(v)

    @staticmethod
    def _ev_val(ev: dict, key: str) -> str:
        """Return the lower-cased quick-filter value for *key* from *ev*.

        "timestamp_date" is a virtual key that yields the display-timezone date
        (YYYY-MM-DD) so cascade filtering matches the popup values shown to the
        user, even after a timezone change.
        "log" falls back to channel if the raw log field is absent.
        """
        if key == "timestamp_date":
            return NormalColValueWorker._display_date(ev.get("timestamp", ""))
        if key == "log":
            return str(ev.get("log") or ev.get("channel", "")).lower()
        return str(ev.get(key, "")).lower()

    @staticmethod
    def _display_date(raw_ts: str) -> str:
        """Convert a raw UTC ISO timestamp to display-timezone YYYY-MM-DD (lowercased)."""
        if not raw_ts:
            return ""
        try:
            from evtx_tool.gui.models import apply_tz as _apply_tz
            return _apply_tz(raw_ts)[:10].lower()
        except Exception:
            return str(raw_ts)[:10].lower()

    def run(self) -> None:
        if self._col_key not in self._ALLOWED_KEYS:
            self.finished.emit({})
            return
        try:
            counts: dict[str, int] = {}
            has_excl = bool(self._cascade_excludes)
            has_incl = bool(self._cascade_includes)
            for ev in self._events:
                # ── Cascade filter (same AND logic as proxy filterAcceptsRow) ──
                if has_excl:
                    skip = False
                    for k, excl_set in self._cascade_excludes.items():
                        if self._ev_val(ev, k) in excl_set:
                            skip = True
                            break
                    if skip:
                        continue
                if has_incl:
                    skip = False
                    for k, incl_set in self._cascade_includes.items():
                        if self._ev_val(ev, k) not in incl_set:
                            skip = True
                            break
                    if skip:
                        continue
                # Extract the column value; virtual keys need special treatment.
                if self._col_key == "timestamp_date":
                    # Use display-timezone date so popup values match the table.
                    s = self._display_date(ev.get("timestamp", ""))
                elif self._col_key == "log":
                    s = str(ev.get("log") or ev.get("channel", ""))
                else:
                    raw = ev.get(self._col_key)
                    if raw is None:
                        continue
                    s = str(raw)
                if s:
                    counts[s] = counts.get(s, 0) + 1
            top = dict(sorted(counts.items(), key=lambda x: -x[1])[:1000])
            self.finished.emit(top)
        except Exception as exc:
            logger.warning("NormalColValueWorker: col_key=%r  error: %s",
                           self._col_key, exc)
            self.finished.emit({})


class ColValueWorker(QThread):
    """
    Run GROUP BY COUNT(*) on a background thread using an in-memory DuckDB
    connection registered against the Arrow table from ArrowTableModel.

    Accepts a pa.Table (not a parquet_dir string) — no file I/O, no lock
    conflicts, no dependency on the defunct open_session_duck() function.
    """

    finished = Signal(dict)   # {value_str: count_int}

    def __init__(self, arrow_table: "pa.Table", col_key: str,
                 where_sql: "str | None" = None,
                 where_params: "list | None" = None,
                 parent=None):
        super().__init__(parent)
        self._table        = arrow_table
        self._col_key      = col_key
        self._where_sql    = where_sql
        self._where_params = list(where_params or [])

    def run(self) -> None:
        # resolve_col_expr handles timestamp_date specially — its expression
        # depends on the current display-TZ state and must be rebuilt fresh.
        expr = resolve_col_expr(self._col_key)
        if not expr:
            self.finished.emit({})
            return
        try:
            import duckdb
            con = duckdb.connect()
            con.register("events", self._table)
            try:
                base = f"({self._where_sql}) AND " if self._where_sql else ""
                rows = con.execute(
                    f"SELECT {expr}, COUNT(*) FROM events "
                    f"WHERE {base}{expr} IS NOT NULL "
                    f"GROUP BY {expr} ORDER BY COUNT(*) DESC LIMIT 1000",
                    self._where_params,
                ).fetchall()
                self.finished.emit(
                    {(str(r[0]) if r[0] is not None else ""): r[1] for r in rows}
                )
            finally:
                con.close()
        except Exception as exc:
            logger.warning("ColValueWorker: col_key=%r  error: %s", self._col_key, exc)
            self.finished.emit({})
