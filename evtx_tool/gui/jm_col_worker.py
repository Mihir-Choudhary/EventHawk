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
_COL_MAP: dict[str, str] = {
    "event_id":    "CAST(event_id AS VARCHAR)",
    "level_name":  "level_name",
    "computer":    "computer",
    "channel":     "channel",
    "user_id":     "user_id",
    "source_file": "source_file",
}


# ── No-op shim kept for any external code that imports _register_regexp ────────
def _register_regexp(con) -> None:  # noqa: D401
    """No-op for DuckDB — regexp_matches() is built-in."""
    pass


class NormalColValueWorker(QThread):
    """Count distinct column values from an in-memory event list on a background thread.

    Used by normal (non-Juggernaut) mode so the main thread is never blocked
    waiting for the count loop to finish.  Same interface as ColValueWorker —
    emits ``finished(dict)`` with ``{value_str: count_int}``.
    """

    finished = Signal(dict)

    _ALLOWED_KEYS: frozenset = frozenset(_COL_MAP.keys())

    def __init__(self, events: list, col_key: str, parent=None):
        super().__init__(parent)
        self._events  = events
        self._col_key = col_key

    def run(self) -> None:
        if self._col_key not in self._ALLOWED_KEYS:
            self.finished.emit({})
            return
        try:
            counts: dict[str, int] = {}
            for ev in self._events:
                val = ev.get(self._col_key)
                if val is None:
                    continue
                s = str(val)
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
        expr = _COL_MAP.get(self._col_key)
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
