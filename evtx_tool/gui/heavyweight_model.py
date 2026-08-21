"""
ArrowTableModel — in-memory Apache Arrow QAbstractTableModel (Architecture 1).

Data flow:
  1. load_arrow_table(parquet_dir) reads Parquet shards into a single pa.Table
     (~114 MB for 6M rows with dictionary-encoded string columns).
  2. ArrowTableModel wraps that table. data() reads Arrow buffers directly —
     O(1) per cell, zero I/O, zero background threads during scroll.
  3. _FilterThread (single QThread) owns one in-memory DuckDB connection
     registered against the full Arrow table. Filter changes are dispatched to
     the thread's queue; stale results are discarded via generation counter.
  4. event_data_json is lazy-loaded from Parquet on row selection (<20 ms on
     SSD). An LRU cache of 100 entries avoids repeated Parquet I/O.

This eliminates every failure mode of the previous worker-per-scroll design:
  no file lock conflicts, no OOM from concurrent allocations, no scroll storms.
"""

from __future__ import annotations

import json
import logging
import os
import queue as _queue_module
from collections import OrderedDict
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel, QModelIndex, Qt, QThread, Signal, Slot,
)
from PySide6.QtGui import QColor, QFont

logger = logging.getLogger(__name__)

# ── Shared column/colour imports from the normal-mode model ───────────────────

from evtx_tool.gui.models import (
    COLUMNS,
    COL_ATTACK,
    COL_CHANNEL,
    COL_COMPUTER,
    COL_CORR_ID,
    COL_EID,
    COL_KERN_TIME,
    COL_KEYWORDS,
    COL_LEVEL,
    COL_LOG,
    COL_NUM,
    COL_OPCODE,
    COL_PID,
    COL_PROC_ID,
    COL_PROC_TIME,
    COL_PROVIDER,
    COL_RECORD_ID,
    COL_SID,
    COL_SOURCE,
    COL_TID,
    COL_TS,
    COL_USER,
    COL_USER_TIME,
    apply_tz,
)

# ── Colour palette ─────────────────────────────────────────────────────────────

_LEVEL_FG = {
    "Critical":    QColor("#a01800"),
    "Error":       QColor("#a01800"),
    "Warning":     QColor("#7a4c00"),
    "Information": QColor("#1e1a14"),
    "Verbose":     QColor("#9a8878"),
    "LogAlways":   QColor("#9a8878"),
}

_BG_NORMAL   = QColor("#f5f0e8")
_BG_ALT      = QColor("#ede8d8")
_BG_BOOKMARK = QColor("#e8c96e")   # amber highlight for bookmarked rows
_MONO_FONT   = QFont("Consolas", 9)
_COLOR_GRAY  = QColor("#9a8878")

# ── Visible window cache size ──────────────────────────────────────────────────
# Rows loaded from Arrow per slice — amortises Python/C++ boundary call overhead.
_CACHE_WINDOW = 600

# LRU cap for lazy-loaded event_data_json blobs.
_EVENT_DATA_CACHE_SIZE = 100

# ── Sort column map (Arrow column name → used by sort_by) ─────────────────────
_SORT_COL_MAP: dict[int, str] = {
    COL_NUM:       "row_id",
    COL_EID:       "event_id",
    COL_LEVEL:     "level_name",
    COL_TS:        "timestamp_utc",
    COL_COMPUTER:  "computer",
    COL_CHANNEL:   "channel",
    COL_USER:      "user_id",
    COL_SOURCE:    "source_file",
    COL_RECORD_ID: "record_id",
    COL_PROVIDER:  "provider",
}

# ── Text-search expression — single canonical definition lives in filter_sql ───
# Imported so apply_text_filter() and filter_sql._term_clause() always use the
# exact same blob. No risk of the two drifting out of sync.
from evtx_tool.core.heavyweight.filter_sql import SEARCH_TEXT_EXPR as _ARROW_SEARCH_EXPR  # noqa: E402


# ── Single filter background thread ───────────────────────────────────────────

class _FilterThread(QThread):
    """
    Owns one in-memory DuckDB connection registered against the full Arrow table.
    Receives filter specs from a SimpleQueue. Drains the queue before executing
    so that rapid filter changes only process the latest request (never stale).
    Emits ``done(filtered_table, generation)`` on the main thread via Qt signal.

    Two-phase filtering when conditions are present:
      Phase 1 — metadata WHERE clause against Arrow table (no I/O)
      Phase 2 — condition clauses against event_data_json in Parquet shards via JOIN

    Sorting happens HERE, not on the GUI thread.  It used to run in
    ``_on_filter_done`` (a Slot, i.e. the main thread) and again in ``sort()``,
    so every filter change and every column-header click blocked the UI for the
    length of a full-table sort — the busy indicator could not even repaint,
    because the thread it lives on was the one stalled.  On the common
    metadata-only path the sort is now fused into the DuckDB query as ORDER BY,
    so DuckDB sorts row_ids in parallel and ``take()`` yields an already-ordered
    table with no separate Arrow sort pass at all.
    """

    done = Signal(object, int)   # (pa.Table, generation)

    def __init__(self, full_table: "pa.Table", parquet_dir: str = "", parent=None):
        super().__init__(parent)
        self._full_table   = full_table
        self._parquet_dir  = parquet_dir
        self._q: _queue_module.SimpleQueue = _queue_module.SimpleQueue()
        self._shard_paths: list | None = None  # loaded lazily on first condition query
        # Last emitted result + the keys that produced it.  A column-header
        # click changes only the sort, so the (expensive) filter is reused and
        # just re-ordered instead of being run again.
        self._last_fkey:   tuple | None = None
        self._last_sort:   tuple | None = None
        self._last_result: object       = None

    # ── Shard manifest loader (cached) ────────────────────────────────────────
    def _get_shard_paths(self) -> list:
        if self._shard_paths is not None:
            return self._shard_paths
        import json as _json_lib
        manifest = os.path.join(self._parquet_dir, "parquet_manifest.json")
        try:
            with open(manifest) as fh:
                self._shard_paths = _json_lib.load(fh)
        except Exception as exc:
            logger.warning("_FilterThread: cannot load shard manifest: %s", exc)
            self._shard_paths = []
        return self._shard_paths

    # ── Sort helpers ──────────────────────────────────────────────────────────
    # Whitelist: _SORT_COL_MAP is the only producer of sort columns, but the
    # value is interpolated into SQL, so it is validated rather than trusted.
    _SORTABLE = frozenset(_SORT_COL_MAP.values())

    @classmethod
    def _sort_keys(cls, sort_col: str, sort_asc: bool) -> list:
        """Arrow sort keys, with the forensic tiebreaker preserved."""
        if sort_col not in cls._SORTABLE:
            sort_col = "timestamp_utc"
        direction = "ascending" if sort_asc else "descending"
        if sort_col == "timestamp_utc":
            # record_id tiebreaker on timestamp sorts: same-second events (the
            # overwhelming majority in Security logs) get deterministic,
            # log-write order instead of arbitrary shard-interleave order.
            return [(sort_col, direction), ("record_id", direction)]
        return [(sort_col, direction)]

    @classmethod
    def _order_by_sql(cls, sort_col: str, sort_asc: bool) -> str:
        """The same ordering as _sort_keys(), expressed for DuckDB."""
        if sort_col not in cls._SORTABLE:
            sort_col = "timestamp_utc"
        direction = "ASC" if sort_asc else "DESC"
        if sort_col == "timestamp_utc":
            return f"timestamp_utc {direction}, record_id {direction}"
        return f"{sort_col} {direction}"

    def _order_result(self, con, result, sort_col: str, sort_asc: bool):
        """Order an already-filtered result via DuckDB.

        Arrow's ``sort_by`` raises on dictionary-encoded columns -- which is how
        every string column in this table is stored (computer, channel,
        provider, source_file, user_id, level_name).  The old code caught that
        and fell through to "returning unsorted result", so sorting the grid by
        any of those columns silently displayed UNSORTED rows.  DuckDB sorts
        them correctly, and in parallel.

        Every result here is derived from _full_table, so it always carries the
        row_id column; ordering the ids and re-taking is equivalent to ordering
        the rows, and take() preserves dictionary encoding.
        """
        if len(result) == 0:
            return result
        import pyarrow as pa
        try:
            con.register("_ord_keep", pa.table({"row_id": result["row_id"]}))
            try:
                ids = con.execute(
                    f"SELECT e.row_id FROM events e "
                    f"JOIN _ord_keep k ON e.row_id = k.row_id "
                    f"ORDER BY {self._order_by_sql(sort_col, sort_asc)}"
                ).fetch_arrow_table()["row_id"]
            finally:
                try:
                    con.unregister("_ord_keep")
                except Exception:
                    pass
            return self._full_table.take(ids)
        except Exception as exc:
            logger.warning("DuckDB ordering failed (%s) — falling back to Arrow", exc)
            return self._sort_table(result, sort_col, sort_asc)

    def _sort_table(self, table, sort_col: str, sort_asc: bool):
        """Sort an Arrow table, falling back to the un-tiebroken order."""
        try:
            return table.sort_by(self._sort_keys(sort_col, sort_asc))
        except Exception as exc:
            logger.warning("Sort failed (%s) — retrying without tiebreaker", exc)
            try:
                direction = "ascending" if sort_asc else "descending"
                return table.sort_by([(sort_col, direction)])
            except Exception:
                logger.warning("Sort failed entirely — returning unsorted result")
                return table

    def _metadata_filter(self, con, where_sql: str, params: list,
                         sort_col: str, sort_asc: bool):
        """Metadata-only filter with the sort fused in as ORDER BY.

        Fetches only row_ids and take()s from full_table: take() preserves
        dictionary encoding and shares the underlying string buffers, avoiding
        a ~1.7 GB unencoded copy that SELECT * would materialise.

        Uses fetch_arrow_table() (Arrow C-interface) rather than fetchnumpy():
        modern pyarrow (14+) makes numpy OPTIONAL, so a box can have
        pyarrow+duckdb (Juggernaut active) but no numpy.  fetchnumpy() then
        raised "No module named 'numpy'", which the caller's except turned into
        result=full_table -- silently showing EVERY event for any filtered view.
        """
        row_ids = con.execute(
            f"SELECT row_id FROM events WHERE {where_sql} "
            f"ORDER BY {self._order_by_sql(sort_col, sort_asc)}",
            params,
        ).fetch_arrow_table()["row_id"]
        return self._full_table.take(row_ids)

    # ── Two-phase condition post-filter ───────────────────────────────────────
    def _apply_with_conditions(self, con, where_sql: str, params: list, conditions_cfg: dict):
        """
        Phase 1: metadata filter via Arrow/DuckDB → (row_id, record_id) pairs.
        Phase 2: condition clauses via parquet_scan JOIN → passing record_ids.
        Phase 3: take() from full_table using row_ids that survived both phases.
        """
        import duckdb
        import pyarrow as pa
        from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql

        # Phase 1 — metadata filter
        # Select source_file alongside record_id so the Phase 2 JOIN uses a
        # composite (record_id, source_file) key — bare record_id is not unique
        # across multi-file loads and would mix rows from different files.
        # Arrow, not Python lists — see the note in _apply_with_full_text_search:
        # per-row Python work here holds the GIL and freezes the window.
        p1 = con.execute(
            f"SELECT row_id AS _p1_row, record_id AS _p1_rid, "
            f"       source_file AS _p1_src "
            f"FROM events WHERE {where_sql}",
            params,
        ).fetch_arrow_table()
        if p1.num_rows == 0:
            return self._full_table.slice(0, 0)   # empty, preserve schema
        row_ids = p1["_p1_row"]

        # Phase 2 — condition filter via Parquet
        shards = self._get_shard_paths()
        if not shards:
            logger.warning("_FilterThread: no Parquet shards — returning metadata-only result")
            return self._full_table.take(row_ids)

        cond_sql, cond_params = filter_config_to_sql(conditions_cfg)
        if cond_sql == "1=1":
            return self._full_table.take(row_ids)

        quoted = ", ".join(f"'{p}'" for p in shards)
        try:
            con2 = duckdb.connect()
            # Composite (record_id, source_file) key prevents cross-file matches
            # Column names deliberately DO NOT match the Parquet columns.
            # SEARCH_TEXT_EXPR_FULL and the condition SQL reference bare column
            # names (source_file, event_id, ...); with a probe table that also
            # had "source_file", DuckDB raised "Ambiguous reference to column
            # name" and the except below swallowed it -- silently showing the
            # UNFILTERED metadata result as if the search had been applied.
            con2.register("_p1_ids", p1)
            # The JOIN yields the surviving ROW IDS directly, so Phase 3 is a
            # single Arrow take() with no Python set-membership pass.
            phase2_sql = (
                f"SELECT f._p1_row AS row_id "
                f"FROM parquet_scan([{quoted}]) p "
                f"JOIN _p1_ids f "
                f"  ON p.record_id = f._p1_rid AND p.source_file = f._p1_src "
                f"WHERE {cond_sql}"
            )
            keep_ids = con2.execute(phase2_sql, cond_params).fetch_arrow_table()["row_id"]
            con2.close()
        except Exception as exc:
            # Same fail-open hazard as the main filter loop: the user's field
            # conditions are silently DROPPED and the metadata-only (over-
            # inclusive) result is shown.  Make it loud — results are unreliable.
            logger.error(
                "Condition post-filter FAILED (%s) — conditions NOT applied; "
                "showing metadata-only (over-inclusive) result, UNRELIABLE", exc,
            )
            return self._full_table.take(row_ids)

        # Phase 3 — the JOIN already returned the surviving row ids.
        if len(keep_ids) == 0:
            return self._full_table.slice(0, 0)
        return self._full_table.take(keep_ids)

    # ── Full-text search via Parquet ──────────────────────────────────────────
    def _apply_with_full_text_search(
        self,
        con,
        where_sql_no_text: str,
        params_no_text: list,
        conditions_cfg: dict,
        text_search_cfg: dict,
    ):
        """
        Two-phase full-text search that includes event_data_json.

        Phase 1: run all non-text, non-condition metadata filters against the
                 Arrow table (fast, zero I/O) → candidate (row_id, record_id) pairs.
        Phase 2: run CONTAINS(SEARCH_TEXT_EXPR_FULL, term) AND optional condition
                 clauses against the Parquet shards for those candidates.
                 SEARCH_TEXT_EXPR_FULL concatenates all metadata columns PLUS
                 event_data_json, so paths, package names, process names etc. are
                 all matched even though event_data_json is not in the Arrow table.
        Phase 3: take() the surviving row_ids from full_table.

        Falls back to the metadata-only result if the Parquet scan fails.
        """
        import duckdb
        import pyarrow as pa
        from evtx_tool.core.heavyweight.filter_sql import (
            text_config_to_parquet_sql,
            filter_config_to_sql,
        )

        # Phase 1 — non-text metadata filter via Arrow
        # Select source_file so Phase 2 can use composite (record_id, source_file)
        # key — bare record_id is not unique across multi-file loads.
        # Kept in ARROW, never materialised into Python lists.  fetchall()
        # here returned one tuple per candidate row -- 1.7M of them on an
        # unfiltered search -- and the list/set comprehensions that followed
        # walked them several more times.  All of that holds the GIL, which
        # starved the GUI thread: measured 1291 ms of frozen window during a
        # text search, even though the work was on a worker.
        p1 = con.execute(
            f"SELECT row_id AS _p1_row, record_id AS _p1_rid, "
            f"       source_file AS _p1_src "
            f"FROM events WHERE {where_sql_no_text}",
            params_no_text,
        ).fetch_arrow_table()
        if p1.num_rows == 0:
            return self._full_table.slice(0, 0)
        row_ids = p1["_p1_row"]

        # Phase 2 — CONTAINS + optional conditions via Parquet
        shards = self._get_shard_paths()
        if not shards:
            logger.warning(
                "_FilterThread: no Parquet shards for full-text search — "
                "returning metadata-only result (event_data_json not searched)"
            )
            return self._full_table.take(row_ids)

        # text_search_cfg may be a single config or several (the Advanced
        # Filter's term and the quick toolbar term are independent legs and
        # must AND together -- one must never silently replace the other, and
        # each keeps its own regex/exclude/case flags).
        _cfgs = (text_search_cfg if isinstance(text_search_cfg, (list, tuple))
                 else [text_search_cfg])
        _sqls, text_params = [], []
        for _c in _cfgs:
            if not (_c or {}).get("text_search"):
                continue
            _sql, _prm = text_config_to_parquet_sql(_c)
            if _sql != "1=1":
                _sqls.append(f"({_sql})")
                text_params.extend(_prm)
        text_sql = " AND ".join(_sqls) if _sqls else "1=1"
        if text_sql == "1=1":
            return self._full_table.take(row_ids)

        # Combine with conditions if any
        has_cond = bool(conditions_cfg.get("conditions"))
        if has_cond:
            cond_sql, cond_params = filter_config_to_sql(conditions_cfg)
            if cond_sql != "1=1":
                phase2_where  = f"({text_sql}) AND ({cond_sql})"
                phase2_params = text_params + cond_params
            else:
                phase2_where  = text_sql
                phase2_params = text_params
        else:
            phase2_where  = text_sql
            phase2_params = text_params

        quoted = ", ".join(f"'{p}'" for p in shards)
        try:
            con2 = duckdb.connect()
            # Composite (record_id, source_file) key — prevents cross-file row matches
            # Column names deliberately DO NOT match the Parquet columns.
            # SEARCH_TEXT_EXPR_FULL and the condition SQL reference bare column
            # names (source_file, event_id, ...); with a probe table that also
            # had "source_file", DuckDB raised "Ambiguous reference to column
            # name" and the except below swallowed it -- silently showing the
            # UNFILTERED metadata result as if the search had been applied.
            con2.register("_p1_ids", p1)
            # The JOIN yields the surviving ROW IDS directly, so Phase 3 is a
            # single Arrow take() with no Python set-membership pass.
            phase2_sql = (
                f"SELECT f._p1_row AS row_id "
                f"FROM parquet_scan([{quoted}]) p "
                f"JOIN _p1_ids f "
                f"  ON p.record_id = f._p1_rid AND p.source_file = f._p1_src "
                f"WHERE {phase2_where}"
            )
            keep_ids = con2.execute(phase2_sql, phase2_params).fetch_arrow_table()["row_id"]
            con2.close()
        except Exception as exc:
            # Fail-open: the full-text term is silently DROPPED and the
            # metadata-only (over-inclusive) result is shown.  Make it loud.
            logger.error(
                "Full-text Phase 2 Parquet scan FAILED (%s) — text search NOT "
                "applied; showing metadata-only (over-inclusive) result, UNRELIABLE",
                exc,
            )
            return self._full_table.take(row_ids)

        # Phase 3 — the JOIN already returned the surviving row ids.
        if len(keep_ids) == 0:
            return self._full_table.slice(0, 0)
        return self._full_table.take(keep_ids)

    # ── Main loop ─────────────────────────────────────────────────────────────
    def run(self) -> None:
        import duckdb
        con = duckdb.connect()
        # Was min(4, cpu): the parser gets cpu-1 workers, so on a 12-core box
        # parsing ran 11-wide while the interactive filter — the one the analyst
        # actually waits on — ran 4-wide.  This runs on a background thread, so
        # the only core that must stay free is the GUI's.
        con.execute(f"SET threads={max(2, min((os.cpu_count() or 4) - 1, 16))}")
        con.register("events", self._full_table)

        while True:
            item = self._q.get()          # blocks until request arrives
            if item is None:
                break                     # shutdown sentinel
            (gen, where_sql, params, conditions_cfg,
             text_search_cfg, sort_col, sort_asc) = item

            # Drain queue — only the latest request matters.
            while not self._q.empty():
                item = self._q.get_nowait()
                if item is None:
                    con.close()
                    return
                (gen, where_sql, params, conditions_cfg,
                 text_search_cfg, sort_col, sort_asc) = item

            has_conditions = bool(conditions_cfg.get("conditions"))
            _tc = (text_search_cfg if isinstance(text_search_cfg, (list, tuple))
                   else [text_search_cfg])
            has_full_text  = any((c or {}).get("text_search") for c in _tc)

            # A column-header click changes only (sort_col, sort_asc).  Re-running
            # the filter for that would be pure waste, so the previous result is
            # reused and merely re-ordered; an identical repeat is emitted as-is.
            fkey = (where_sql, tuple(params),
                    repr(conditions_cfg), repr(text_search_cfg))
            skey = (sort_col, sort_asc)
            if fkey == self._last_fkey and self._last_result is not None:
                if skey == self._last_sort:
                    try:
                        self.done.emit(self._last_result, gen)
                    except RuntimeError:
                        pass
                    continue
                result = self._order_result(con, self._last_result, sort_col, sort_asc)
                self._last_sort, self._last_result = skey, result
                try:
                    self.done.emit(result, gen)
                except RuntimeError:
                    pass
                continue

            sorted_in_sql = False
            try:
                if not has_conditions and not has_full_text:
                    # Metadata-only (including the unfiltered "1=1" case).  This
                    # used to short-circuit to `result = self._full_table` when
                    # unfiltered, which then needed an Arrow sort that could not
                    # order dictionary columns; ordering in SQL is both correct
                    # and parallel, and take() still preserves dict encoding.
                    result = self._metadata_filter(con, where_sql, params,
                                                   sort_col, sort_asc)
                    sorted_in_sql = True
                elif has_full_text:
                    # Full-text search: Phase 2 Parquet scan includes event_data_json.
                    # Handles conditions too if both are set.
                    result = self._apply_with_full_text_search(
                        con, where_sql, params, conditions_cfg, text_search_cfg
                    )
                else:
                    # Two-phase: metadata via Arrow + conditions via Parquet.
                    result = self._apply_with_conditions(con, where_sql, params, conditions_cfg)
                    sorted_in_sql = False
            except Exception as exc:
                # NOTE: this fallback shows the FULL table (fail-open).  That is
                # a forensic-integrity hazard — a filtered view silently showing
                # every event — so make the failure loud rather than a debug
                # aside.  The fallback semantics are intentionally left unchanged
                # here (over-inclusion is noticeable; fail-closed would hide
                # evidence); changing them is a separate, deliberate decision.
                logger.error(
                    "Filter thread FAILED (%s) — showing ALL rows unfiltered; "
                    "results are UNRELIABLE for where=%r", exc, where_sql,
                )
                result = self._full_table   # on error, show all rows (see note)
                sorted_in_sql = False

            if not sorted_in_sql:
                result = self._order_result(con, result, sort_col, sort_asc)

            self._last_fkey, self._last_sort, self._last_result = fkey, skey, result

            try:
                self.done.emit(result, gen)
            except RuntimeError:
                pass  # model already destroyed

        con.close()

    def request(self, gen: int, where_sql: str, params: list,
                conditions_cfg: dict = None, text_search_cfg: dict = None,
                sort_col: str = "timestamp_utc", sort_asc: bool = True) -> None:
        self._q.put((gen, where_sql, params, conditions_cfg or {},
                     text_search_cfg or {}, sort_col, sort_asc))

    def stop(self) -> None:
        self._q.put(None)
        self.wait(3000)


# ── Compatibility shim kept for any code that imports _register_regexp ─────────
def _register_regexp(con) -> None:
    """No-op — regexp_matches() is built into DuckDB. Kept for import compat."""
    pass


# ── Main model ────────────────────────────────────────────────────────────────

class ArrowTableModel(QAbstractTableModel):
    """
    In-memory Arrow QAbstractTableModel.

    data() reads from a visible-window dict-cache of the current _display_table.
    Filters are executed by _FilterThread (single background DuckDB worker).
    No async I/O during scrolling — scroll is always instant.
    """

    busy_started = Signal()
    busy_finished = Signal()

    # Keep old class name accessible so any isinstance() checks still work.
    _header_font: "QFont | None" = None

    def __init__(
        self,
        full_table: "pa.Table",
        parquet_dir: str = "",
        db_path: str = "",
        fixed_where: str = "1=1",
        fixed_params: "list | None" = None,
        parent=None,
    ):
        super().__init__(parent)
        self._full_table   = full_table
        # When a fixed pre-filter is set (per-file tab), start empty so the view
        # doesn't briefly show the entire shared full_table before the first filter
        # completes. _on_filter_done will populate to the correct per-file count.
        if fixed_where != "1=1":
            self._display_table = full_table.slice(0, 0)
            self._total_rows    = 0
        else:
            self._display_table = full_table        # current filtered+sorted view
            self._total_rows    = len(full_table)
        self._parquet_dir  = parquet_dir or db_path
        self._db_path      = self._parquet_dir      # compat alias

        # ── Visible window cache ───────────────────────────────────────────
        self._cache_dict: dict[str, list] = {}
        self._cache_start = 0
        self._cache_end   = 0

        # ── Lazy event_data_json LRU cache ─────────────────────────────────
        self._event_data_cache: OrderedDict[int, str] = OrderedDict()

        # ── Fixed (immutable) pre-filter — used by per-file tabs so they
        #    share the full arrow_table without materialising a filtered copy.
        #    Never cleared by reset_filter() or apply_filter().
        self._fixed_where_sql: str      = fixed_where
        self._fixed_params:    list[Any] = list(fixed_params or [])

        # ── Four filter layers (same API as HeavyweightTableModel) ─────────
        self._base_where_sql  = "1=1"
        self._base_params:  list[Any] = []
        self._has_advanced_filter = False
        self._text_where_sql  = ""
        self._text_params:  list[Any] = []
        self._quick_filters:  list[dict] = []
        self._quick_where_sql = ""
        self._quick_params: list[Any] = []
        self._record_id_where_sql = ""
        self._record_id_params: list[Any] = []
        self._bookmarked_keys: frozenset = frozenset()  # (source_file, record_id) pairs

        self._sort_col = "timestamp_utc"
        self._sort_asc = True
        self._generation = 0
        self._cached_where: tuple[str, list[Any]] | None = None
        self._last_where_key: tuple | None = None  # dedup guard: skip re-dispatch if WHERE unchanged

        # ── Condition post-filter config (populated by apply_filter) ────────
        # Holds {"conditions": [...], "case_sensitive": bool} when the user
        # sets custom field conditions. Passed to _FilterThread for Phase 2
        # Parquet post-filtering (event_data_json not in Arrow table).
        self._conditions_cfg: dict = {}

        # ── Full-text search config (populated by apply_filter) ──────────
        # Holds the text_search subset of the FilterConfig when the user
        # enters text in the Advanced Filter.  Passed to _FilterThread so
        # Phase 2 can run CONTAINS against event_data_json in Parquet shards
        # (event_data_json is not present in the Arrow table).
        self._text_search_cfg: dict = {}
        # Quick toolbar search — separate leg, ANDed with the above.
        self._quick_text_cfg: dict = {}

        # ── Start filter thread and dispatch initial sort ───────────────────
        self._filter_thread = _FilterThread(full_table, parquet_dir=self._parquet_dir, parent=self)
        self._filter_thread.done.connect(self._on_filter_done)
        self._filter_thread.start()

        # Populate the initial display table (sorted by timestamp_utc asc).
        self._invalidate()

    # ── Qt interface ──────────────────────────────────────────────────────────

    def rowCount(self, parent=QModelIndex()) -> int:
        return self._total_rows

    def columnCount(self, parent=QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section: int, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                overrides = getattr(self, "_header_overrides", {})
                if section in overrides:
                    return overrides[section]
                return COLUMNS[section] if section < len(COLUMNS) else ""
            if role == Qt.ItemDataRole.FontRole:
                if ArrowTableModel._header_font is None:
                    ArrowTableModel._header_font = QFont("Segoe UI", 8)
                    ArrowTableModel._header_font.setBold(True)
                return ArrowTableModel._header_font
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row >= self._total_rows:
            return None

        # Refresh visible cache if this row falls outside the current window.
        if row < self._cache_start or row >= self._cache_end:
            start = max(0, row - _CACHE_WINDOW // 4)
            end   = min(self._total_rows, start + _CACHE_WINDOW)
            try:
                chunk = self._display_table.slice(start, end - start)
                self._cache_dict  = chunk.to_pydict()
                self._cache_start = start
                self._cache_end   = end
            except Exception:
                return None

        local = row - self._cache_start
        if local < 0 or local >= (self._cache_end - self._cache_start):
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            return self._cell_text(local, row, col)
        if role == Qt.ItemDataRole.ForegroundRole:
            return self._cell_fg(local, col)
        if role == Qt.ItemDataRole.BackgroundRole:
            if self._bookmarked_keys:
                sf  = self._v(local, "source_file")
                rid = self._v(local, "record_id")
                try:
                    if (sf, int(rid)) in self._bookmarked_keys:
                        return _BG_BOOKMARK
                except (ValueError, TypeError):
                    pass
            return _BG_ALT if row % 2 else _BG_NORMAL
        if role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (COL_NUM, COL_EID, COL_RECORD_ID):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            if col == COL_LEVEL:
                return Qt.AlignmentFlag.AlignCenter
            return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        if role == Qt.ItemDataRole.FontRole:
            if col == COL_SOURCE:
                return _MONO_FONT
        if role == Qt.ItemDataRole.UserRole:
            return self.get_event(row)

        return None

    # ── Cell rendering ────────────────────────────────────────────────────────

    def _v(self, local: int, col_name: str) -> str:
        """Safe string getter from the visible cache dict."""
        lst = self._cache_dict.get(col_name)
        if lst is None or local >= len(lst):
            return ""
        v = lst[local]
        return "" if v is None else str(v)

    def _cell_text(self, local: int, abs_row: int, col: int) -> str:
        if col == COL_NUM:
            if self._bookmarked_keys:
                sf  = self._v(local, "source_file")
                rid = self._v(local, "record_id")
                try:
                    if (sf, int(rid)) in self._bookmarked_keys:
                        return f"★{abs_row + 1}"
                except (ValueError, TypeError):
                    pass
            return str(abs_row + 1)
        if col == COL_EID:
            return self._v(local, "event_id")
        if col == COL_LEVEL:
            return self._v(local, "level_name")
        if col == COL_TS:
            ts_raw = self._v(local, "timestamp_utc")
            if not ts_raw:
                return ""
            return apply_tz(ts_raw.replace(" ", "T") + "Z")
        if col == COL_COMPUTER:
            return self._v(local, "computer")
        if col == COL_CHANNEL:
            ch = self._v(local, "channel")
            return ch.removeprefix("Microsoft-Windows-")
        if col == COL_USER:
            return self._v(local, "user_id")
        if col == COL_ATTACK:
            return ""   # not stored in Juggernaut mode
        if col == COL_SOURCE:
            return os.path.basename(self._v(local, "source_file"))
        if col == COL_KEYWORDS:
            return self._v(local, "keywords")
        if col == COL_OPCODE:
            return self._v(local, "opcode")
        if col == COL_LOG:
            return self._v(local, "channel")
        if col == COL_PID:
            return self._v(local, "process_id")
        if col == COL_TID:
            return self._v(local, "thread_id")
        if col == COL_CORR_ID:
            return self._v(local, "correlation_id")
        if col == COL_RECORD_ID:
            return self._v(local, "record_id")
        if col == COL_PROVIDER:
            return self._v(local, "provider")
        if col in (COL_PROC_ID, COL_SID, COL_KERN_TIME, COL_USER_TIME, COL_PROC_TIME):
            return ""
        return ""

    def _cell_fg(self, local: int, col: int):
        lvl = self._v(local, "level_name")
        if col == COL_LEVEL:
            return _LEVEL_FG.get(lvl, _COLOR_GRAY)
        if col in (COL_NUM, COL_SOURCE):
            return _COLOR_GRAY
        if lvl in ("Verbose", "LogAlways"):
            return _COLOR_GRAY
        return None

    # ── Filter core ───────────────────────────────────────────────────────────

    def _combined_where(self) -> tuple[str, list[Any]]:
        """Merge all four filter layers with AND. Cached until _invalidate()."""
        if self._cached_where is not None:
            return self._cached_where

        all_parts = [
            (self._fixed_where_sql,     self._fixed_params),
            (self._base_where_sql,      self._base_params),
            (self._text_where_sql,      self._text_params),
            (self._quick_where_sql,     self._quick_params),
            (self._record_id_where_sql, self._record_id_params),
        ]
        active = [(sql, p) for sql, p in all_parts if sql and sql != "1=1"]
        if not active:
            result: tuple[str, list[Any]] = ("1=1", [])
        elif len(active) == 1:
            sql, p = active[0]
            result = (sql, list(p))
        else:
            combined = " AND ".join(f"({sql})" for sql, _ in active)
            params: list[Any] = []
            for _, p in active:
                params.extend(p)
            result = (combined, params)

        self._cached_where = result
        return result

    def _invalidate(self) -> None:
        """Invalidate visible cache and dispatch a new filter request."""
        self._cached_where = None
        where_sql, params = self._combined_where()
        # Sort is part of the key: the thread now does the ordering, so a
        # sort-only change must still dispatch (the thread reuses the cached
        # filter result and only re-orders it).
        _text_legs = [c for c in (self._text_search_cfg, self._quick_text_cfg)
                      if c.get("text_search")]
        where_key = (where_sql, tuple(params), str(self._conditions_cfg),
                     str(_text_legs), self._sort_col, self._sort_asc)
        if where_key == self._last_where_key:
            return  # nothing changed — skip redundant dispatch
        self._last_where_key = where_key
        self.busy_started.emit()
        self._generation += 1
        self._cache_dict  = {}
        self._cache_start = self._cache_end = 0
        self._filter_thread.request(
            self._generation, where_sql, list(params),
            self._conditions_cfg,
            _text_legs,
            self._sort_col, self._sort_asc,
        )

    @Slot(object, int)
    def _on_filter_done(self, filtered_table: "pa.Table", generation: int) -> None:
        if generation != self._generation:
            return   # stale — a newer request is already in flight

        # Already ordered by _FilterThread (see its docstring).  Sorting here
        # ran on the GUI thread and stalled the UI after every single filter
        # change, not just on header clicks.
        self._display_table = filtered_table
        self._total_rows    = len(filtered_table)
        self._cache_dict    = {}
        self._cache_start   = self._cache_end = 0
        self.beginResetModel()
        self.endResetModel()
        self.busy_finished.emit()

    # ── Public filter API (same signatures as HeavyweightTableModel) ───────────

    def apply_filter(self, filter_config: dict) -> None:
        from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql

        fc = filter_config or {}
        conditions = fc.get("conditions") or []
        cs = fc.get("case_sensitive", False)

        # Store conditions for Phase 2 Parquet post-filter in _FilterThread.
        # event_data_json is not in the Arrow table, so conditions cannot be
        # evaluated in the DuckDB Arrow query. Instead they are applied after
        # the metadata filter via a JOIN against the Parquet shards.
        self._conditions_cfg = {"conditions": conditions, "case_sensitive": cs} if conditions else {}

        # Extract text_search config for Phase 2 full-text Parquet search.
        # SEARCH_TEXT_EXPR (Arrow path) only covers extracted metadata columns;
        # it misses event_data_json.  Phase 2 uses SEARCH_TEXT_EXPR_FULL which
        # includes event_data_json via a Parquet scan JOIN.
        _TEXT_KEYS = frozenset({"text_search", "text_regex", "text_exclude",
                                 "search_mode", "case_sensitive"})
        has_text = bool(fc.get("text_search"))
        if has_text:
            self._text_search_cfg = {k: fc[k] for k in _TEXT_KEYS if k in fc}
        else:
            self._text_search_cfg = {}

        # Build metadata-only WHERE clause for the Arrow/DuckDB Phase 1.
        # Strip: conditions (need Parquet) and text_search (handled in Phase 2).
        _strip = set()
        if conditions:
            _strip.add("conditions")
        if has_text:
            _strip.update({"text_search", "text_regex", "text_exclude"})
        fc_meta = {k: v for k, v in fc.items() if k not in _strip} if _strip else fc
        self._base_where_sql, self._base_params = filter_config_to_sql(fc_meta)
        self._has_advanced_filter = bool(fc) and (
            self._base_where_sql != "1=1"
            or bool(self._conditions_cfg)
            or bool(self._text_search_cfg)
        )
        self._invalidate()

    def clear_filter(self) -> None:
        self._base_where_sql  = "1=1"
        self._base_params     = []
        self._has_advanced_filter = False
        self._conditions_cfg  = {}
        self._text_search_cfg = {}
        # _quick_text_cfg deliberately untouched: clearing the ADVANCED filter
        # must not silently empty the toolbar search box's effect.
        self._invalidate()

    def has_filter(self) -> bool:
        return self._has_advanced_filter

    def apply_text_filter(self, text: str) -> None:
        """Standalone text search — SAME coverage as the Advanced Filter.

        NOTE: nothing in the GUI calls this today; the only user-facing event
        text search is the Advanced Filter dialog, which goes through
        apply_filter(). Kept and corrected rather than deleted so that a future
        toolbar/quick-search box cannot reintroduce the narrower scope
        described below.


        This used to search _ARROW_SEARCH_EXPR only: the metadata columns plus
        ed_values.  event_data_json is deliberately not held in the Arrow table
        (~500 B/row), so EventData FIELD NAMES and the outer container keys were
        invisible here while the Advanced Filter found them -- the same term
        gave two different answers depending on which box it was typed into.

        It now routes through the Phase 2 Parquet scan, exactly like the
        Advanced Filter, so both boxes and both modes agree.  That costs a
        Parquet read (~3.9 s on 1.7M rows vs ~2.2 s), paid on the filter thread,
        which is the right trade for a search that does not lie about coverage.
        """
        term = text.strip()
        self._text_where_sql = ""
        self._text_params    = []
        # Its OWN leg: the Advanced Filter's text term lives in
        # _text_search_cfg and the two AND together, exactly as they did when
        # this was an Arrow WHERE clause.  Sharing one slot would have made the
        # quick box silently drop an advanced text term.
        self._quick_text_cfg = (
            {"text_search": term, "case_sensitive": False} if term else {}
        )
        self._invalidate()

    def apply_record_id_filter(self, ids: frozenset) -> None:
        # M3 fix: do NOT zero _text_where_sql/_text_params here.
        # Text search is independent state; clearing it on every record-id
        # filter application makes active text searches silently disappear
        # (and clearing the record-id filter can never restore them).
        if ids:
            ph = ",".join("?" * len(ids))
            self._record_id_where_sql = f"record_id IN ({ph})"
            self._record_id_params    = sorted(ids)
        else:
            self._record_id_where_sql = ""
            self._record_id_params    = []
        self._invalidate()

    def clear_record_id_filter(self) -> None:
        if getattr(self, "_record_id_where_sql", ""):
            self._record_id_where_sql = ""
            self._record_id_params    = []
            self._invalidate()

    @property
    def total_unfiltered_rows(self) -> int:
        """Total rows in the dataset before any filter is applied."""
        return len(self._full_table) if self._full_table is not None else 0

    def get_cascade_base_where(self) -> "tuple[str, list]":
        """Return the advanced-filter and session-filter WHERE clauses (excluding
        quick filters and text search) as DuckDB-compatible SQL.

        Used by ColValueWorker so cascade popup counts reflect ALL active view
        filters, not just quick filters.

        Known limitation — text search is intentionally omitted:
        ``_text_where_sql`` uses ``CONTAINS(_ARROW_SEARCH_EXPR, ?)`` which is
        evaluated against the pre-filtered Arrow ``_display_table``, not the
        full ``_full_table`` that ColValueWorker queries.  Re-applying it in the
        GROUP BY DuckDB query would double-filter against a different base table
        and produce inconsistent counts.  Consequence: when text search is active
        the popup values may include entries that text search would hide.  This
        is a known, documented trade-off — fixing it requires passing the
        already-filtered ``_display_table`` to ColValueWorker instead of
        ``_full_table``, which is a separate architectural change.
        """
        parts:  list[str] = []
        params: list      = []
        for sql, p in (
            (self._base_where_sql,      self._base_params),
            (self._record_id_where_sql, self._record_id_params),
        ):
            if sql and sql != "1=1":
                parts.append(f"({sql})")
                params.extend(p)
        if not parts:
            return "", []
        return " AND ".join(parts), params

    def apply_bookmark_filter(self, keys: "frozenset[tuple[str, int]]") -> None:
        """Filter to only bookmarked events using (source_file, record_id) composite key.

        Builds an OR chain so events with the same record_id from different files
        are correctly distinguished in merge / Juggernaut mode.

        M3 fix: does NOT touch _text_where_sql/_text_params.  Text search is
        independent state owned by apply_text_filter(); clobbering it here
        causes active text searches to vanish when any bookmark/RA/logon-session
        filter is applied, and they cannot be restored by clearing that filter.
        """
        if not keys:
            self.clear_record_id_filter()
            return
        parts:  list[str] = []
        params: list      = []
        for sf, rid in keys:
            parts.append("(source_file = ? AND record_id = ?)")
            params.extend([sf, rid])
        self._record_id_where_sql = " OR ".join(parts)
        self._record_id_params    = params
        self._invalidate()

    def _get_shard_paths(self) -> list:
        """Delegate to the filter thread's shard manifest loader."""
        return self._filter_thread._get_shard_paths()

    def set_bookmark_highlights(self, keys: "frozenset[tuple[str, int]]") -> None:
        """Update which rows receive the amber bookmark highlight (visual only, no filtering)."""
        self._bookmarked_keys = keys
        n = self._total_rows
        if n > 0:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(n - 1, len(COLUMNS) - 1),
            )

    # ── Quick filters (right-click column filter) ─────────────────────────────

    # timestamp_date intentionally omitted — its SQL expression depends on
    # the live display-TZ state.  Resolved at filter-build time via
    # ``_quick_col_info()`` so popup values and filters BOTH use the same
    # display-TZ date the user sees in the event table.
    _QUICK_KEY_TO_COL: dict[str, tuple[str, str]] = {
        # ── Core columns ──────────────────────────────────────────────────────
        "event_id":       ("event_id",                       "int"),
        "level_name":     ("level_name",                     "str"),
        "computer":       ("computer",                       "str"),
        "channel":        ("channel",                        "str"),
        "user_id":        ("user_id",                        "str"),
        "source_file":    ("source_file",                    "str"),
        # ── Extended columns ──────────────────────────────────────────────────
        # These map to real columns in the SQLite events table.
        "provider":       ("provider",                       "str"),
        "keywords":       ("keywords",                       "str"),
        # opcode is stored as int32; cast to TEXT so lower() + string compare works.
        "opcode":         ("CAST(opcode AS TEXT)",           "str"),
        # JM schema has no separate "log" column — channel is the display fallback.
        "log":            ("channel",                        "str"),
        # process_id / thread_id are int32; cast to TEXT for string compare.
        "process_id":     ("CAST(process_id AS TEXT)",       "str"),
        "thread_id":      ("CAST(thread_id AS TEXT)",        "str"),
        "correlation_id": ("correlation_id",                 "str"),
        # session_id and processor_id have no JM counterpart — omitted intentionally.
        # record_id is int64 in the schema.
        "record_id":      ("record_id",                      "int"),
    }

    def _quick_col_info(self, key: str) -> "tuple[str, str] | None":
        """Resolve a quick-filter key to (sql_expr, type).

        Wraps ``_QUICK_KEY_TO_COL`` so ``timestamp_date`` can return a
        display-TZ-aware DuckDB expression rebuilt fresh each call — the
        underlying ``_tz_state`` global is mutable so a static dict would
        bake-in whatever TZ was active when the class was first imported.
        """
        if key == "timestamp_date":
            from evtx_tool.gui.jm_col_worker import _timestamp_date_expr
            return (_timestamp_date_expr(), "str")
        return self._QUICK_KEY_TO_COL.get(key)

    def add_quick_filter(self, key: str, value: str, include: bool) -> None:
        self._quick_filters = [f for f in self._quick_filters if f["key"] != key]
        self._quick_filters.append({"key": key, "value": value, "include": include})
        self._rebuild_quick_where()
        self._invalidate()

    def clear_quick_filters(self) -> None:
        self._quick_filters.clear()
        self._quick_where_sql = ""
        self._quick_params    = []
        self._invalidate()

    def clear_all_filters(self) -> None:
        """Reset every filter layer in one atomic batch — single _invalidate() call.

        Clears: advanced filter, conditions, text search (both cfg and sql),
        quick filters, and record-id/bookmark pivot.  Use this instead of
        calling clear_filter() + clear_quick_filters() separately to avoid
        dispatching two redundant _invalidate() round-trips per model.
        """
        # Advanced filter + conditions + text search cfg
        self._base_where_sql      = "1=1"
        self._base_params         = []
        self._has_advanced_filter = False
        self._conditions_cfg      = {}
        self._text_search_cfg     = {}
        # Standalone text filter (apply_text_filter path)
        self._text_where_sql      = ""
        self._text_params         = []
        # Record-id / bookmark pivot
        self._record_id_where_sql = ""
        self._record_id_params    = []
        # Quick column filters
        self._quick_filters.clear()
        self._quick_where_sql     = ""
        self._quick_params        = []
        # Single dispatch — all state already reset above
        self._invalidate()

    def set_quick_filters(self, filters: list[dict]) -> None:
        self._quick_filters = list(filters)
        self._rebuild_quick_where()
        self._invalidate()

    def has_quick_filters(self) -> bool:
        return bool(self._quick_filters)

    def get_quick_filters(self) -> list[dict]:
        return list(self._quick_filters)

    def _rebuild_quick_where(self) -> None:
        groups: dict[tuple[str, str, bool], list] = {}
        for qf in self._quick_filters:
            # _quick_col_info handles timestamp_date dynamically so popup
            # values (display-TZ dates) and this filter clause stay in sync.
            col_info = self._quick_col_info(qf["key"])
            if col_info is None:
                continue
            col, col_type = col_info
            key = (col, col_type, bool(qf["include"]))
            groups.setdefault(key, []).append(qf["value"])

        parts:  list[str]  = []
        params: list[Any]  = []

        for (col, col_type, incl), values in groups.items():
            if col_type == "int":
                int_vals: list[int] = []
                for v in values:
                    try:
                        int_vals.append(int(v))
                    except (ValueError, TypeError):
                        int_vals.append(0)
                # EXCLUDE must keep rows where the column is NULL — SQL `col != x`
                # is NULL (row dropped) for a NULL col, which would silently hide
                # every event with no value in that column (e.g. NULL user_id).
                # Normal mode keeps them (it compares against ""), so add
                # `OR col IS NULL` to the exclude clause to match.
                if len(int_vals) == 1:
                    op = "=" if incl else "!="
                    parts.append(f"{col} {op} ?" if incl else f"({col} {op} ? OR {col} IS NULL)")
                    params.append(int_vals[0])
                else:
                    op = "IN" if incl else "NOT IN"
                    ph = ", ".join("?" * len(int_vals))
                    parts.append(f"{col} {op} ({ph})" if incl else f"({col} {op} ({ph}) OR {col} IS NULL)")
                    params.extend(int_vals)
            else:
                lower_vals = [v.lower() for v in values]
                if len(lower_vals) == 1:
                    op = "=" if incl else "!="
                    parts.append(f"lower({col}) {op} ?" if incl else f"(lower({col}) {op} ? OR {col} IS NULL)")
                    params.append(lower_vals[0])
                else:
                    op = "IN" if incl else "NOT IN"
                    ph = ", ".join("?" * len(lower_vals))
                    parts.append(f"lower({col}) {op} ({ph})" if incl else f"(lower({col}) {op} ({ph}) OR {col} IS NULL)")
                    params.extend(lower_vals)

        if parts:
            self._quick_where_sql = " AND ".join(parts)
            self._quick_params    = params
        else:
            self._quick_where_sql = ""
            self._quick_params    = []

    # ── Sort ──────────────────────────────────────────────────────────────────

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        arrow_col = _SORT_COL_MAP.get(column)
        if arrow_col is None:
            return
        if arrow_col == self._sort_col and (order == Qt.SortOrder.AscendingOrder) == self._sort_asc:
            return                      # same order already applied
        self._sort_col = arrow_col
        self._sort_asc = (order == Qt.SortOrder.AscendingOrder)
        # Dispatch to _FilterThread rather than sorting inline.  It reuses the
        # cached filter result and only re-orders, so this costs a sort, not a
        # re-filter — and it no longer freezes the window on large tables.
        self._invalidate()

    # ── Event count ───────────────────────────────────────────────────────────

    def total_event_count(self) -> int:
        """Return unfiltered total (matches old API used in main_window.py)."""
        return len(self._full_table)

    # ── Detail panel ──────────────────────────────────────────────────────────

    def get_event(self, row: int) -> dict | None:
        """Build event dict for the detail panel. event_data_json is lazy-loaded."""
        if row < 0 or row >= self._total_rows:
            return None

        # Read metadata directly from the display table (O(1) Arrow column access).
        t = self._display_table
        def _col(name: str):
            try:
                return t[name][row].as_py()
            except Exception:
                return None

        record_id   = _col("record_id")
        source_file = _col("source_file") or ""
        ts_raw      = _col("timestamp_utc") or ""
        event_data_json = self._load_event_data(record_id, source_file)

        return {
            "record_id":      record_id,
            "event_id":       _col("event_id"),
            "level":          _col("level"),
            "level_name":     _col("level_name") or "",
            "timestamp":      (ts_raw.replace(" ", "T") + "Z") if ts_raw else "",
            "computer":       _col("computer") or "",
            "channel":        _col("channel") or "",
            "user_id":        _col("user_id") or "",
            "source_file":    source_file,
            "provider":       _col("provider") or "",
            "keywords":       _col("keywords") or "",
            "task":           _col("task") or 0,
            "opcode":         _col("opcode") or 0,
            "process_id":     _col("process_id"),
            "thread_id":      _col("thread_id"),
            "correlation_id": _col("correlation_id") or "",
            "event_data":     json.loads(event_data_json) if event_data_json else {},
            "_heavyweight":   True,
        }

    def _load_event_data(self, record_id: int | None, source_file: str = "") -> str:
        """Lazy-load event_data_json for one (source_file, record_id) from Parquet.

        source_file is required to avoid returning data from a different file that
        happens to share the same record_id (record_id is only unique per file).
        The cache key is (source_file, record_id) for the same reason.
        """
        if record_id is None:
            return "{}"

        cache_key = (source_file, record_id)

        # LRU cache hit.
        if cache_key in self._event_data_cache:
            self._event_data_cache.move_to_end(cache_key)
            return self._event_data_cache[cache_key]

        val = "{}"
        try:
            from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME
            import json as _json
            import duckdb

            manifest = os.path.join(self._parquet_dir, _MANIFEST_FILENAME)
            with open(manifest, "r", encoding="utf-8") as fh:
                shards = _json.load(fh)
            quoted = ", ".join(f"'{p.replace(chr(39), chr(39)*2)}'" for p in shards)
            con = duckdb.connect()
            try:
                if source_file:
                    row = con.execute(
                        f"SELECT event_data_json FROM parquet_scan([{quoted}]) "
                        f"WHERE record_id = ? AND source_file = ?",
                        [record_id, source_file],
                    ).fetchone()
                else:
                    row = con.execute(
                        f"SELECT event_data_json FROM parquet_scan([{quoted}]) "
                        f"WHERE record_id = ?",
                        [record_id],
                    ).fetchone()
            finally:
                con.close()
            if row and row[0]:
                val = row[0]
        except Exception as exc:
            logger.debug("event_data lazy-load failed for record_id=%s source_file=%s: %s",
                         record_id, source_file, exc)

        # LRU eviction.
        if len(self._event_data_cache) >= _EVENT_DATA_CACHE_SIZE:
            self._event_data_cache.popitem(last=False)
        self._event_data_cache[cache_key] = val
        return val

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def set_events(self, _events: list) -> None:
        """Compatibility shim — normal-mode EventTableModel has set_events().
        Called by _close_file_tab; delegates to close() for resource release."""
        self.close()

    def close(self) -> None:
        """Shut down filter thread and release Arrow table references."""
        self._generation += 1
        if self._filter_thread.isRunning():
            self._filter_thread.stop()
        self._display_table = None  # type: ignore[assignment]
        self._full_table    = None  # type: ignore[assignment]
        self._cache_dict    = {}

    # ── Legacy alias ──────────────────────────────────────────────────────────
    # Keep HeavyweightTableModel as an alias so any remaining isinstance() checks
    # or direct class references in main_window.py continue to work.

HeavyweightTableModel = ArrowTableModel
