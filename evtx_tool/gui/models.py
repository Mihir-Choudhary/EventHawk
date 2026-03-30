"""
Virtual table model for EVTX events.

Uses QAbstractTableModel (NOT QStandardItemModel) so Qt never copies data —
rowCount() and data() index directly into the Python list.
Handles 100K+ rows with zero lag.

FilterProxyModel provides debounced live-search across all visible columns.
"""

from __future__ import annotations

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
    Qt,
)
from PySide6.QtGui import QColor, QFont

# FINDING-9: import _parse_ts at module level so _passes_advanced() avoids
# executing an import statement on every row in the hot loop.
try:
    from evtx_tool.core.filters import _parse_ts as _filter_parse_ts
except ImportError:
    _filter_parse_ts = None  # type: ignore[assignment]

# ── Column definitions ────────────────────────────────────────────────────────
# Columns 0-8 are visible by default.
# Columns 9-19 are hidden by default; users can add them via Add/Remove Columns.

COLUMNS = [
    "#",               # 0
    "Event ID",        # 1
    "Level",           # 2
    "Timestamp",       # 3
    "Computer",        # 4
    "Channel",         # 5
    "User",            # 6
    "ATT&CK",          # 7
    "Source File",     # 8
    # ── Extended (hidden by default) ─────────────────────────────────────────
    "Keywords",        # 9
    "Operational Code",# 10
    "Log",             # 11
    "Process ID",      # 12
    "Thread ID",       # 13
    "Processor ID",    # 14
    "Session ID",      # 15
    "Kernel Time",     # 16
    "User Time",       # 17
    "Processor Time",  # 18
    "Correlation Id",  # 19
    "Record ID",       # 20
    "Provider",        # 21
]

COL_NUM       = 0
COL_EID       = 1
COL_LEVEL     = 2
COL_TS        = 3
COL_COMPUTER  = 4
COL_CHANNEL   = 5
COL_USER      = 6
COL_ATTACK    = 7
COL_SOURCE    = 8
COL_KEYWORDS  = 9
COL_OPCODE    = 10
COL_LOG       = 11
COL_PID       = 12
COL_TID       = 13
COL_PROC_ID   = 14
COL_SID       = 15
COL_KERN_TIME = 16
COL_USER_TIME = 17
COL_PROC_TIME = 18
COL_CORR_ID   = 19
COL_RECORD_ID = 20
COL_PROVIDER  = 21

# Number of columns shown by default (first N in COLUMNS list)
COL_DEFAULT_COUNT = 9

# ── Colours for level column ──────────────────────────────────────────────────

_LEVEL_FG = {
    "Critical":    QColor("#a01800"),
    "Error":       QColor("#a01800"),
    "Warning":     QColor("#7a4c00"),
    "Information": QColor("#1e1a14"),
    "Verbose":     QColor("#9a8878"),
    "LogAlways":   QColor("#9a8878"),
}

_BG_NORMAL = QColor("#f5f0e8")
_BG_ALT    = QColor("#ede8d8")
_BG_SEL    = QColor("#ddd4bc")

# Mono font for source file column
_MONO_FONT = QFont("Consolas", 9)

import os as _os
import sys as _sys

# ── Timezone display state ─────────────────────────────────────────────────────
# Module-level dict so all EventTableModel instances share the same setting.
# Updated by set_tz_config(); read by apply_tz() and _cell_text().

_tz_state: dict = {
    "mode": "local",            # "local" | "utc" | "specific" | "custom"
    "specific": "Asia/Kolkata", # IANA name used when mode == "specific"
    "custom_offset_min": 330,   # signed total minutes (e.g. +330 = +05:30)
}


def set_tz_config(
    mode: str,
    specific: str = "Asia/Kolkata",
    custom_offset_min: int = 330,
) -> None:
    """Update the global timezone display config for all EventTableModel instances."""
    _tz_state["mode"] = mode
    _tz_state["specific"] = specific
    _tz_state["custom_offset_min"] = custom_offset_min


def apply_tz(raw_ts: str) -> str:
    """
    Convert a raw ISO-8601/UTC event timestamp to a display string in the
    currently configured timezone.  Returns empty string for empty input;
    falls back gracefully if the timestamp cannot be parsed.
    """
    if not raw_ts:
        return ""
    try:
        from datetime import datetime as _dt2, timezone as _tz2, timedelta as _td2
        ts = raw_ts.strip()
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = _dt2.fromisoformat(ts)
        # Normalise to UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_tz2.utc)
        else:
            dt = dt.astimezone(_tz2.utc)
        # Convert to the selected display zone
        mode = _tz_state["mode"]
        if mode == "local":
            dt_out = dt.astimezone()                          # system local TZ
        elif mode == "utc":
            dt_out = dt                                       # already UTC
        elif mode == "specific":
            try:
                from zoneinfo import ZoneInfo
                dt_out = dt.astimezone(ZoneInfo(_tz_state["specific"]))
            except Exception:
                dt_out = dt                                   # fallback to UTC
        elif mode == "custom":
            tz = _tz2(offset=_td2(minutes=_tz_state["custom_offset_min"]))
            dt_out = dt.astimezone(tz)
        else:
            dt_out = dt
        return dt_out.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Never crash the UI — return stripped raw value
        return raw_ts.replace("T", " ").replace("Z", "")[:19]


class EventTableModel(QAbstractTableModel):
    """
    Virtual model — stores list[dict] events, never copies data into Qt items.
    Call set_events() to load or replace data (triggers full table reset).

    Performance: pre-builds a lowered search string per event so the proxy
    model's filterAcceptsRow() does a single ``in`` check, not O(fields)
    string concatenation per row per keystroke.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._events: list[dict] = []
        self._search_cache: list[str] = []   # pre-lowered search strings
        self._header_overrides: dict[int, str] = {}  # col_idx → custom header text

    # ── Qt interface ──────────────────────────────────────────────────────────

    def rowCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(self._events)

    def columnCount(self, parent: QModelIndex = QModelIndex()) -> int:
        return len(COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                return self._header_overrides.get(section, COLUMNS[section])
            if role == Qt.ItemDataRole.FontRole:
                f = QFont("Segoe UI", 8)
                f.setBold(True)
                return f
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        row = index.row()
        col = index.column()

        if row >= len(self._events):
            return None

        ev = self._events[row]

        if role == Qt.ItemDataRole.DisplayRole:
            return self._cell_text(ev, row, col)

        if role == Qt.ItemDataRole.ForegroundRole:
            return self._cell_fg(ev, col)

        if role == Qt.ItemDataRole.BackgroundRole:
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
            # Return the raw event dict so the detail panel can use it
            return ev

        return None

    # ── Cell helpers ──────────────────────────────────────────────────────────

    def _cell_text(self, ev: dict, row: int, col: int) -> str:
        if col == COL_NUM:
            return str(row + 1)
        if col == COL_EID:
            return str(ev.get("event_id", ""))
        if col == COL_LEVEL:
            return ev.get("level_name", "")
        if col == COL_TS:
            return apply_tz(ev.get("timestamp", ""))
        if col == COL_COMPUTER:
            return ev.get("computer", "")
        if col == COL_CHANNEL:
            ch = ev.get("channel", "")
            return ch.removeprefix("Microsoft-Windows-")
        if col == COL_USER:
            return ev.get("user_id", "")
        if col == COL_ATTACK:
            tags = ev.get("attack_tags") or []
            return tags[0]["tid"] if tags else ""
        if col == COL_SOURCE:
            return _os.path.basename(ev.get("source_file", ""))
        # ── Extended columns (indices 9-19) ───────────────────────────────────
        if col == COL_KEYWORDS:
            return str(ev.get("keywords", ""))
        if col == COL_OPCODE:
            return str(ev.get("opcode", ""))
        if col == COL_LOG:
            # "Log" falls back to Channel if a dedicated log field isn't present
            return ev.get("log", "") or ev.get("channel", "")
        if col == COL_PID:
            exec_info = ev.get("execution") or {}
            return str(ev.get("process_id", "") or exec_info.get("process_id", ""))
        if col == COL_TID:
            exec_info = ev.get("execution") or {}
            return str(ev.get("thread_id", "") or exec_info.get("thread_id", ""))
        if col == COL_PROC_ID:
            return str(ev.get("processor_id", ""))
        if col == COL_SID:
            return str(ev.get("session_id", ""))
        if col == COL_KERN_TIME:
            return str(ev.get("kernel_time", ""))
        if col == COL_USER_TIME:
            return str(ev.get("user_time", ""))
        if col == COL_PROC_TIME:
            return str(ev.get("processor_time", ""))
        if col == COL_CORR_ID:
            return str(ev.get("correlation_id", ""))
        if col == COL_RECORD_ID:
            return str(ev.get("record_id", ""))
        if col == COL_PROVIDER:
            return ev.get("provider", "")
        return ""

    def _cell_fg(self, ev: dict, col: int):
        if col == COL_LEVEL:
            return _LEVEL_FG.get(ev.get("level_name", ""), QColor("#9a8878"))
        if col == COL_NUM:
            return QColor("#9a8878")
        if col == COL_ATTACK:
            tags = ev.get("attack_tags") or []
            if tags:
                return QColor("#7a5c1e")
        if col == COL_SOURCE:
            return QColor("#9a8878")
        if ev.get("level_name") in ("Verbose", "LogAlways"):
            return QColor("#9a8878")
        return None   # use palette default

    # ── Data management ───────────────────────────────────────────────────────

    @staticmethod
    def _build_search_str(ev: dict) -> str:
        """Build a lowered, space-joined search string for one event.

        Called once per event at load time. The result is stored in
        ``_search_cache`` so filterAcceptsRow() does a single ``in``
        check instead of rebuilding the string per keystroke.
        """
        tags = ev.get("attack_tags") or []
        parts = [
            str(ev.get("event_id", "")),
            ev.get("level_name", ""),
            ev.get("timestamp", ""),
            ev.get("computer", ""),
            ev.get("channel", ""),
            ev.get("user_id", "") or "",
            ev.get("provider", ""),
            ev.get("source_file", ""),
        ]
        if tags:
            parts.append(" ".join(t.get("tid", "") for t in tags))
            parts.append(" ".join(t.get("tactic", "") for t in tags))
        ed = ev.get("event_data")
        if isinstance(ed, dict):
            # Use _ev_str() instead of str() to avoid repr double-escaping backslashes
            # when a field value is a list (e.g. multiple unnamed <Data> elements parsed
            # as {"Data": ["item1", "item2", "C:\\path\\..."]}). Also collapse any
            # backslash+whitespace sequences from XML line-split paths.
            for v in ed.values():
                if v and v != "-":
                    parts.append(_re.sub(r'\\\s+', r'\\', _ev_str(v)))
        elif ed:
            parts.append(_re.sub(r'\\\s+', r'\\', _ev_str(ed)))
        # Semantic description keys added by SemanticNormalizer (e.g. "Network (SMB / RPC)")
        # makes them searchable — user can type "network" or "audit failure" etc.
        for k, v in ev.items():
            if k.endswith("_desc") and v:
                parts.append(str(v))
        return " ".join(parts).lower()

    # ── Fast Python-level sorting (avoids 7M lessThan() C++→Python calls) ────

    _SORT_KEY_FUNCS = {
        0: lambda ev: 0,  # row number — identity order
        1: lambda ev: ev.get("event_id", 0),
        2: lambda ev: ev.get("level_name", ""),
        3: lambda ev: ev.get("timestamp", ""),
        4: lambda ev: ev.get("computer", ""),
        5: lambda ev: ev.get("channel", ""),
        6: lambda ev: ev.get("user_id", "") or "",
        7: lambda ev: (ev.get("attack_tags") or [{}])[0].get("tid", "") if ev.get("attack_tags") else "",
        8: lambda ev: _os.path.basename(ev.get("source_file", "")),
        20: lambda ev: ev.get("record_id", 0),   # Record ID — numeric
    }

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        """Sort events using Python's C-level list.sort() — ~100x faster than
        Qt's lessThan() callback approach for 400K rows."""
        if not self._events:
            return

        key_fn = self._SORT_KEY_FUNCS.get(column)
        if key_fn is None:
            return

        self.layoutAboutToBeChanged.emit()
        reverse = (order == Qt.SortOrder.DescendingOrder)

        # Build (key, original_index) pairs, sort, then reorder both lists
        n = len(self._events)
        indices = sorted(range(n), key=lambda i: key_fn(self._events[i]), reverse=reverse)
        self._events = [self._events[i] for i in indices]
        if len(self._search_cache) == n:
            self._search_cache = [self._search_cache[i] for i in indices]
        self.layoutChanged.emit()

    # High-cardinality fields that repeat across events — interning these makes
    # all events with the same value share one Python string object instead of
    # one per event.  For 400K events all in "Security" channel this saves
    # ~20 MB for that field alone.  Interning is O(1) per string via hash table.
    _INTERN_KEYS = ("channel", "computer", "level_name", "provider", "source_file")

    def set_events(self, events: list[dict], search_cache: list[str] | None = None) -> None:
        """Replace entire dataset. Called from GUI thread after worker finishes.

        Parameters
        ----------
        events : list[dict]
            The event data to display.
        search_cache : list[str] | None
            Pre-built search strings (from worker thread). If None, builds
            the cache here (blocks the main thread — avoid for large datasets).
        """
        # Point 1 (list[dict] memory): intern repeated string values so all
        # events with the same channel/computer/level share one Python object.
        _intern = _sys.intern
        _intern_keys = self._INTERN_KEYS
        for ev in events:
            for k in _intern_keys:
                v = ev.get(k)
                if isinstance(v, str):
                    ev[k] = _intern(v)

        self.beginResetModel()
        self._events = events
        if search_cache is not None and len(search_cache) == len(events):
            self._search_cache = search_cache
        else:
            self._search_cache = [self._build_search_str(ev) for ev in events]
        self.endResetModel()

    def get_event(self, row: int) -> dict | None:
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    def get_search_str(self, row: int) -> str:
        """Return the pre-computed lowercase search string for the given row."""
        if 0 <= row < len(self._search_cache):
            return self._search_cache[row]
        return ""

    def event_count(self) -> int:
        return len(self._events)


# ── Proxy model (live text filter) ────────────────────────────────────────────

import re as _re
from datetime import datetime as _dt, timedelta as _td, timezone as _tz


def _ev_str(val) -> str:
    """Flatten an event_data value to a plain string without repr-escaping.

    str(list) and str(dict) use repr() for nested elements, which double-escapes
    backslashes in Windows paths (C:\\foo → C:\\\\foo), breaking substring searches.

    pyevtx-rs wraps unnamed <Data> XML elements in one of these shapes:
      {"#text": "value"}            — single unnamed Data element
      {"#text": ["v1", "v2", ...]}  — multiple unnamed Data elements
      ["v1", "v2", ...]             — plain list variant

    All are flattened here with str() on leaf values, preserving single backslashes.
    """
    if isinstance(val, list):
        return " ".join(str(item) for item in val if item is not None)
    if isinstance(val, dict):
        # pyevtx-rs wraps unnamed <Data> elements as {"#text": value}
        text = val.get("#text")
        if text is not None:
            return _ev_str(text)
        # Named-field dicts: join all non-# values
        return " ".join(
            _ev_str(v) for k, v in val.items()
            if not k.startswith("#") and v is not None
        )
    return str(val)


class EventFilterProxyModel(QSortFilterProxyModel):
    """
    Multi-column text filter with optional tactic/technique filter AND
    advanced ELE-style filter from the FilterDialog.

    All three filter layers compose with AND logic:
      1. Tactic/technique filter (from ATT&CK tab click)
      2. Text filter (from live filter bar — uses pre-computed search cache)
      3. Advanced filter (from FilterDialog — uses pre-compiled state)

    Performance notes:
      - Layer 2 uses ``EventTableModel.get_search_str()`` which returns a
        pre-built lowercase haystack, so each keystroke is a single
        ``needle in haystack`` per row, not O(fields) string concat.
      - ``set_advanced_filter()`` pre-computes all state (lowered sets,
        compiled regex, parsed timestamps) so ``_passes_advanced()`` is
        pure comparison logic with zero allocation.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_text = ""
        self._tactic_filter: str | None = None      # lowercase tactic name
        self._technique_filter: str | None = None   # lowercase TID (e.g. "t1059")
        self._adv: dict | None = None                # advanced filter config

        # ── Layer 4: Quick Filter (ELE-style right-click filters) ─────────
        # Each entry: {"key": <event dict key>, "value": <str>, "include": <bool>}
        self._quick_filters: list[dict] = []
        # Pre-built lookup sets for O(1) filterAcceptsRow checks.
        # _rebuild_quick_sets() keeps these in sync with _quick_filters.
        self._quick_excludes: dict[str, set[str]] = {}  # key → excluded values
        self._quick_includes: dict[str, set[str]] = {}  # key → required values

        # ── Layer 5: Logon Session filter ──────────────────────────────────
        # When set, only events whose event_data contains a matching
        # TargetLogonId or SubjectLogonId are shown.
        self._session_logon_id: str | None = None

        # IOC pivot / session / missing-record-ID pivot: filter by int record_id.
        self._record_id_filter: frozenset | None = None

        # Bookmark filter: composite (source_file, record_id) key so that events
        # with the same record_id from different files are distinguished in merge mode.
        self._bookmark_key_filter: frozenset | None = None   # frozenset[tuple[str, int]]

        # FINDING-17: fast-path flag — set True whenever any filter layer is
        # active so filterAcceptsRow() can return True immediately when idle.
        self._any_filter_active: bool = False

        # ── Pre-compiled advanced filter state ────────────────────────────
        self._adv_levels: set[str] | None = None
        self._adv_eid_include: set[int] = set()
        self._adv_eid_exclude: set[int] = set()
        self._adv_eid_exclude_mode: bool = False
        self._adv_case_sensitive: bool = False
        self._adv_sources: list[str] = []      # already lowered (if not case-sensitive)
        self._adv_source_exclude: bool = False
        self._adv_categories: list[str] = []
        self._adv_category_exclude: bool = False
        self._adv_users: list[str] = []
        self._adv_user_exclude: bool = False
        self._adv_computers: list[str] = []
        self._adv_computer_exclude: bool = False
        self._adv_text: str = ""
        self._adv_text_regex: object | None = None   # compiled re.Pattern or None
        self._adv_text_exclude: bool = False
        self._adv_date_from: object | None = None    # datetime or None
        self._adv_date_to: object | None = None
        self._adv_date_active: bool = False
        self._adv_date_exclude: bool = False
        self._adv_rel_cutoff: object | None = None   # datetime or None
        self._adv_rel_exclude: bool = False
        self._adv_conditions: list[dict] = []

        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.setSortCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        # Point 3 (Python sort overhead): setDynamicSortFilter(True) causes Qt
        # to call sort() — which delegates to Python list.sort() on 400K rows —
        # after every invalidateFilter(). This means every keypress in the search
        # bar triggers a full sort. Setting False preserves the source model's
        # already-sorted order across filter changes without re-sorting.
        # Explicit sorts (header clicks) still work via the sort() override.
        self.setDynamicSortFilter(False)

    # FINDING-17: single flag updated by every filter setter so filterAcceptsRow
    # can skip all per-row checks when nothing is active.
    def _update_filter_active(self) -> None:
        self._any_filter_active = bool(
            self._tactic_filter
            or self._filter_text
            or self._adv
            or self._quick_filters
            or self._session_logon_id
            or self._record_id_filter
            or self._bookmark_key_filter
        )

    def clear_all_filters(self) -> None:
        """Reset every filter layer in one pass and call invalidateFilter() once."""
        if not self._any_filter_active:
            return  # nothing active — skip entirely
        self._filter_text        = ""
        self._record_id_filter   = None
        self._bookmark_key_filter = None
        self._session_logon_id   = None
        self._quick_filters      = []
        self._quick_excludes     = {}
        self._quick_includes     = {}
        # Reset advanced filter compiled state
        self._adv = None
        self._adv_levels = None
        self._adv_eid_include = set()
        self._adv_eid_exclude = set()
        self._adv_eid_exclude_mode = False
        self._adv_case_sensitive = False
        self._adv_sources = []
        self._adv_source_exclude = False
        self._adv_categories = []
        self._adv_category_exclude = False
        self._adv_users = []
        self._adv_user_exclude = False
        self._adv_computers = []
        self._adv_computer_exclude = False
        self._adv_text = ""
        self._adv_text_regex = None
        self._adv_text_exclude = False
        self._adv_date_from = None
        self._adv_date_to = None
        self._adv_date_active = False
        self._adv_date_exclude = False
        self._adv_rel_cutoff = None
        self._adv_rel_exclude = False
        self._adv_conditions = []
        self._any_filter_active = False
        self.invalidateFilter()

    def set_record_id_filter(self, ids: frozenset) -> None:
        """Show only events whose record_id is in ids (IOC pivot / session pivot)."""
        self._record_id_filter = ids
        self._update_filter_active()
        self.invalidateFilter()

    def clear_record_id_filter(self) -> None:
        """Remove IOC pivot record_id filter (no-op if not set)."""
        if self._record_id_filter is not None:
            self._record_id_filter = None
            self._update_filter_active()
            self.invalidateFilter()

    def set_bookmark_filter(self, keys: frozenset) -> None:
        """Show only events whose (source_file, record_id) pair is in keys."""
        self._bookmark_key_filter = keys
        self._update_filter_active()
        self.invalidateFilter()

    def clear_bookmark_filter(self) -> None:
        """Remove bookmark filter (no-op if not set)."""
        if self._bookmark_key_filter is not None:
            self._bookmark_key_filter = None
            self._update_filter_active()
            self.invalidateFilter()

    def _rebuild_quick_sets(self) -> None:
        """Rebuild pre-computed exclude/include sets from _quick_filters.

        Called whenever _quick_filters changes so filterAcceptsRow() can use
        O(1) ``in`` set checks instead of a per-row for-loop over the list.

        Example: two exclude filters on "channel" become
            self._quick_excludes["channel"] = {"security", "system"}
        The filterAcceptsRow hot-path then checks
            ev_val in self._quick_excludes.get("channel", ())
        which is a single C-level hash lookup, not a Python for-loop.
        """
        excl: dict[str, set[str]] = {}
        incl: dict[str, set[str]] = {}
        for qf in self._quick_filters:
            key = qf["key"]
            val = str(qf["value"]).lower()
            if qf["include"]:
                incl.setdefault(key, set()).add(val)
            else:
                excl.setdefault(key, set()).add(val)
        self._quick_excludes = excl
        self._quick_includes = incl

    def set_filter_text(self, text: str) -> None:
        self._filter_text = text.strip().lower()
        self._update_filter_active()
        self.invalidateFilter()

    def set_tactic_filter(self, tactic: str | None, technique: str | None = None) -> None:
        """
        Apply (or clear) a tactic/technique filter.
        Pass tactic=None to clear.  technique should be a TID string (e.g. "T1059").
        Both comparisons are case-insensitive.
        """
        self._tactic_filter = tactic.lower() if tactic else None
        self._technique_filter = technique.lower() if technique else None
        self._update_filter_active()
        self.invalidateFilter()

    # ── Advanced filter (from FilterDialog) ───────────────────────────────

    def set_advanced_filter(self, cfg: dict | None) -> None:
        """
        Apply (or clear) the advanced ELE-style filter.

        **Pre-compiles all filter state** so ``_passes_advanced()`` is
        pure comparison logic — no string lowering, no regex compilation,
        no timestamp parsing happens inside the per-row hot loop.
        """
        self._adv = cfg
        if not cfg:
            # Reset all pre-compiled state
            self._adv_levels = None
            self._adv_eid_include = set()
            self._adv_eid_exclude = set()
            self._adv_eid_exclude_mode = False
            self._adv_case_sensitive = False
            self._adv_sources = []
            self._adv_source_exclude = False
            self._adv_categories = []
            self._adv_category_exclude = False
            self._adv_users = []
            self._adv_user_exclude = False
            self._adv_computers = []
            self._adv_computer_exclude = False
            self._adv_text = ""
            self._adv_text_regex = None
            self._adv_text_exclude = False
            self._adv_date_from = None
            self._adv_date_to = None
            self._adv_date_active = False
            self._adv_date_exclude = False
            self._adv_rel_cutoff = None
            self._adv_rel_exclude = False
            self._adv_conditions = []
            self._update_filter_active()
            self.invalidateFilter()
            return

        from evtx_tool.core.filters import parse_event_id_expression, _parse_ts

        cs = cfg.get("case_sensitive", False)
        self._adv_case_sensitive = cs
        _low = (lambda s: s) if cs else (lambda s: s.lower())

        # Event ID sets
        self._adv_eid_include, self._adv_eid_exclude = parse_event_id_expression(
            cfg.get("event_id_expr", "")
        )
        self._adv_eid_exclude_mode = cfg.get("event_id_exclude", False)

        # Levels
        levels = cfg.get("levels")
        self._adv_levels = set(levels) if levels and len(levels) < 7 else None

        # Source / category / user / computer → pre-lower
        self._adv_sources = [_low(s) for s in cfg.get("sources", [])]
        self._adv_source_exclude = cfg.get("source_exclude", False)
        self._adv_categories = [_low(c) for c in cfg.get("categories", [])]
        self._adv_category_exclude = cfg.get("category_exclude", False)
        self._adv_users = [_low(u) for u in cfg.get("users", [])]
        self._adv_user_exclude = cfg.get("user_exclude", False)
        self._adv_computers = [_low(c) for c in cfg.get("computers", [])]
        self._adv_computer_exclude = cfg.get("computer_exclude", False)

        # Text search — pre-compile regex
        text_search = cfg.get("text_search", "")
        self._adv_text_exclude = cfg.get("text_exclude", False)
        if text_search and cfg.get("text_regex", False):
            try:
                flags = 0 if cs else _re.IGNORECASE
                self._adv_text_regex = _re.compile(text_search, flags)
            except _re.error:
                self._adv_text_regex = None
            self._adv_text = _low(text_search)
        else:
            self._adv_text_regex = None
            self._adv_text = _low(text_search) if text_search else ""

        # Date/time — pre-parse
        self._adv_date_active = bool(cfg.get("date_enabled") or cfg.get("time_enabled"))
        self._adv_date_exclude = cfg.get("date_exclude", False)
        self._adv_date_from = _parse_ts(cfg.get("date_from")) if cfg.get("date_from") else None
        self._adv_date_to = _parse_ts(cfg.get("date_to")) if cfg.get("date_to") else None

        # Relative time — pre-compute cutoff
        rel_days = cfg.get("relative_days", 0)
        rel_hours = cfg.get("relative_hours", 0)
        self._adv_rel_exclude = cfg.get("relative_exclude", False)
        if rel_days > 0 or rel_hours > 0:
            self._adv_rel_cutoff = _dt.now(_tz.utc) - _td(days=rel_days, hours=rel_hours)
        else:
            self._adv_rel_cutoff = None

        # Custom conditions — pre-lower values
        raw_conds = cfg.get("conditions", [])
        prepped: list[dict] = []
        for c in raw_conds:
            name = c.get("name", "")
            if not name:
                continue
            op = c.get("operator", "contains")
            val = c.get("value", "")
            entry: dict = {"name": name, "operator": op, "value": _low(val)}
            if op == "regex":
                try:
                    flags = 0 if cs else _re.IGNORECASE
                    entry["compiled"] = _re.compile(val, flags)
                except _re.error:
                    entry["compiled"] = None
            prepped.append(entry)
        self._adv_conditions = prepped

        self._update_filter_active()
        self.invalidateFilter()

    def has_advanced_filter(self) -> bool:
        """Return True if an advanced filter is currently active."""
        return self._adv is not None

    def get_advanced_filter(self) -> dict | None:
        """Return the current advanced filter config (for dialog restore)."""
        return self._adv

    def clear_advanced_filter(self) -> None:
        """Remove the advanced filter."""
        self.set_advanced_filter(None)

    # ── Quick filter (ELE-style right-click context filter) ────────────────

    def add_quick_filter(self, key: str, value: str, include: bool = True) -> None:
        """
        Add a Quick Filter constraint (stacks with AND logic).

        Parameters
        ----------
        key : str
            Event dict key, e.g. 'event_id', 'computer', 'channel', 'level_name', 'user_id'.
        value : str
            The cell value to match (compared case-insensitively).
        include : bool
            True = show only rows with this value; False = exclude rows with this value.
        """
        self._quick_filters.append({
            "key": key,
            "value": str(value).lower(),
            "include": include,
        })
        self._rebuild_quick_sets()
        self._update_filter_active()
        self.invalidateFilter()

    def set_quick_filters(self, filters: list[dict]) -> None:
        """Replace ALL quick filters atomically in a single invalidateFilter() call.

        Equivalent to clear_quick_filters() + N×add_quick_filter() but avoids
        N+1 invalidateFilter() calls — each of which causes Qt to re-evaluate
        filterAcceptsRow() on every visible row.

        ``filters`` is a list of dicts with keys 'key', 'value', 'include'.
        """
        self._quick_filters = [
            {"key": f["key"], "value": str(f["value"]).lower(), "include": bool(f["include"])}
            for f in filters
        ]
        self._rebuild_quick_sets()
        self._update_filter_active()
        self.invalidateFilter()

    def clear_quick_filters(self) -> None:
        """Remove all quick filters."""
        self._quick_filters.clear()
        self._rebuild_quick_sets()
        self._update_filter_active()
        self.invalidateFilter()

    def has_quick_filters(self) -> bool:
        """Return True if any quick filters are active."""
        return len(self._quick_filters) > 0

    def get_quick_filters(self) -> list[dict]:
        """Return current quick filter list (for UI display)."""
        return list(self._quick_filters)

    # ── Session LogonId filter (Layer 5) ──────────────────────────────────

    def set_session_filter(self, logon_id: str | None) -> None:
        """
        Show only events that belong to a specific logon session.

        Matches events whose event_data contains a TargetLogonId or
        SubjectLogonId equal to *logon_id*.  Pass None to clear.
        """
        self._session_logon_id = logon_id
        self._update_filter_active()
        self.invalidateFilter()

    def has_session_filter(self) -> bool:
        """Return True if a session filter is currently active."""
        return self._session_logon_id is not None

    def get_session_filter(self) -> str | None:
        """Return the active session LogonId, or None."""
        return self._session_logon_id

    def clear_session_filter(self) -> None:
        """Remove the session filter."""
        self.set_session_filter(None)

    # ── Sort override ─────────────────────────────────────────────────────

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802
        """Numeric sort for integer columns; string sort for everything else."""
        col = left.column()
        if col in (COL_NUM, COL_EID, COL_PID, COL_TID, COL_PROC_ID, COL_SID, COL_RECORD_ID):
            try:
                lv = int(left.data(Qt.ItemDataRole.DisplayRole) or "0")
                rv = int(right.data(Qt.ItemDataRole.DisplayRole) or "0")
                return lv < rv
            except (ValueError, TypeError):
                pass
        return super().lessThan(left, right)

    # ── Core filter logic ─────────────────────────────────────────────────

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        # FINDING-17: fast-path — skip all per-row checks when no filter is active.
        # This eliminates ~2M attribute accesses per sort/invalidation on 400K rows
        # in the idle (no-filter) state, which is the most common state.
        if not self._any_filter_active:
            return True

        src_model = self.sourceModel()
        if not isinstance(src_model, EventTableModel):
            return True

        ev = src_model.get_event(source_row)
        if ev is None:
            return True

        # ── Layer 0a: Bookmark pivot — (source_file, record_id) composite key ──
        # Uses a composite key so events with identical record_ids from different
        # files are correctly distinguished in merge mode.
        if self._bookmark_key_filter is not None:
            rid = ev.get("record_id")
            sf  = ev.get("source_file", "")
            return (sf, int(rid) if rid is not None else -1) in self._bookmark_key_filter

        # ── Layer 0b: IOC pivot — record_id exact match ──────────────────────
        # When active, only events that contributed to the pivoted IOC are shown.
        # This takes precedence over text/advanced filters so the count matches
        # exactly what the IOC extractor counted.
        if self._record_id_filter is not None:
            return ev.get("record_id") in self._record_id_filter

        # ── Layer 1: Tactic / technique filter ──────────────────────────────
        if self._tactic_filter:
            tags = ev.get("attack_tags") or []
            if not tags:
                return False
            if self._technique_filter:
                matched = any(
                    t.get("tactic", "").lower() == self._tactic_filter
                    and t.get("tid", "").lower() == self._technique_filter
                    for t in tags
                )
            else:
                matched = any(
                    t.get("tactic", "").lower() == self._tactic_filter
                    for t in tags
                )
            if not matched:
                return False

        # ── Layer 2: Live text filter bar (uses pre-computed cache) ─────────
        if self._filter_text:
            haystack = src_model.get_search_str(source_row)
            if self._filter_text not in haystack:
                return False

        # ── Layer 3: Advanced ELE-style filter ──────────────────────────────
        if self._adv:
            if not self._passes_advanced(ev):
                return False

        # ── Layer 4: Quick filter (right-click context filters) ──────────────
        # Uses pre-built sets (_quick_excludes / _quick_includes) for O(1)
        # hash lookups instead of iterating the _quick_filters list per row.
        if self._quick_excludes:
            for key, excl_set in self._quick_excludes.items():
                if str(ev.get(key, "")).lower() in excl_set:
                    return False
        if self._quick_includes:
            for key, incl_set in self._quick_includes.items():
                if str(ev.get(key, "")).lower() not in incl_set:
                    return False

        # ── Layer 5: Session LogonId filter ──────────────────────────────────
        if self._session_logon_id:
            ed = ev.get("event_data", {}) or {}
            # Different event types store the LogonId under different field names
            lid = (
                str(ed.get("TargetLogonId",  "") or "").strip() or
                str(ed.get("SubjectLogonId", "") or "").strip()
            )
            if lid != self._session_logon_id:
                return False

        return True

    def _passes_advanced(self, ev: dict) -> bool:
        """Apply all advanced filter criteria using pre-compiled state.

        No string lowering, regex compilation, or timestamp parsing happens
        here — all of that was done once in ``set_advanced_filter()``.
        """
        _low = (lambda s: s) if self._adv_case_sensitive else str.lower

        # ── Event types / levels ────────────────────────────────────────────
        if self._adv_levels is not None:
            if ev.get("level_name", "") not in self._adv_levels:
                return False

        # ── Event ID expression ─────────────────────────────────────────────
        eid = ev.get("event_id")
        if eid is not None:
            eid_int = int(eid)
            if self._adv_eid_include:
                in_inc = eid_int in self._adv_eid_include
                if self._adv_eid_exclude_mode:
                    if in_inc:
                        return False
                else:
                    if not in_inc:
                        return False
            if self._adv_eid_exclude:
                if eid_int in self._adv_eid_exclude:
                    return False

        # ── Source (provider) — pre-lowered sets ───────────────────────────
        if self._adv_sources:
            val = _low(ev.get("provider", ""))
            hit = any(s in val for s in self._adv_sources)
            if self._adv_source_exclude:
                if hit: return False
            else:
                if not hit: return False

        # ── Category (channel) ──────────────────────────────────────────────
        if self._adv_categories:
            val = _low(ev.get("channel", ""))
            hit = any(c in val for c in self._adv_categories)
            if self._adv_category_exclude:
                if hit: return False
            else:
                if not hit: return False

        # ── User ────────────────────────────────────────────────────────────
        if self._adv_users:
            val = _low(ev.get("user_id", "") or "")
            hit = any(u in val for u in self._adv_users)
            if self._adv_user_exclude:
                if hit: return False
            else:
                if not hit: return False

        # ── Computer ────────────────────────────────────────────────────────
        if self._adv_computers:
            val = _low(ev.get("computer", ""))
            hit = any(c in val for c in self._adv_computers)
            if self._adv_computer_exclude:
                if hit: return False
            else:
                if not hit: return False

        # ── Text in description ─────────────────────────────────────────────
        if self._adv_text:
            # Build haystack matching the search_text STORED GENERATED COLUMN scope:
            # event_id + level_name + channel + provider + computer + user_id +
            # source_file + event_data_json (all fields, not just event_data values).
            # This keeps normal mode and Juggernaut mode results consistent.
            parts: list[str] = []
            for _fld in ("event_id", "level_name", "channel", "provider",
                         "computer", "user_id", "source_file"):
                _v = ev.get(_fld)
                if _v is not None:
                    parts.append(str(_v))
            ed = ev.get("event_data", {}) or {}
            if isinstance(ed, dict):
                for v in ed.values():
                    if v is not None:
                        parts.append(_re.sub(r'\\\s+', r'\\', _ev_str(v)))
            elif ed:
                parts.append(_re.sub(r'\\\s+', r'\\', _ev_str(ed)))
            desc_text = " ".join(parts)
            if not self._adv_case_sensitive:
                desc_text = desc_text.lower()

            if self._adv_text_regex is not None:
                found = bool(self._adv_text_regex.search(desc_text))
            else:
                found = self._adv_text in desc_text

            if self._adv_text_exclude:
                if found: return False
            else:
                if not found: return False

        # ── Date/time filter (pre-parsed timestamps) ────────────────────────
        if self._adv_date_active:
            # FINDING-9: use module-level _filter_parse_ts (imported once at startup)
            event_ts = _filter_parse_ts(ev.get("timestamp")) if _filter_parse_ts else None
            if event_ts is None:
                return not self._adv_date_exclude
            in_range = True
            if self._adv_date_from and event_ts < self._adv_date_from:
                in_range = False
            if self._adv_date_to and event_ts > self._adv_date_to:
                in_range = False
            if self._adv_date_exclude:
                if in_range: return False
            else:
                if not in_range: return False

        # ── Relative time (pre-computed cutoff) ─────────────────────────────
        if self._adv_rel_cutoff is not None:
            # FINDING-9: use module-level _filter_parse_ts (imported once at startup)
            event_ts = _filter_parse_ts(ev.get("timestamp")) if _filter_parse_ts else None
            if event_ts is None:
                return not self._adv_rel_exclude
            in_window = event_ts >= self._adv_rel_cutoff
            if self._adv_rel_exclude:
                if in_window: return False
            else:
                if not in_window: return False

        # ── Custom conditions (pre-lowered, pre-compiled regex) ─────────────
        if self._adv_conditions:
            ed = ev.get("event_data", {}) or {}
            if not isinstance(ed, dict):
                return False
            for cond in self._adv_conditions:
                field_val = str(ed.get(cond["name"], "") or "")
                if not self._adv_case_sensitive:
                    field_val = field_val.lower()
                cv = cond["value"]
                op = cond["operator"]

                if op == "contains":
                    if cv not in field_val: return False
                elif op == "equals":
                    if field_val != cv: return False
                elif op == "starts with":
                    if not field_val.startswith(cv): return False
                elif op == "ends with":
                    if not field_val.endswith(cv): return False
                elif op == "not contains":
                    if cv in field_val: return False
                elif op == "not equals":
                    if field_val == cv: return False
                elif op == "regex":
                    pat = cond.get("compiled")
                    if pat and not pat.search(field_val):
                        return False
                elif op == "greater than":
                    try:
                        if not (float(field_val) > float(cv)): return False
                    except ValueError:
                        return False
                elif op == "less than":
                    try:
                        if not (float(field_val) < float(cv)): return False
                    except ValueError:
                        return False

        return True

    # ── Fast sort (delegate to source model's Python-level sort) ────────

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder) -> None:
        """Delegate sorting to the source model's Python-level sort.

        This avoids Qt's default lessThan() callback approach which requires
        O(n log n) C++ → Python transitions for 400K rows (~27s).
        Python's list.sort() does the same work in ~0.5s.
        """
        src = self.sourceModel()
        if isinstance(src, EventTableModel):
            src.sort(column, order)
            self.invalidate()  # rebuild proxy mapping after source reorder
        else:
            super().sort(column, order)

    # ── Helpers ───────────────────────────────────────────────────────────

    def get_source_event(self, proxy_row: int) -> dict | None:
        """Map proxy row index to the underlying event dict."""
        src_index = self.mapToSource(self.index(proxy_row, 0))
        src_model = self.sourceModel()
        if isinstance(src_model, EventTableModel):
            return src_model.get_event(src_index.row())
        return None

