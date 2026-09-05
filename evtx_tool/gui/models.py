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
    Signal,
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

_BG_NORMAL    = QColor("#f5f0e8")
_BG_ALT       = QColor("#ede8d8")
_BG_SEL       = QColor("#ddd4bc")
_BG_BOOKMARK  = QColor("#e8c96e")   # amber highlight for bookmarked rows

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


# ── Timestamp fractional-second precision ──────────────────────────────────────
# Analyst-selectable display precision for timestamps.  0 = whole seconds (the
# default — byte-identical to the historical behaviour), 3 = milliseconds,
# 6 = microseconds.  The underlying event timestamp is stored at full precision
# everywhere (parser/engine keep the raw SystemTime; the Juggernaut Arrow column
# keeps 26-char strings), so this is a pure display concern — no re-parse needed.
# Shared module-level state so apply_tz() (used by BOTH the normal table and the
# Juggernaut table) honours it for every model instance.

_ts_precision: dict = {"digits": 0}   # 0 | 3 | 6


def set_ts_precision(digits: int) -> None:
    """Set the global timestamp display precision (fractional-second digits)."""
    _ts_precision["digits"] = digits if digits in (0, 3, 6) else 0


def get_ts_precision() -> int:
    """Return the current timestamp display precision (0, 3, or 6)."""
    return _ts_precision["digits"]


def _frac_suffix(microsecond: int, digits: int) -> str:
    """Render the fractional-second suffix, e.g. '.898000' at 6 digits.

    Empty string at digits==0 (so the seconds-only path is byte-identical to the
    historical output — no trailing dot).  Zero-pads shorter fractions to the
    requested width and truncates (never rounds) longer ones.
    """
    if not digits:
        return ""
    try:
        micros = 0 if microsecond is None else max(0, min(999999, int(microsecond)))
    except (ValueError, TypeError):
        micros = 0
    return "." + f"{micros:06d}"[:digits]


def _micros_from_raw(raw_ts: str) -> int:
    """Extract the microsecond value from a raw ISO timestamp string.

    Used only by apply_tz's parse-failure fallback (the main path reads
    datetime.microsecond directly).  Right-pads a short fraction to 6 digits so
    '.898' → 898000, matching fromisoformat's interpretation on the main path.
    """
    s = str(raw_ts or "")
    i = s.find(".")
    if i == -1:
        return 0
    j = i + 1
    digs = ""
    while j < len(s) and s[j].isdigit() and len(digs) < 6:
        digs += s[j]
        j += 1
    return int(digs.ljust(6, "0")) if digs else 0


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
        return dt_out.strftime("%Y-%m-%d %H:%M:%S") + _frac_suffix(
            dt_out.microsecond, _ts_precision["digits"]
        )
    except Exception:
        # Never crash the UI — return stripped raw value
        return (
            raw_ts.replace("T", " ").replace("Z", "")[:19]
            + _frac_suffix(_micros_from_raw(raw_ts), _ts_precision["digits"])
        )


class EventRef:
    """Opaque carrier for an event dict returned via ``Qt.ItemDataRole.UserRole``.

    Returning the bare dict looks natural but is a data-corruption trap.  When
    Qt fetches a role through C++ -- ``index.data(role)``, which is the
    idiomatic call -- PySide converts a Python ``dict`` to a ``QVariantMap``,
    and that coerces every int to a SIGNED 64-bit value.  Windows event data
    carries UNSIGNED 64-bit values: BITS writes ``bandwidthLimit`` /
    ``fileLength`` / ``bytesTotal`` as 18446744073709551615 (2**64-1), which
    does not fit.  Measured on the real logs, ``index.data(UserRole)`` raises
    ``OverflowError`` on those events.

    An instance of an unknown Python class is passed through by reference
    instead of being converted, so the dict arrives untouched.  Read it with
    ``.event``.

    The app's own code paths use ``get_source_event()`` / ``get_event()``
    directly and never hit the C++ boundary, so this was latent -- but the
    obvious Qt call must not be a landmine.  See
    ``tests/test_signal_int_overflow.py``.
    """

    __slots__ = ("event",)

    def __init__(self, event: dict):
        self.event = event

    def __repr__(self) -> str:            # keeps debugger output readable
        ev = self.event or {}
        return f"<EventRef record_id={ev.get('record_id')!r} eid={ev.get('event_id')!r}>"


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
        # Advanced-text haystacks, lowered.  Built lazily on the first advanced
        # text filter (most sessions never run one, and building it eagerly
        # would slow every load), then reused for every subsequent pass.
        self._adv_search_cache: list[str] | None = None
        self._adv_cache_gen: int = 0
        self._adv_build_timer = None
        self._adv_partial: list[str] = []
        self._header_overrides: dict[int, str] = {}  # col_idx → custom header text
        self._bookmarked_keys: frozenset = frozenset()  # (source_file, record_id) pairs

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
            if self._bookmarked_keys:
                rid = ev.get("record_id")
                sf  = ev.get("source_file", "")
                if (sf, int(rid) if rid is not None else -1) in self._bookmarked_keys:
                    return _BG_BOOKMARK
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
            # Wrapped, NOT the bare dict — a dict is coerced to QVariantMap on
            # the C++ round trip and overflows on unsigned 64-bit event values.
            # See EventRef.
            return EventRef(ev)

        return None

    # ── Cell helpers ──────────────────────────────────────────────────────────

    def _cell_text(self, ev: dict, row: int, col: int) -> str:
        if col == COL_NUM:
            if self._bookmarked_keys:
                rid = ev.get("record_id")
                sf  = ev.get("source_file", "")
                if (sf, int(rid) if rid is not None else -1) in self._bookmarked_keys:
                    return f"★{row + 1}"
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
    def build_adv_search_str(ev: dict) -> str:
        """Haystack for the ADVANCED text filter (not the quick search bar).

        Deliberately a different scope from ``_build_search_str``: no timestamp,
        no ATT&CK tags, and event_data flattened RECURSIVELY via
        flatten_searchable_values -- i.e. exactly Juggernaut's ed_values blob,
        so the same query returns the same events in both modes.  Changing this
        scope changes which events an analyst sees, so the two must not be
        merged for convenience.

        Previously this was rebuilt inline for EVERY row on EVERY filter pass
        (recursive flatten plus a regex substitution per value, ~23 us/row):
        11.4 s of frozen GUI for one text search over 500k events.
        """
        from evtx_tool.core.filters import flatten_searchable_values as _fsv
        parts: list[str] = []
        # EVERY System-level field, not a hand-picked subset.  The old list
        # covered seven; the other twelve (timestamp, record_id, keywords, task,
        # opcode, pids, correlation, qualifiers, version, level, provider_guid,
        # event_source_name) were silently unsearchable, so a term the analyst
        # could see in the detail panel returned nothing from Advanced Filter.
        # Mirrors SEARCH_TEXT_EXPR_FULL so both modes answer identically.
        for _fld in ("event_id", "record_id", "level", "level_name", "channel",
                     "provider", "event_source_name", "provider_guid",
                     "computer", "user_id", "source_file", "timestamp",
                     "keywords", "correlation_id", "task", "opcode",
                     "process_id", "thread_id", "qualifiers", "version"):
            _v = ev.get(_fld)
            if _v is not None and _v != "":
                parts.append(str(_v))
        # Normal mode stores the ISO form ("...T...Z"); Juggernaut stores
        # "YYYY-MM-DD HH:MM:SS.ffffff".  Each mode could only find its own
        # rendering, so the same pasted timestamp hit in one and missed in the
        # other.  Both forms go in both haystacks.
        _ts = str(ev.get("timestamp") or "")
        if _ts:
            parts.append(_ts.replace("T", " ").rstrip("Z"))
        ed = ev.get("event_data", {}) or {}
        if ed:
            # Mirrors the JM side exactly: ed_values (normalised values) PLUS
            # event_data_json (the complete nested structure — container keys,
            # leaf names, values and attributes).  The JSON dump is what makes
            # field names searchable; walking keys by hand missed attributes,
            # and the two modes have to answer identically.
            for _val in _fsv(ed):
                parts.append(_re.sub(r'\\\s+', r'\\', _val))
            try:
                # MUST match how the Juggernaut engine serialises
                # event_data_json (orjson): compact separators and raw UTF-8.
                # Python's defaults differ on both counts -- ", " / ": " and
                # \uXXXX escapes -- so a search for '"Provider":"IntelMEProv"'
                # or for a non-ASCII field name would have hit in one mode and
                # missed in the other.
                parts.append(_json_mod.dumps(
                    ed, separators=(",", ":"), ensure_ascii=False, default=str))
            except Exception:
                parts.append(str(ed))
        return " ".join(parts)

    @staticmethod
    def _build_search_str(ev: dict) -> str:
        """Build a lowered, space-joined search string for one event.

        Called once per event at load time. The result is stored in
        ``_search_cache`` so filterAcceptsRow() does a single ``in``
        check instead of rebuilding the string per keystroke.
        """
        tags = ev.get("attack_tags") or []
        # `or ""` on every field, not just user_id: a key PRESENT with a None
        # value (rather than absent) made the join below raise TypeError, which
        # propagated out of set_events() and failed the whole model load.
        parts = [
            str(ev.get("event_id", "")),
            ev.get("level_name") or "",
            ev.get("timestamp") or "",
            ev.get("computer") or "",
            ev.get("channel") or "",
            ev.get("user_id") or "",
            ev.get("provider") or "",
            ev.get("source_file") or "",
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

    @staticmethod
    def _sort_mixed(v) -> tuple:
        """Order a display string the way a reader expects.

        Numeric-looking values sort numerically (PID 999 before 1000, not
        after it as a lexical sort would), everything else case-insensitively
        as text, and the two groups never compare against each other -- so the
        key is total and ``list.sort`` can never raise on mixed content.
        """
        s = "" if v is None else str(v)
        try:
            return (0, float(s), "")
        except (TypeError, ValueError):
            return (1, 0.0, s.lower())

    # Every column the table can DISPLAY needs an entry here: EventTableModel.
    # sort() silently returns when a column is missing, so an absent entry
    # means clicking that header does nothing at all, with no feedback.  The
    # extended columns were all missing; each key below mirrors the matching
    # branch of data() exactly, so the order always matches what is on screen.
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
        # ── Extended columns ──────────────────────────────────────────────
        9:  lambda ev: EventTableModel._sort_mixed(ev.get("keywords", "")),
        10: lambda ev: EventTableModel._sort_mixed(ev.get("opcode", "")),
        11: lambda ev: EventTableModel._sort_mixed(
            ev.get("log", "") or ev.get("channel", "")),
        12: lambda ev: EventTableModel._sort_mixed(
            ev.get("process_id", "")
            or (ev.get("execution") or {}).get("process_id", "")),
        13: lambda ev: EventTableModel._sort_mixed(
            ev.get("thread_id", "")
            or (ev.get("execution") or {}).get("thread_id", "")),
        14: lambda ev: EventTableModel._sort_mixed(ev.get("processor_id", "")),
        15: lambda ev: EventTableModel._sort_mixed(ev.get("session_id", "")),
        16: lambda ev: EventTableModel._sort_mixed(ev.get("kernel_time", "")),
        17: lambda ev: EventTableModel._sort_mixed(ev.get("user_time", "")),
        18: lambda ev: EventTableModel._sort_mixed(ev.get("processor_time", "")),
        19: lambda ev: EventTableModel._sort_mixed(ev.get("correlation_id", "")),
        21: lambda ev: EventTableModel._sort_mixed(ev.get("provider", "")),
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
        if self._adv_search_cache is not None and len(self._adv_search_cache) == n:
            self._adv_search_cache = [self._adv_search_cache[i] for i in indices]
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
        self._adv_search_cache = None      # dataset changed — rebuild on demand
        self._adv_cache_gen = getattr(self, "_adv_cache_gen", 0) + 1
        self._stop_adv_build()
        self.endResetModel()

    def get_event(self, row: int) -> dict | None:
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    # Chunk size for background haystack building.  Small enough that a chunk
    # is a few milliseconds, large enough that per-chunk overhead is noise.
    _ADV_CHUNK = 20_000

    def start_adv_cache_build(self) -> None:
        """Build the advanced-search haystack incrementally, off the hot path.

        Measured on 1,710,518 real events, building this the first time a text
        search runs froze the GUI for ~30 s -- the single worst stall in Normal
        Mode. It is pure Python string work, so a thread would hold the GIL and
        stall the UI anyway; instead it is built in timed slices that yield to
        the event loop between chunks, started as soon as the events land.

        A text search arriving before this finishes still works: the getter
        falls back to building the rest synchronously.
        """
        from PySide6.QtCore import QTimer
        if self._adv_search_cache is not None:
            return                      # already complete
        if getattr(self, "_adv_build_timer", None) is not None:
            return                      # already running
        self._adv_partial = []
        self._adv_build_gen = getattr(self, "_adv_cache_gen", 0)
        self._adv_build_timer = QTimer()
        self._adv_build_timer.setInterval(0)
        self._adv_build_timer.timeout.connect(self._adv_cache_step)
        self._adv_build_timer.start()

    def _adv_cache_step(self) -> None:
        # The dataset changed underneath us — abandon this build.
        if self._adv_build_gen != getattr(self, "_adv_cache_gen", 0):
            self._stop_adv_build()
            return
        start = len(self._adv_partial)
        end = min(start + self._ADV_CHUNK, len(self._events))
        for ev in self._events[start:end]:
            self._adv_partial.append(self.build_adv_search_str(ev).lower())
        if end >= len(self._events):
            self._adv_search_cache = self._adv_partial
            self._stop_adv_build()

    def _stop_adv_build(self) -> None:
        _t = getattr(self, "_adv_build_timer", None)
        if _t is not None:
            _t.stop()
        self._adv_build_timer = None
        self._adv_partial = []

    def get_adv_search_str(self, row: int) -> str:
        """Lowered advanced-filter haystack for *row*, building the cache once."""
        if self._adv_search_cache is None:
            # A search beat the background build. Finish what it started rather
            # than throwing the partial result away.
            partial = getattr(self, "_adv_partial", None) or []
            self._stop_adv_build()
            for ev in self._events[len(partial):]:
                partial.append(self.build_adv_search_str(ev).lower())
            self._adv_search_cache = partial
        if 0 <= row < len(self._adv_search_cache):
            return self._adv_search_cache[row]
        return ""

    def get_search_str(self, row: int) -> str:
        """Return the pre-computed lowercase search string for the given row."""
        if 0 <= row < len(self._search_cache):
            return self._search_cache[row]
        return ""

    def event_count(self) -> int:
        return len(self._events)

    def set_bookmark_highlights(self, keys: "frozenset[tuple[str, int]]") -> None:
        """Update which rows receive the amber bookmark highlight."""
        self._bookmarked_keys = keys
        n = len(self._events)
        if n > 0:
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(n - 1, len(COLUMNS) - 1),
            )


# ── Proxy model (live text filter) ────────────────────────────────────────────

import json as _json_mod
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

    # Emitted around EVERY filter pass, whichever setter triggered it.
    # Wrapping the ~30 call sites individually was how some paths ended up
    # with no feedback at all; bracketing invalidateFilter() catches them all,
    # including ones added later.
    filtering_started  = Signal()
    filtering_finished = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._filter_depth = 0
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
        # TargetLogonId or SubjectLogonId are shown.  _session_computer scopes
        # the filter to a single host so that different machines with the same
        # LUID value are not conflated in multi-host loads.  The optional time
        # bounds prevent same-host LogonId reuse later in the dataset from
        # leaking into the selected session view.
        self._session_logon_id: str | None = None
        self._session_computer: str | None = None
        self._session_linked_lid: str | None = None   # sibling split-token session
        self._session_start_ts: str | None = None
        self._session_end_ts: str | None = None
        self._session_end_inclusive: bool = False
        self._session_start_dt: object | None = None
        self._session_end_dt: object | None = None

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
        self._adv_text_terms: list[str] = []          # all terms, pre-lowered
        self._adv_text_regexes: list = []             # compiled, one per term
        self._adv_text_mode: str = "AND"
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

    def invalidateFilter(self) -> None:      # noqa: N802  (Qt naming)
        """Bracket every filter pass with start/finish signals.

        Qt re-runs filterAcceptsRow for every row here, which on a large
        dataset is seconds of frozen GUI. The signals let the window put a
        wait dialog up so that stall reads as "working", not "crashed".

        Depth-counted because setters legitimately nest, and a nested pass must
        not close the dialog the outer one opened.
        """
        self._filter_depth += 1
        if self._filter_depth == 1:
            try:
                self.filtering_started.emit()
            except RuntimeError:
                pass
        try:
            super().invalidateFilter()
        finally:
            self._filter_depth -= 1
            if self._filter_depth == 0:
                try:
                    self.filtering_finished.emit()
                except RuntimeError:
                    pass

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
        self._session_computer   = None
        self._session_linked_lid = None
        self._session_start_ts   = None
        self._session_end_ts     = None
        self._session_end_inclusive = False
        self._session_start_dt   = None
        self._session_end_dt     = None
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
        self._adv_text_terms = []      # must reset with the rest, or a cleared
        self._adv_text_regexes = []    # filter leaves the predicate gate armed
        self._adv_text_mode = "AND"
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
            self._adv_dt_mode = "range"
            self._adv_date_from_d = self._adv_date_from_t = None
            self._adv_date_to_d   = self._adv_date_to_t   = None
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
        self._adv_levels = set(levels) if levels and len(levels) < 8 else None

        # Source / category / user / computer → pre-lower
        self._adv_sources = [_low(s) for s in cfg.get("sources", [])]
        self._adv_source_exclude = cfg.get("source_exclude", False)
        self._adv_categories = [_low(c) for c in cfg.get("categories", [])]
        self._adv_category_exclude = cfg.get("category_exclude", False)
        self._adv_users = [_low(u) for u in cfg.get("users", [])]
        self._adv_user_exclude = cfg.get("user_exclude", False)
        self._adv_computers = [_low(c) for c in cfg.get("computers", [])]
        self._adv_computer_exclude = cfg.get("computer_exclude", False)

        # Text search — pre-compile regex.
        # text_search may be a STRING or a LIST of terms: the Juggernaut side
        # has always accepted both (text_config_to_parquet_sql normalises), and
        # a list here used to raise AttributeError: 'list' object has no
        # attribute 'lower' — a hard crash, not a wrong result.
        _raw_ts = cfg.get("text_search", "")
        if isinstance(_raw_ts, (list, tuple)):
            _terms = [str(t) for t in _raw_ts if str(t).strip()]
        else:
            _terms = [str(_raw_ts)] if str(_raw_ts).strip() else []
        self._adv_text_terms = [_low(t) for t in _terms]
        self._adv_text_mode = str(cfg.get("search_mode", "AND") or "AND").upper()
        self._adv_text_exclude = cfg.get("text_exclude", False)
        text_search = _terms[0] if _terms else ""
        if _terms and cfg.get("text_regex", False):
            flags = 0 if cs else _re.IGNORECASE
            self._adv_text_regexes = []
            for _t in _terms:
                try:
                    self._adv_text_regexes.append(_re.compile(_t, flags))
                except _re.error:
                    self._adv_text_regexes.append(None)
            self._adv_text_regex = self._adv_text_regexes[0]
            self._adv_text = _low(text_search)
        else:
            self._adv_text_regexes = []
            self._adv_text_regex = None
            self._adv_text = _low(text_search) if text_search else ""

        # Date/time — pre-parse
        # Determine filtering mode from the three checkboxes:
        #   date_only  — compare the date portion only  (Date ✓, Time ✗)
        #   time_only  — compare the time-of-day only   (Date ✗, Time ✓)
        #   separate   — date portion AND time portion independently (Date ✓, Time ✓, Separately ✓)
        #   range      — combined datetime range (Date ✓, Time ✓, Separately ✗, or specific_day)
        _date_en  = bool(cfg.get("date_enabled"))
        _time_en  = bool(cfg.get("time_enabled"))
        _sep_en   = bool(cfg.get("separately_enabled"))
        _spec_en  = bool(cfg.get("specific_day_enabled"))
        self._adv_date_active = bool(_date_en or _time_en or _spec_en)
        if _spec_en or (_date_en and _time_en and not _sep_en):
            self._adv_dt_mode = "range"
        elif _date_en and _time_en and _sep_en:
            self._adv_dt_mode = "separate"
        elif _date_en and not _time_en:
            self._adv_dt_mode = "date_only"
        elif _time_en and not _date_en:
            self._adv_dt_mode = "time_only"
        else:
            self._adv_dt_mode = "range"
        self._adv_date_exclude = cfg.get("date_exclude", False)
        self._adv_date_from = _parse_ts(cfg.get("date_from")) if cfg.get("date_from") else None
        self._adv_date_to   = _parse_ts(cfg.get("date_to"))   if cfg.get("date_to")   else None

        # ── Timezone correction ──────────────────────────────────────────
        # The filter dialog emits date_from/date_to as naive strings in the
        # user's *display* timezone (e.g. "2025-09-26 00:00:00" means midnight
        # IST if the user is in IST).  _parse_ts() wrongly stamps them as UTC.
        # Correct by re-interpreting the parsed datetime in the display timezone
        # and converting to true UTC, so the comparison vs event timestamps
        # (stored as UTC) matches what the user actually sees in the table.
        if self._adv_date_from or self._adv_date_to:
            from datetime import timezone as _tz, timedelta as _td
            mode = _tz_state["mode"]
            display_tz = None  # None means UTC — no shift needed
            use_system_local = False
            if mode == "local":
                # NOT a fixed offset captured "right now": the boundary belongs
                # to the LOG's date. In a DST zone, filtering January logs from
                # July shifted the boundary by an hour relative to the table
                # display — events silently landing on the wrong day. A naive
                # datetime passed to astimezone() is read as system local time
                # with the rules in force on ITS OWN date, matching apply_tz().
                use_system_local = True
            elif mode == "specific":
                try:
                    from zoneinfo import ZoneInfo
                    display_tz = ZoneInfo(_tz_state["specific"])
                except Exception:
                    pass
            elif mode == "custom":
                display_tz = _tz(offset=_td(minutes=_tz_state["custom_offset_min"]))
            # mode == "utc" → display_tz stays None → no conversion needed.

            if display_tz is not None or use_system_local:
                # Re-interpret: read the boundary in the display timezone, then
                # convert to true UTC.
                def _boundary_to_utc(_d):
                    naive = _d.replace(tzinfo=None)
                    if use_system_local:
                        return naive.astimezone(_tz.utc)
                    return naive.replace(tzinfo=display_tz).astimezone(_tz.utc)

                if self._adv_date_from:
                    self._adv_date_from = _boundary_to_utc(self._adv_date_from)
                if self._adv_date_to:
                    self._adv_date_to = _boundary_to_utc(self._adv_date_to)
                # Force to "range" mode.  The date_only / time_only / separate
                # modes extract .date() / .time() from the UTC-converted
                # boundaries, but those parts do NOT correspond to the user's
                # display-TZ calendar date or clock time.  Example: midnight
                # IST (+5:30) → 18:30 UTC on the PREVIOUS day, so .date() is
                # off by 1 and .time() inverts (18:30 > 18:29 → always False).
                # The full datetime range comparison is correct after conversion.
                if self._adv_dt_mode in ("date_only", "time_only", "separate"):
                    self._adv_dt_mode = "range"

        # Pre-extract date/time parts to avoid per-row method calls in filterAcceptsRow()
        self._adv_date_from_d = self._adv_date_from.date() if self._adv_date_from else None
        self._adv_date_from_t = self._adv_date_from.time() if self._adv_date_from else None
        self._adv_date_to_d   = self._adv_date_to.date()   if self._adv_date_to   else None
        self._adv_date_to_t   = self._adv_date_to.time()   if self._adv_date_to   else None

        # Relative time — pre-compute cutoff
        rel_days = cfg.get("relative_days", 0)
        rel_hours = cfg.get("relative_hours", 0)
        self._adv_rel_exclude = cfg.get("relative_exclude", False)
        if rel_days > 0 or rel_hours > 0:
            self._adv_rel_cutoff = _dt.now(_tz.utc) - _td(days=rel_days, hours=rel_hours)
        else:
            self._adv_rel_cutoff = None

        # Custom conditions — pre-lower values, pre-expand format variants.
        # expand_condition_value() handles two classes of mismatch:
        #
        #   1. Numeric hex ↔ decimal — applied UNIVERSALLY to every field.
        #      Typing "1936" matches stored "0x790" (and vice-versa) in
        #      ProcessId, NewProcessId, TargetLogonId, HandleId, custom
        #      Sysmon fields, third-party providers — anything numeric.
        #      Safe because adding hex variants to a decimal-only field
        #      never produces false positives (the hex form simply isn't
        #      present in that field's rows).
        #
        #   2. Field-specific symbolic aliases for cases where stored form
        #      is a wholly different STRING:
        #        LogonType          "3" ↔ "Network", "10" ↔ "RDP" / "RemoteInteractive"
        #        ElevatedToken      "%%1842" ↔ "Yes", "true", "1"
        #        VirtualAccount     same
        #        TokenElevationType "%%19xx" ↔ "Full" / "Default" / "Limited"
        #
        # We freeze the resulting set so the per-row hot path is O(1) membership.
        from evtx_tool.core.heavyweight.filter_sql import expand_condition_value
        raw_conds = cfg.get("conditions", [])
        prepped: list[dict] = []
        for c in raw_conds:
            name = c.get("name", "")
            if not name:
                continue
            op = c.get("operator", "contains")
            val = c.get("value", "")
            entry: dict = {"name": name, "operator": op, "value": _low(val)}
            # Pre-compute format/symbolic variants so the per-row hot path is
            # just a set lookup.
            if op in ("equals", "not equals", "contains", "not contains"):
                _variants = expand_condition_value(name, val)
                if len(_variants) > 1:
                    if not cs:
                        _variants = [v.lower() for v in _variants]
                    entry["variants"] = frozenset(_variants)
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
        # Replace any existing filter for the same key to avoid impossible AND
        # conditions (e.g. include "Security" AND include "System" on the same
        # column would match nothing).  Mirrors JM mode behavior.
        self._quick_filters = [f for f in self._quick_filters if f["key"] != key]
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

    def set_session_filter(
        self,
        logon_id: str | None,
        computer: str | None = None,
        start_ts: str | None = None,
        end_ts: str | None = None,
        end_inclusive: bool = False,
        linked_lid: str | None = None,
    ) -> None:
        """
        Show only events that belong to a specific logon session.

        Matches events whose event_data contains a TargetLogonId or
        SubjectLogonId equal to *logon_id*.  When *computer* is provided the
        filter is also scoped to that host, preventing false matches in
        multi-host loads where different machines can share the same LUID.
        Optional *start_ts* / *end_ts* bounds further scope the filter to the
        concrete session instance so later LogonId reuse on the same host is
        excluded.  *linked_lid* widens the filter to include a sibling
        split-token / UAC-elevated session.  Pass logon_id=None to clear.

        All fields are set atomically before the single invalidateFilter() call
        so the proxy is never re-scanned with a partially-updated state.
        """
        self._session_logon_id = logon_id
        self._session_computer = computer if logon_id else None
        self._session_linked_lid = (linked_lid or None) if logon_id else None
        self._session_start_ts = start_ts if logon_id and start_ts else None
        self._session_end_ts = end_ts if logon_id and end_ts else None
        self._session_end_inclusive = bool(logon_id and self._session_end_ts and end_inclusive)
        self._session_start_dt = (
            _filter_parse_ts(self._session_start_ts) if self._session_start_ts and _filter_parse_ts else None
        )
        self._session_end_dt = (
            _filter_parse_ts(self._session_end_ts) if self._session_end_ts and _filter_parse_ts else None
        )
        self._update_filter_active()
        self.invalidateFilter()  # single pass — all fields already committed above

    def has_session_filter(self) -> bool:
        """Return True if a session filter is currently active."""
        return self._session_logon_id is not None

    def get_session_filter(self) -> str | None:
        """Return the active session LogonId, or None."""
        return self._session_logon_id

    def get_session_filter_computer(self) -> str | None:
        """Return the active session computer scope, or None."""
        return self._session_computer

    def get_session_filter_start_ts(self) -> str | None:
        """Return the active session start boundary, or None."""
        return self._session_start_ts

    def get_session_filter_end_ts(self) -> str | None:
        """Return the active session end boundary, or None."""
        return self._session_end_ts

    def get_session_filter_end_inclusive(self) -> bool:
        """Return whether the active session end boundary is inclusive."""
        return self._session_end_inclusive

    def get_session_linked_lid(self) -> str | None:
        """Return the active sibling split-token session's LogonId, or None."""
        return self._session_linked_lid

    def set_session_linked_lid(self, linked_lid: str | None) -> None:
        """Set the sibling split-token session's LogonId so its events are
        included when the primary session filter is active.

        Prefer passing linked_lid to set_session_filter() directly when
        possible — it sets all fields atomically with a single invalidation.
        This method exists for callers that need to update the linked lid
        independently after the primary filter is already active.
        """
        self._session_linked_lid = linked_lid or None
        if self._session_logon_id:
            self._update_filter_active()
            self.invalidateFilter()

    def clear_session_filter(self) -> None:
        """Remove the session filter."""
        self.set_session_filter(None)
        self._session_linked_lid = None

    # ── Sort override ─────────────────────────────────────────────────────

    def lessThan(self, left: QModelIndex, right: QModelIndex) -> bool:  # noqa: N802
        """Numeric sort for integer columns; string sort for everything else."""
        col = left.column()
        if col in (COL_NUM, COL_EID, COL_PID, COL_TID, COL_PROC_ID, COL_SID, COL_RECORD_ID):
            try:
                # Strip bookmark star prefix ("★42" → "42") before int conversion
                lv = int((left.data(Qt.ItemDataRole.DisplayRole) or "0").lstrip("★").strip() or "0")
                rv = int((right.data(Qt.ItemDataRole.DisplayRole) or "0").lstrip("★").strip() or "0")
                return lv < rv
            except (ValueError, TypeError):
                pass
        return super().lessThan(left, right)

    # ── Core filter logic ─────────────────────────────────────────────────

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        try:
            return self._filterAcceptsRow_impl(source_row, source_parent)
        except Exception:
            import logging as _log
            _log.getLogger("eventhawk.filter").exception(
                "filterAcceptsRow raised an exception at source_row=%d", source_row
            )
            return True  # show row rather than hide it on error

    def _filterAcceptsRow_impl(self, source_row: int, source_parent: QModelIndex) -> bool:
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
            if not self._passes_advanced(ev, source_row, src_model):
                return False

        # ── Layer 4: Quick filter (right-click context filters) ──────────────
        # Uses pre-built sets (_quick_excludes / _quick_includes) for O(1)
        # hash lookups instead of iterating the _quick_filters list per row.
        #
        # Virtual key semantics:
        #   "timestamp_date" → display-timezone YYYY-MM-DD (via apply_tz), so
        #       the filter matches the date the user actually sees in the table.
        #   "log" → ev["log"] falling back to ev["channel"], matching COL_LOG
        #       display logic in EventTableModel.data().
        if self._quick_excludes:
            for key, excl_set in self._quick_excludes.items():
                if key == "timestamp_date":
                    ev_val = apply_tz(ev.get("timestamp", ""))[:10].lower()
                elif key == "log":
                    ev_val = str(ev.get("log") or ev.get("channel", "")).lower()
                else:
                    ev_val = str(ev.get(key, "")).lower()
                if ev_val in excl_set:
                    return False
        if self._quick_includes:
            for key, incl_set in self._quick_includes.items():
                if key == "timestamp_date":
                    ev_val = apply_tz(ev.get("timestamp", ""))[:10].lower()
                elif key == "log":
                    ev_val = str(ev.get("log") or ev.get("channel", "")).lower()
                else:
                    ev_val = str(ev.get(key, "")).lower()
                if ev_val not in incl_set:
                    return False

        # ── Layer 5: Session LogonId filter ──────────────────────────────────
        if self._session_logon_id:
            # Scope to the originating host first (prevents false matches when
            # different machines share the same LUID in a multi-host load).
            if self._session_computer:
                if ev.get("computer", "") != self._session_computer:
                    return False
            ed = ev.get("event_data", {}) or {}
            # Check both fields independently — an event belongs to the session
            # if EITHER TargetLogonId OR SubjectLogonId matches.
            target_lid  = str(ed.get("TargetLogonId",  "") or "").strip()
            subject_lid = str(ed.get("SubjectLogonId", "") or "").strip()
            lids_match = (
                target_lid == self._session_logon_id
                or subject_lid == self._session_logon_id
                or (self._session_linked_lid and (
                    target_lid == self._session_linked_lid
                    or subject_lid == self._session_linked_lid
                ))
            )
            if not lids_match:
                return False
            if self._session_start_dt or self._session_end_dt:
                event_ts = _filter_parse_ts(ev.get("timestamp")) if _filter_parse_ts else None
                if event_ts is None:
                    return False
                if self._session_start_dt and event_ts < self._session_start_dt:
                    return False
                if self._session_end_dt:
                    if self._session_end_inclusive:
                        if event_ts > self._session_end_dt:
                            return False
                    elif event_ts >= self._session_end_dt:
                        return False

        return True

    def _passes_advanced(self, ev: dict, source_row: int = -1,
                         src_model: "EventTableModel | None" = None) -> bool:
        """Apply all advanced filter criteria using pre-compiled state.

        No string lowering, regex compilation, or timestamp parsing happens
        here — all of that was done once in ``set_advanced_filter()``.
        """
        _low = (lambda s: s) if self._adv_case_sensitive else str.lower

        # ── Event types / levels ────────────────────────────────────────────
        # Standard ETW levels are stored in level_name ("Critical", "Error", …).
        # "Audit Success" and "Audit Failure" are NOT — they're encoded in the
        # Keywords bitfield (bit 53 = success, bit 52 = failure).  A plain
        # ``level_name in _adv_levels`` check on those two would silently match
        # zero rows.  Detect them via the Keywords value when present.
        if self._adv_levels is not None:
            _lv = ev.get("level_name", "")
            if _lv in self._adv_levels:
                pass   # standard level match — fast path
            else:
                _matched = False
                _audit_su = "Audit Success" in self._adv_levels
                _audit_fa = "Audit Failure" in self._adv_levels
                if _audit_su or _audit_fa:
                    try:
                        _kw_int = int(ev.get("keywords", "") or "0", 16)
                    except (ValueError, TypeError):
                        _kw_int = 0
                    if _audit_su and (_kw_int & 0x0020000000000000):
                        _matched = True
                    elif _audit_fa and (_kw_int & 0x0010000000000000):
                        _matched = True
                if not _matched:
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

        # ── Source (provider + channel) — pre-lowered sets ──────────────────
        if self._adv_sources:
            # Check both provider and channel to match JM mode (filter_sql.py),
            # where the "Source" field searches both columns with OR logic.
            prov = _low(ev.get("provider", ""))
            chan = _low(ev.get("channel", ""))
            hit = any(s in prov or s in chan for s in self._adv_sources)
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
            # Align with JM mode which checks user_id, ed_subject_user, and
            # ed_target_user (SubjectUserName / TargetUserName from event_data).
            _ed_u = ev.get("event_data") or {}
            if not isinstance(_ed_u, dict):
                _ed_u = {}
            _user_parts = [
                ev.get("user_id") or "",
                _ed_u.get("SubjectUserName") or "",
                _ed_u.get("TargetUserName") or "",
                _ed_u.get("SubjectUserSid") or "",
                _ed_u.get("TargetUserSid") or "",
            ]
            val = _low(" ".join(str(p) for p in _user_parts if p))
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
        if self._adv_text_terms:
            # Build haystack matching the search_text STORED GENERATED COLUMN scope:
            # event_id + level_name + channel + provider + computer + user_id +
            # source_file + event_data_json (all fields, not just event_data values).
            # This keeps normal mode and Juggernaut mode results consistent.
            # Same haystack scope as before (see build_adv_search_str), but
            # taken from a cache built once per dataset instead of being
            # reconstructed for every row on every pass.  The case-sensitive
            # path is rare and needs original case, so it still builds inline.
            if src_model is not None and source_row >= 0 and not self._adv_case_sensitive:
                desc_text = src_model.get_adv_search_str(source_row)
            else:
                # Case-sensitive search needs original case, and a caller that
                # passed no model/row (direct use in tests) must still work.
                desc_text = EventTableModel.build_adv_search_str(ev)
                if not self._adv_case_sensitive:
                    desc_text = desc_text.lower()

            # Every term, combined per search_mode — matches the Juggernaut
            # side, which ANDs/ORs the same list.
            if self._adv_text_regexes:
                hits = [bool(r.search(desc_text)) if r is not None else False
                        for r in self._adv_text_regexes]
            else:
                hits = [t in desc_text for t in self._adv_text_terms]
            if not hits:
                found = False
            elif self._adv_text_mode == "OR":
                found = any(hits)
            else:
                found = all(hits)

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
            mode = self._adv_dt_mode
            if mode == "date_only":
                # Compare only the calendar date — time-of-day is ignored
                ev_d    = event_ts.date()
                in_range = (
                    (self._adv_date_from_d is None or ev_d >= self._adv_date_from_d) and
                    (self._adv_date_to_d   is None or ev_d <= self._adv_date_to_d)
                )
            elif mode == "time_only":
                # Compare only the time-of-day — calendar date is ignored
                ev_t    = event_ts.time()
                in_range = (
                    (self._adv_date_from_t is None or ev_t >= self._adv_date_from_t) and
                    (self._adv_date_to_t   is None or ev_t <= self._adv_date_to_t)
                )
            elif mode == "separate":
                # Date condition AND time condition applied independently
                ev_d = event_ts.date()
                ev_t = event_ts.time()
                in_range = (
                    (self._adv_date_from_d is None or ev_d >= self._adv_date_from_d) and
                    (self._adv_date_to_d   is None or ev_d <= self._adv_date_to_d)   and
                    (self._adv_date_from_t is None or ev_t >= self._adv_date_from_t) and
                    (self._adv_date_to_t   is None or ev_t <= self._adv_date_to_t)
                )
            else:
                # "range" — combined datetime comparison (also used for specific_day)
                in_range = (
                    (self._adv_date_from is None or event_ts >= self._adv_date_from) and
                    (self._adv_date_to   is None or event_ts <= self._adv_date_to)
                )
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
            ed = ev.get("event_data") or {}
            if not isinstance(ed, dict):
                ed = {}
            # Nested-aware field map so conditions resolve fields nested inside a
            # container element — identical to JM's ed_flat_json and normal-mode
            # _conditions_pass, so conditions match across all three paths.
            from evtx_tool.core.filters import flatten_fields as _flatten_fields
            ed_flat = _flatten_fields(ed)
            # Lazy-imported once outside the condition loop
            from evtx_tool.core.heavyweight.filter_sql import _FIELD_DUAL_SOURCE
            for cond in self._adv_conditions:
                name = cond["name"]
                # Build the list of candidate field values this condition can
                # match against.  Normally one value (top-level event dict or
                # event_data sub-field).  For dual-source fields like
                # ProcessId / ThreadId we ALSO include the top-level column
                # equivalent (process_id / thread_id) so the user finds events
                # whose PID lives in <Execution> rather than event_data.
                candidates: list[str] = []
                raw1 = ev.get(name)
                raw2 = ed_flat.get(name) if raw1 is None else None
                primary = raw1 if raw1 is not None else raw2
                # Explicit None check: a real value of 0/False/"" is falsy but
                # must stay matchable (parity with JM json_extract_string).
                candidates.append(str(primary) if primary is not None else "")
                _dual = _FIELD_DUAL_SOURCE.get(name)
                if _dual is not None:
                    # Append the top-level column value alongside the event_data form
                    candidates.append(str(ev.get(_dual, "") or ""))
                if not self._adv_case_sensitive:
                    candidates = [c.lower() for c in candidates]
                cv = cond["value"]
                op = cond["operator"]
                # Set of hex/decimal variants for PID-like fields, or None if
                # this condition is on a regular field.  Pre-computed in
                # set_advanced_filter() so the hot path is O(1) set membership.
                _vset = cond.get("variants")

                # Helper: does ANY candidate satisfy the predicate?
                def _any_match(predicate) -> bool:
                    return any(predicate(c) for c in candidates)

                def _all_match(predicate) -> bool:
                    """For negative operators — must hold for ALL sources."""
                    return all(predicate(c) for c in candidates)

                if op == "contains":
                    if _vset is not None:
                        # Any candidate contains any variant
                        if not _any_match(lambda fv: any(v in fv for v in _vset)):
                            return False
                    elif not _any_match(lambda fv: cv in fv):
                        return False
                elif op == "equals":
                    if _vset is not None:
                        if not _any_match(lambda fv: fv in _vset):
                            return False
                    elif not _any_match(lambda fv: fv == cv):
                        return False
                elif op == "starts with":
                    if not _any_match(lambda fv: fv.startswith(cv)):
                        return False
                elif op == "ends with":
                    if not _any_match(lambda fv: fv.endswith(cv)):
                        return False
                elif op == "not contains":
                    # Negation must hold for ALL candidate sources
                    if _vset is not None:
                        if not _all_match(lambda fv: not any(v in fv for v in _vset)):
                            return False
                    elif not _all_match(lambda fv: cv not in fv):
                        return False
                elif op == "not equals":
                    if _vset is not None:
                        if not _all_match(lambda fv: fv not in _vset):
                            return False
                    elif not _all_match(lambda fv: fv != cv):
                        return False
                elif op == "regex":
                    pat = cond.get("compiled")
                    if pat and not _any_match(lambda fv: pat.search(fv) is not None):
                        return False
                elif op == "greater than":
                    def _gt(fv: str) -> bool:
                        try:
                            return float(fv) > float(cv)
                        except ValueError:
                            return False
                    if not _any_match(_gt):
                        return False
                elif op == "less than":
                    def _lt(fv: str) -> bool:
                        try:
                            return float(fv) < float(cv)
                        except ValueError:
                            return False
                    if not _any_match(_lt):
                        return False
                else:
                    # Unknown operator — fail CLOSED (drop the event), matching
                    # filters.py._conditions_pass and JM's filter_sql.  Falling
                    # through to `return True` here would silently pass every
                    # event on a typo'd operator — a silent divergence.
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

    def collect_source_events_for_popup(self, exclude_qf_key: str) -> list:
        """Return source event dicts that pass ALL active filters, with the
        quick filter for *exclude_qf_key* temporarily suspended.

        This gives cascade-accurate popup counts that respect advanced, text,
        session, AND quick filters — minus the current column's own quick filter
        so the popup still shows all of that column's possible values.

        Operates entirely on the calling thread (no invalidateFilter call) so
        the table does not flash.  The quick-exclude/include dicts are restored
        in a ``finally`` block even if an exception occurs mid-scan.

        Known limitation: for very large in-memory datasets (> 200 K events)
        this scan can cause a brief pause before the background worker starts
        counting.  Fixing it properly requires snapshotting all filter state
        and re-running the full filter logic in the worker thread — a separate
        architectural change outside the scope of this method.
        """
        src = self.sourceModel()
        if not isinstance(src, EventTableModel):
            return []

        # Temporarily suspend the target column's quick-filter sets so that
        # _filterAcceptsRow_impl treats those entries as absent.
        saved_excl = self._quick_excludes
        saved_incl = self._quick_includes
        self._quick_excludes = {k: v for k, v in saved_excl.items()
                                if k != exclude_qf_key}
        self._quick_includes = {k: v for k, v in saved_incl.items()
                                if k != exclude_qf_key}
        events: list = []
        mi = QModelIndex()
        try:
            for row in range(src.rowCount()):
                if self._filterAcceptsRow_impl(row, mi):
                    ev = src.get_event(row)
                    if ev is not None:
                        events.append(ev)
        finally:
            self._quick_excludes = saved_excl
            self._quick_includes = saved_incl
        return events

