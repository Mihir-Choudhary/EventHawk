"""
Custom columns (Event Log Explorer style): a value template evaluated per event.

A template is literal text plus tokens:

    {EventID}  {TimeCreated[SystemTime]}  {Provider[Name]}  {Execution[ProcessID]} ...
                                     System fields, attribute in brackets
    {Data[LogonType]}                EventData / UserData field by name (nested-aware)
    {Data[3]}                        the 3rd <Data> element (counting from 1)
    {UserData[Name]}                 same lookup as {Data[Name]}
    {{  }}                           literal braces (a backslash is just a backslash,
                                     so "{Data[TargetDomainName]}\\{Data[TargetUserName]}"
                                     reads DOMAIN\\user)

EventHawk keeps the values of the event, not its XML text.  A System field it
does not keep is refused when the column is defined ("EventHawk does not keep
<name>"), so an empty column can never be mistaken for "the log has no value";
a kept field that one event simply lacks gives that event an empty value.

One evaluator for both modes: Normal mode runs it over the events in memory,
Juggernaut over rows streamed from the Parquet shards, on the same event-dict
shape, so a column shows the same values in both.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field

from evtx_tool.core.filters import flatten_fields, parse_event_id_expression


class CustomColumnError(ValueError):
    """The column definition cannot be used; the message says why."""


@dataclass
class CustomColumnSpec:
    col_id: int
    title: str
    template: str
    eid_expr: str = ""
    providers: tuple = ()
    kind: str = "text"          # "text" | "int"


# Token (as written, lower-cased) -> event-dict key EventHawk keeps.
SYSTEM_TOKENS: dict[str, str] = {
    "eventid": "event_id",
    "eventid[qualifiers]": "qualifiers",
    "version": "version",
    "level": "level",
    "task": "task",
    "opcode": "opcode",
    "keywords": "keywords",
    "timecreated[systemtime]": "timestamp",
    "eventrecordid": "record_id",
    "correlation[activityid]": "correlation_id",
    "execution[processid]": "process_id",
    "execution[threadid]": "thread_id",
    "channel": "channel",
    "computer": "computer",
    "security[userid]": "user_id",
    "provider[name]": "provider",
    "provider[guid]": "provider_guid",
    "provider[eventsourcename]": "event_source_name",
}
# Canonical spelling of each System token, in the order the field picker lists them.
SYSTEM_TOKEN_NAMES: tuple = (
    "EventID", "TimeCreated[SystemTime]", "EventRecordID", "Provider[Name]", "Provider[Guid]",
    "Provider[EventSourceName]", "Channel", "Computer", "Security[UserID]", "Level", "Task",
    "Opcode", "Keywords", "Version", "EventID[Qualifiers]", "Correlation[ActivityID]",
    "Execution[ProcessID]", "Execution[ThreadID]",
)
# System elements of the event XML: a token naming one of these that is not in
# SYSTEM_TOKENS names something EventHawk does not keep.
_SYSTEM_ELEMENTS = {"provider", "eventid", "version", "level", "task", "opcode", "keywords",
                    "timecreated", "eventrecordid", "correlation", "execution", "channel",
                    "computer", "security", "system"}
_DATA_NAMES = {"data", "userdata", "eventdata"}
_TOKEN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)(?:\[([^\]]*)\])?$")


def _render(v) -> str:
    """A field value as cell text (lists one per item, containers as JSON)."""
    if v is None:
        return ""
    if isinstance(v, list):
        return ", ".join(_render(x) for x in v)
    if isinstance(v, dict):
        if "#text" in v:
            return _render(v["#text"])
        return json.dumps(v, separators=(",", ":"), ensure_ascii=False, default=str)
    return str(v)


def data_items(event_data) -> list:
    """The <Data> elements of *event_data* in document order, as (name, value).

    Unnamed <Data> elements have no name.  For UserData (nested elements, no
    <Data>) these are its leaf fields, in order.
    """
    if not isinstance(event_data, dict):
        return []
    if "Data" in event_data:
        v = event_data["Data"]
        if isinstance(v, dict) and "#text" in v:
            v = v["#text"]
        if isinstance(v, list):
            out = []
            for item in v:
                if isinstance(item, dict):
                    nm = (item.get("#attributes") or {}).get("Name")
                    out.append((str(nm) if nm else None, item.get("#text", "")))
                else:
                    out.append((None, item))
            return out
        if not isinstance(v, dict):
            return [(None, v)]
    return [(k, v) for k, v in flatten_fields(event_data).items() if k != "Binary"]


@dataclass
class _Part:
    literal: str = ""
    token: str = ""             # as written, e.g. "{Data[LogonType]}"
    key: str = ""               # System: event-dict key
    data_name: str = ""         # Data by name
    data_index: int = 0         # Data by position (1-based)


@dataclass
class CompiledColumn:
    spec: CustomColumnSpec
    parts: list
    eid_include: frozenset
    eid_exclude: frozenset
    providers: frozenset
    hits: Counter = field(default_factory=Counter)

    @property
    def tokens(self) -> list:
        return [p.token for p in self.parts if p.token]

    def applies(self, ev: dict) -> bool:
        """True when the event passes the column's Event ID / Provider filter."""
        if self.eid_include or self.eid_exclude:
            try:
                eid = int(ev.get("event_id"))
            except (TypeError, ValueError):
                return False
            if self.eid_include and eid not in self.eid_include:
                return False
            if eid in self.eid_exclude:
                return False
        if self.providers and str(ev.get("provider") or "").lower() not in self.providers:
            return False
        return True

    def value(self, ev: dict) -> str:
        """The column's value for *ev*: "" outside its filter or when the event
        has none of the fields the template names."""
        if not self.applies(ev):
            return ""
        out: list[str] = []
        found = False
        items = None
        flat = None          # the EventData itself when it is a plain {name: value} map
        for p in self.parts:
            if not p.token:
                out.append(p.literal)
                continue
            v = None
            if p.key:
                v = ev.get(p.key)
                if v == "":
                    v = None
            else:
                ed = ev.get("event_data")
                if not p.data_index and flat is None:
                    # Most EventData is already flat: then a name lookup is a
                    # dict lookup (flattening it would give the same pairs).
                    flat = (ed if isinstance(ed, dict) and "Data" not in ed and not any(
                        isinstance(x, (dict, list)) or (isinstance(k, str) and k[:1] in "#@")
                        for k, x in ed.items()) else False)
                if not p.data_index and flat is not False:
                    v = flat.get(p.data_name)
                else:
                    if items is None:
                        items = data_items(ed)
                    if p.data_index:
                        if p.data_index <= len(items):
                            v = items[p.data_index - 1][1]
                    else:
                        for nm, iv in items:
                            if nm == p.data_name:
                                v = iv
                                break
                        else:
                            if isinstance(ed, dict):
                                v = flatten_fields(ed).get(p.data_name)
            if v is not None:
                found = True
                self.hits[p.token] += 1
                out.append(_render(v))
        return "".join(out) if found else ""


def compile_spec(spec: CustomColumnSpec) -> CompiledColumn:
    """Parse *spec*; raises CustomColumnError with a message for the user."""
    t = spec.template or ""
    parts: list[_Part] = []
    lit: list[str] = []
    i = 0
    while i < len(t):
        ch = t[i]
        if ch == "{" and t.startswith("{{", i):
            lit.append("{"); i += 2; continue
        if ch == "}" and t.startswith("}}", i):
            lit.append("}"); i += 2; continue
        if ch == "}":
            raise CustomColumnError(f"Unmatched closing brace at position {i + 1}; write }}}} for a literal brace.")
        if ch != "{":
            lit.append(ch); i += 1; continue
        end = t.find("}", i + 1)
        if end < 0:
            raise CustomColumnError(f"Unclosed brace at position {i + 1}: every {{ needs a }}.")
        inner = t[i + 1:end].strip()
        token = "{" + inner + "}"
        if lit:
            parts.append(_Part(literal="".join(lit))); lit = []
        parts.append(_compile_token(inner, token))
        i = end + 1
    if lit:
        parts.append(_Part(literal="".join(lit)))
    if not any(p.token for p in parts):
        raise CustomColumnError("The value names no field: use tokens such as {EventID} or {Data[LogonType]}.")
    inc, exc = parse_event_id_expression(spec.eid_expr or "")
    provs = frozenset(str(p).strip().lower() for p in (spec.providers or ()) if str(p).strip())
    if spec.kind not in ("text", "int"):
        raise CustomColumnError(f"Unknown type {spec.kind!r}: use text or int.")
    return CompiledColumn(spec=spec, parts=parts, eid_include=frozenset(inc),
                          eid_exclude=frozenset(exc), providers=provs)


def _compile_token(inner: str, token: str) -> _Part:
    m = _TOKEN_RE.match(inner)
    if not m:
        raise CustomColumnError(f"{token} is not a field: write {{Name}} or {{Name[Attribute]}}.")
    name, arg = m.group(1), m.group(2)
    low = name.lower()
    if low in _DATA_NAMES:
        if arg is None or not arg.strip():
            raise CustomColumnError(f"{token}: name the field, e.g. {{Data[LogonType]}} or {{Data[3]}}.")
        arg = arg.strip()
        if arg.isdigit():
            n = int(arg)
            if n < 1:
                raise CustomColumnError(f"{token}: <Data> positions count from 1.")
            return _Part(token=token, data_index=n)
        return _Part(token=token, data_name=arg)
    key = low if arg is None else f"{low}[{arg.strip().lower()}]"
    if key in SYSTEM_TOKENS:
        return _Part(token=token, key=SYSTEM_TOKENS[key])
    if low in _SYSTEM_ELEMENTS:
        kept = ", ".join("{" + n + "}" for n in SYSTEM_TOKEN_NAMES if n.lower().startswith(low))
        raise CustomColumnError(
            f"EventHawk does not keep {inner}." + (f" It keeps {kept}." if kept else ""))
    raise CustomColumnError(
        f"{token} is not a System field. For an EventData or UserData field write {{Data[{name}]}}.")


def int_sort_key(value: str) -> tuple:
    """Sort key for an Integer column: decimal and 0x hex by value, other text
    after the numbers (as found, never coerced), empty values last."""
    s = (value or "").strip()
    if not s:
        return (2, "")
    try:
        return (0, int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s))
    except ValueError:
        return (1, s.lower())


def field_catalog(ev: dict) -> list:
    """(token, label, value) for every field of *ev*: System fields first, then
    each <Data> element by name (with its 1-based position) or by position."""
    out: list = []
    for name in SYSTEM_TOKEN_NAMES:
        v = ev.get(SYSTEM_TOKENS[name.lower()])
        if v is None or v == "":
            continue
        out.append(("{" + name + "}", name, _render(v)))
    for i, (nm, v) in enumerate(data_items(ev.get("event_data")), 1):
        if nm:
            out.append(("{Data[" + nm + "]}", f"{nm}  (#{i})", _render(v)))
        else:
            out.append(("{Data[" + str(i) + "]}", f"Data #{i}", _render(v)))
    return out


# ── Juggernaut: the same evaluator over the Parquet shards ─────────────────────

# Event-dict key -> Parquet column, for the keys a template can name.
_PARQUET_COLS: dict[str, str] = {
    "event_id": "event_id", "qualifiers": "qualifiers", "version": "version", "level": "level",
    "task": "task", "opcode": "opcode", "keywords": "keywords", "timestamp": "timestamp_utc",
    "record_id": "record_id", "correlation_id": "correlation_id", "process_id": "process_id",
    "thread_id": "thread_id", "channel": "channel", "computer": "computer", "user_id": "user_id",
    "provider": "provider", "provider_guid": "provider_guid", "event_source_name": "event_source_name",
}


def sort_key_text(value: str, kind: str) -> str:
    """A string whose plain ordering is the column's order (int_sort_key for an
    Integer column; case-insensitive text with empty values last otherwise), so
    Juggernaut can sort a custom column with ORDER BY exactly as Normal does."""
    if kind == "int":
        k = int_sort_key(value)
        if k[0] == 0:
            return "0" + format(k[1] + 2 ** 64, "021d")
        return "1" + k[1] if k[0] == 1 else "2"
    return "0" + value.lower() if value else "1"


def arrow_column_values(compiled: CompiledColumn, table, shard_paths: list,
                        batch: int = 65536, cancel=None, mask=None) -> "list[str] | None":
    """The column's value for every row of the Arrow *table*, in row order.

    Juggernaut keeps EventData only in the Parquet shards, so each row is
    matched to its shard row by (source_file, record_id) and rebuilt as the
    same event dict Normal mode evaluates (timestamp in Normal's ISO form,
    event_data parsed from event_data_json), then evaluated by the same code.
    *mask* (one bool per row) limits the evaluation to the rows a tab shows:
    a per-file tab shares the whole table, and counting other files' rows made
    the "no event in this tab has this field" warning miss (audit-5 E5-11).
    Rows outside the mask get "".  Returns None if *cancel()* turns true.
    """
    import duckdb
    import pyarrow as pa
    try:
        import orjson
        _loads = orjson.loads
    except ImportError:                                  # pragma: no cover
        _loads = json.loads
    n = len(table)
    need = {p.key for p in compiled.parts if p.key}
    want_ed = any(p.token and not p.key for p in compiled.parts)
    if compiled.eid_include or compiled.eid_exclude:
        need.add("event_id")
    if compiled.providers:
        need.add("provider")
    keys = [k for k in _PARQUET_COLS if k in need]
    con = duckdb.connect()
    try:
        con.register("t", pa.table({
            "__row": pa.array(range(n), pa.int64()),
            "source_file": table["source_file"], "record_id": table["record_id"]}))
        have = {r[0] for r in con.execute(
            "DESCRIBE SELECT * FROM read_parquet(?, union_by_name=true)", [shard_paths]).fetchall()}
        inner = [f"{_PARQUET_COLS[k]}" if _PARQUET_COLS[k] in have else f"NULL AS {_PARQUET_COLS[k]}"
                 for k in keys]
        if want_ed:
            inner.append("event_data_json")
        sel = ", ".join(["t.__row"] + [f"s.{_PARQUET_COLS[k]}" for k in keys]
                        + (["s.event_data_json"] if want_ed else []))
        def _query(distinct: bool) -> str:
            return (f"SELECT {sel} FROM t LEFT JOIN ("
                    f"SELECT {'DISTINCT ON (source_file, record_id) ' if distinct else ''}"
                    f"source_file, record_id{''.join(', ' + c for c in inner)} "
                    f"FROM read_parquet(?, union_by_name=true)"
                    f") s USING (source_file, record_id) ORDER BY t.__row")
        # One shard row per (source_file, record_id) is the normal case; if a
        # key repeats, the join would yield extra rows and misalign every value
        # after it, so then the shard side is de-duplicated first.
        dup = con.execute("SELECT count(*) - count(DISTINCT (source_file, record_id)) "
                          "FROM read_parquet(?, union_by_name=true)", [shard_paths]).fetchone()[0]
        cur = con.execute(_query(bool(dup)), [shard_paths])
        out: list[str] = []
        value = compiled.value
        ts_i = keys.index("timestamp") + 1 if "timestamp" in keys else -1
        while True:
            if cancel is not None and cancel():
                return None
            rows = cur.fetchmany(batch)
            if not rows:
                break
            for row in rows:
                if mask is not None and not mask[row[0]]:
                    out.append("")
                    continue
                ev = {k: row[i + 1] for i, k in enumerate(keys)}
                if ts_i > 0 and row[ts_i]:
                    # Juggernaut stores "YYYY-MM-DD HH:MM:SS.ffffff"; Normal keeps
                    # the raw "YYYY-MM-DDTHH:MM:SS.ffffffZ".
                    ev["timestamp"] = str(row[ts_i]).replace(" ", "T") + "Z"
                if want_ed:
                    raw = row[-1]
                    if raw and compiled.applies(ev):
                        try:
                            ev["event_data"] = _loads(raw)
                        except Exception:
                            ev["event_data"] = {}
                out.append(value(ev))
        return out
    finally:
        con.close()


# ── Exports ─────────────────────────────────────────────────────────────────

def export_titles(columns: list) -> list:
    """The columns' titles for an export, made unique ("Logon", "Logon (2)")
    so that two columns with one title cannot overwrite each other."""
    out: list[str] = []
    for c in columns:
        t = c.spec.title or f"Column {c.spec.col_id}"
        base, n = t, 2
        while t in out:
            t = f"{base} ({n})"
            n += 1
        out.append(t)
    return out


def with_custom_columns(events, columns: list) -> list:
    """Shallow copies of *events* carrying ``custom_columns: {title: value}``
    (the exporters write it as columns / fields); *events* are not changed.
    A Juggernaut timestamp ("YYYY-MM-DD HH:MM:SS...") is read in Normal mode's
    ISO form for the evaluation, so both modes export the same values."""
    titles = export_titles(columns)
    out = []
    for ev in events:
        src = ev
        ts = ev.get("timestamp")
        if isinstance(ts, str) and ts and "T" not in ts:
            src = dict(ev, timestamp=ts.replace(" ", "T") + "Z")
        out.append(dict(ev, custom_columns={t: c.value(src) for t, c in zip(titles, columns)}))
    return out
