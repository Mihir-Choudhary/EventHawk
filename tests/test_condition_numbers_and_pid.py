"""Field conditions: hex numbers compare as numbers; ProcessId means the event's process.

Gemini audit 3-16 (High): "NewProcessId greater than 100" on NewProcessId
"0x1bc" (444) was False in every engine (float("0x1bc") fails; DuckDB's
TRY_CAST to DOUBLE gives NULL).  The dialog accepted "nan" / "inf".
Gemini audit 3-17 (High): a ProcessId condition also matched the LOGGING
service's System ProcessID, so "ProcessId equals 888" matched every Sysmon
event logged by the Sysmon service (pid 888) whatever process it was about,
and "not equals 888" hid them; a System ProcessID of 0 read as "" in Python
but "0" in Juggernaut.

Expected (CLI passes_filter and compile_filter, Normal view, Juggernaut SQL
all agree):
- NewProcessId "0x1bc" > 100 and < 1000; not > 1000;
- ProcessId = 444 matches the event whose EventData.ProcessId is 444 although
  its System ProcessID is 888; ProcessId = 888 does not match it;
- ProcessId = 0 matches an event with no EventData.ProcessId and System
  ProcessID 0;
- the dialog refuses "nan" and "inf" as a number.
Synthetic raw records through the real Normal and Juggernaut extractors.
"""
import glob
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import duckdb
    import pyarrow as pa
    import pyarrow.parquet as pq
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.core.engine import _extract_event_inline
    from evtx_tool.core.heavyweight import engine as H
    from evtx_tool.core.filters import compile_filter, passes_filter, empty_filter
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

    def raw(rid, eid, sys_pid, data):
        return {"Event": {"System": {
            "Provider": {"#attributes": {"Name": "P"}}, "EventID": eid, "Level": 4,
            "TimeCreated": {"#attributes": {"SystemTime": f"2026-01-01T00:00:0{rid}.000000Z"}},
            "EventRecordID": rid, "Channel": "C", "Computer": "H",
            "Execution": {"#attributes": {"ProcessID": sys_pid, "ThreadID": 1}}}, "EventData": data}}
    raws = [raw(1, 4688, 4, {"NewProcessId": "0x1bc"}),
            raw(2, 1, 888, {"ProcessId": "444", "Image": "x.exe"}),
            raw(3, 7036, 0, {"param1": "svc"})]
    sf = r"C:\c\a.evtx"
    ts = "2026-01-01T00:00:00.000000Z"
    evs = [_extract_event_inline(r, i + 1, ts, sf) for i, r in enumerate(raws)]
    for e in evs:
        e["source_file"] = sf
    rows = [dict(zip(H._COL_NAMES, H._extract_and_filter(r, sf, None, i + 1))) for i, r in enumerate(raws)]
    tmp = tempfile.mkdtemp(prefix="cnum_")
    try:
        pq.write_table(pa.Table.from_pylist(rows, schema=H._make_schema()), os.path.join(tmp, "s0.parquet"))
        shards = [f.replace("\\", "/") for f in glob.glob(os.path.join(tmp, "*.parquet"))]
        con = duckdb.connect()
        con.execute(f"create view ev as select * from read_parquet({shards})")
        src = EventTableModel()
        src.set_events(list(evs))
        px = EventFilterProxyModel()
        px.setSourceModel(src)
        cases = [("NewProcessId > 100", "NewProcessId", "greater than", "100", [1]),
                 ("NewProcessId < 1000", "NewProcessId", "less than", "1000", [1]),
                 ("NewProcessId > 1000", "NewProcessId", "greater than", "1000", []),
                 ("ProcessId = 444", "ProcessId", "equals", "444", [2]),
                 ("ProcessId = 888", "ProcessId", "equals", "888", []),
                 ("ProcessId = 0", "ProcessId", "equals", "0", [3])]
        for label, name, op, val, want in cases:
            fc = empty_filter()
            fc["conditions"] = [{"name": name, "operator": op, "value": val}]
            a = [e["record_id"] for e in evs if passes_filter(e, fc)]
            b = [e["record_id"] for e in evs if compile_filter(fc)(e)]
            px.set_advanced_filter(dict(fc))
            g = sorted(src.get_event(px.mapToSource(px.index(r, 0)).row())["record_id"] for r in range(px.rowCount()))
            where, params = filter_config_to_sql(fc)
            j = sorted(r[0] for r in con.execute(f"select record_id from ev where {where}", params).fetchall())
            check(f"{label}: every engine gives {want}", a == b == g == j == want,
                  f"passes {a}, compile {b}, gui {g}, jm {j}")
        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    from evtx_tool.gui.filter_dialog import FilterDialog
    for bad in ("nan", "inf"):
        dlg = FilterDialog({}, current_filter={"conditions": [{"name": "X", "operator": "greater than", "value": bad}]})
        errs = [e for e in dlg._validate_inputs() if "not a number" in e]
        check(f"the dialog refuses {bad!r} as a number", errs, str(dlg._validate_inputs())[:120])
        dlg.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
