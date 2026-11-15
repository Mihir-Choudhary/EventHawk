"""The same filter gives the same answer in the CLI, the Normal view and Juggernaut.

Gemini audit 3-10 (High), the parts that differ on a real filter:
- users: the CLI also matched event_data UserName; the Normal view and
  Juggernaut match user_id, Subject/TargetUserName and Subject/TargetUserSid;
- case_sensitive: the CLI lowercased computers, users, sources and channels
  regardless; the Normal view and Juggernaut honour it;
- text_search [""] with Exclude: Juggernaut kept the empty term and
  rejected every row (every text contains "").

Expected: for each filter below the CLI (compile_filter and passes_filter),
the Normal proxy and Juggernaut SQL accept the same rows.  Synthetic raw
records, put through the real Normal and Juggernaut extractors.
"""
import os
import sys
import shutil
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import duckdb
    import glob
    from evtx_tool.core.filters import compile_filter, passes_filter, empty_filter
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.core.engine import _extract_event_inline
    from evtx_tool.core.heavyweight import engine as H
    import pyarrow as pa
    import pyarrow.parquet as pq

    def raw(rid, eid, comp, data):
        return {"Event": {"System": {
            "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}}, "EventID": eid,
            "Level": 0, "TimeCreated": {"#attributes": {"SystemTime": f"2026-01-01T00:00:0{rid}.000000Z"}},
            "EventRecordID": rid, "Channel": "Security", "Computer": comp}, "EventData": data}}
    raws = [raw(1, 4648, "HOST-A", {"UserName": "svc_backup"}),
            raw(2, 4624, "HOST-A", {"TargetUserName": "svc_backup"}),
            raw(3, 4624, "host-b", {"TargetUserName": "x"})]
    ts = "2026-01-01T00:00:00.000000Z"
    evs = [_extract_event_inline(r, i + 1, ts, r"C:\c\Security.evtx") for i, r in enumerate(raws)]
    for e in evs:
        e["source_file"] = r"C:\c\Security.evtx"
    rows = [dict(zip(H._COL_NAMES, H._extract_and_filter(r, r"C:\c\Security.evtx", None, i + 1)))
            for i, r in enumerate(raws)]
    tmp = tempfile.mkdtemp(prefix="parity_")
    try:
        pq.write_table(pa.Table.from_pylist(rows, schema=H._make_schema()), os.path.join(tmp, "s0.parquet"))
        shards = [f.replace("\\", "/") for f in glob.glob(os.path.join(tmp, "*.parquet"))]
        con = duckdb.connect()
        con.execute(f"create view ev as select * from read_parquet({shards})")
        src = EventTableModel()
        src.set_events(list(evs))
        px = EventFilterProxyModel()
        px.setSourceModel(src)
        cases = [
            ("users=svc_backup", {"users": ["svc_backup"]}),
            ("computers=HOST-A, case-sensitive", {"computers": ["HOST-A"], "case_sensitive": True}),
            ("computers=host-a, case-sensitive", {"computers": ["host-a"], "case_sensitive": True}),
            ("users=SVC_BACKUP, case-sensitive", {"users": ["SVC_BACKUP"], "case_sensitive": True}),
        ]
        for label, over in cases:
            fc = empty_filter()
            fc.update(over)
            cli = [e["record_id"] for e in evs if compile_filter(fc)(e)]
            cli2 = [e["record_id"] for e in evs if passes_filter(e, fc)]
            px.set_advanced_filter(dict(fc))
            gui = sorted(src.get_event(px.mapToSource(px.index(r, 0)).row())["record_id"] for r in range(px.rowCount()))
            where, params = filter_config_to_sql(fc)
            jm = sorted(r[0] for r in con.execute(f"select record_id from ev where {where}", params).fetchall())
            check(f"{label}: CLI, Normal view and Juggernaut agree", sorted(cli) == sorted(cli2) == gui == jm,
                  f"cli {cli} / {cli2}, gui {gui}, jm {jm}")
        from evtx_tool.core.heavyweight.filter_sql import text_config_to_parquet_sql
        sql, prm = text_config_to_parquet_sql({"text_search": [""], "text_exclude": True})
        check("an empty search term is dropped (does not exclude every row)", "" not in prm and sql == "1=1",
              f"{sql[:60]} {prm}")
        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
