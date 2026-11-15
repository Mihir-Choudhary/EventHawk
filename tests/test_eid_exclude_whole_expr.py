"""Event IDs "Exclude" inverts the whole expression, ! exclusions included.

Gemini audit 3-13 (High): with Exclude ticked, all three engines negated
only the include part of an expression and still applied its "!" part as
written.  "4624-4626!4625" with Exclude (everything except 4624 and 4626)
still hid 4625; "!4625" with Exclude (only 4625) ignored Exclude entirely.

Expected: for each expression, the CLI (passes_filter and compile_filter),
the Normal view and Juggernaut SQL accept exactly the IDs the expression
selects, or with Exclude exactly the others.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import duckdb
    from evtx_tool.core.filters import compile_filter, passes_filter, empty_filter
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    ids = [4623, 4624, 4625, 4626, 4627]
    evs = [{"record_id": i + 1, "event_id": e, "level": 0, "level_name": "Information", "channel": "Security",
            "computer": "H", "provider": "P", "timestamp": f"2026-01-01T00:00:0{i}.000000Z", "event_data": {},
            "source_file": "f.evtx", "user_id": "", "keywords": "0x0"} for i, e in enumerate(ids)]
    con = duckdb.connect()
    con.execute("create table t(event_id int)")
    con.executemany("insert into t values (?)", [[e] for e in ids])
    src = EventTableModel()
    src.set_events([dict(e) for e in evs])
    px = EventFilterProxyModel()
    px.setSourceModel(src)
    for expr, sel in (("4624-4626!4625", {4624, 4626}), ("!4625", {4623, 4624, 4626, 4627}),
                      ("4624,4626", {4624, 4626})):
        for excl in (False, True):
            want = sorted(set(ids) - sel) if excl else sorted(sel)
            fc = empty_filter()
            fc.update(event_id_expr=expr, event_id_exclude=excl)
            a = sorted(e["event_id"] for e in evs if passes_filter(e, fc))
            b = sorted(e["event_id"] for e in evs if compile_filter(fc)(e))
            px.set_advanced_filter(dict(fc))
            g = sorted(src.get_event(px.mapToSource(px.index(r, 0)).row())["event_id"] for r in range(px.rowCount()))
            where, params = filter_config_to_sql(fc)
            j = sorted(r[0] for r in con.execute(f"select event_id from t where {where}", params).fetchall())
            check(f"{expr!r} exclude={excl}: every engine gives {want}", a == b == g == j == want,
                  f"passes {a}, compile {b}, gui {g}, jm {j}")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
