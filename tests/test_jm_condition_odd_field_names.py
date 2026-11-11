"""Juggernaut conditions on field names with unusual characters (audit SA-7).

A condition whose field name held a double quote or a backslash was skipped
in Juggernaut mode with only a log line, so the view showed every event
instead of the matching ones; Normal mode applied it.  A name holding a dot
was read as a path into nested data.  Expected: for every field name the
Juggernaut SQL selects the same events as the parse-time evaluator Normal
mode uses.  Synthetic data only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []

NAMES = ['a"b', "c\\d", "e/f", "g~h", "x.y", "sp ace", "q'q", "naïve", "0", "with-dash", "Plain",
         '"', "\\", "/", "~1", "a~0b/c\"d\\e"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import duckdb
    from evtx_tool.core.filters import _conditions_pass
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql

    evs = [{"event_id": 1, "event_data": {n: f"v{i}", "Common": "c"}} for i, n in enumerate(NAMES)]
    con = duckdb.connect()
    con.execute("CREATE TABLE t (i INTEGER, ed_flat_json VARCHAR, process_id BIGINT, thread_id BIGINT)")
    con.executemany("INSERT INTO t VALUES (?, ?, NULL, NULL)",
                    [[i, json.dumps(e["event_data"])] for i, e in enumerate(evs)])
    for i, name in enumerate(NAMES):
        for op, val in (("equals", f"v{i}"), ("contains", "v"), ("not equals", f"v{i}")):
            conds = [{"name": name, "operator": op, "value": val}]
            core = {k for k, e in enumerate(evs) if _conditions_pass(e, conds, False)}
            try:
                where, params = filter_config_to_sql({"conditions": conds})
                jm = {r[0] for r in con.execute(f"SELECT i FROM t WHERE {where}", params).fetchall()}
                err = ""
            except Exception as exc:
                jm, err = None, f"{type(exc).__name__}: {exc}"
            ok = jm == core and (op == "not equals" or core == {i})
            check(f"field {name!r} {op}", ok,
                  err or f"Juggernaut {len(jm)} event(s), parse-time {len(core)}, of {len(evs)}")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
