"""Two "equals" conditions on the same field mean either value.

Reported by the user (2026-11-01): in the Advanced Filter, "LogonType equals 4"
plus a second row "LogonType equals 10" did not show the type-10 logons.  Every
condition was ANDed, so two equals on one field asked for an event whose
LogonType is 4 AND 10 at once: reproduced through the real dialog widgets on
main (8c5b28a) and beta (9845d67), Normal mode, synthetic events
(5 x type 4, 3 x type 10, 2 x type 3): 0 shown, 8 expected.  Juggernaut's SQL and
the parse-time filter AND them the same way.

Expected: equals rows on the same field are alternatives (OR), as in Event
Viewer.  Every other operator still ANDs, because there AND means something:
two "contains" narrow, "greater than" + "less than" is a range, two
"not equals" exclude both values; conditions on different fields AND.
All three evaluators (Normal view, Juggernaut SQL, parse-time/CLI) must agree.
Synthetic data only.
"""
import json
import os
import sys
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


# (LogonType, SubjectUserName, ProcessId as Windows writes it: hex)
ROWS = ([("4", "alice", "0x10")] * 3 + [("4", "bob", "0x20")] * 2 + [("10", "alice", "0x30")] * 3
        + [("3", "carol", "0x40")] * 2)


def cond(name, op, value):
    return {"name": name, "operator": op, "value": value}


# label, conditions, expected count (written from the rows above, by hand)
CASES = [
    ("LogonType equals 4 + equals 10 (the report)",
     [cond("LogonType", "equals", "4"), cond("LogonType", "equals", "10")], 8),
    ("three equals on one field", [cond("LogonType", "equals", v) for v in ("4", "10", "3")], 10),
    ("equals 4 + equals 10, then a different field ANDs",
     [cond("LogonType", "equals", "4"), cond("LogonType", "equals", "10"),
      cond("SubjectUserName", "equals", "alice")], 6),
    ("one equals still filters", [cond("LogonType", "equals", "10")], 3),
    ("equals on two DIFFERENT fields still ANDs",
     [cond("LogonType", "equals", "4"), cond("SubjectUserName", "equals", "alice")], 3),
    ("two contains on one field still AND (narrowing)",
     [cond("SubjectUserName", "contains", "a"), cond("SubjectUserName", "contains", "i")], 6),
    ("greater than + less than on one field is a range",
     [cond("LogonType", "greater than", "3"), cond("LogonType", "less than", "10")], 5),
    ("not equals 4 + not equals 10 excludes both",
     [cond("LogonType", "not equals", "4"), cond("LogonType", "not equals", "10")], 2),
    ("equals 4 + equals 10 + not equals 10 on one field",
     [cond("LogonType", "equals", "4"), cond("LogonType", "equals", "10"),
      cond("LogonType", "not equals", "10")], 5),
    ("hex-stored ProcessId: equals decimal 16 + equals decimal 48",
     [cond("ProcessId", "equals", "16"), cond("ProcessId", "equals", "48")], 6),
]


def events():
    out = []
    for i, (lt, user, pid) in enumerate(ROWS):
        e = T.ev(r"C:\s\Security.evtx", i + 1, "HOST-A", T.T0 + timedelta(seconds=i), 4624)
        e["event_data"] = {"LogonType": lt, "SubjectUserName": user, "ProcessId": pid}
        out.append(e)
    return out


def main() -> int:
    import duckdb
    from evtx_tool.core.filters import _conditions_pass
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    import evtx_tool.gui.main_window as mw

    evs = events()
    con = duckdb.connect()
    con.execute("CREATE TABLE t (ed_flat_json VARCHAR, process_id BIGINT, thread_id BIGINT)")
    con.executemany("INSERT INTO t VALUES (?, NULL, NULL)", [[json.dumps(e["event_data"])] for e in evs])

    w = mw.MainWindow()
    T.Mode(mw, False).load(w, evs)
    T.pump(200)
    for label, conds, want in CASES:
        core = sum(1 for e in evs if _conditions_pass(e, conds, False))
        where, params = filter_config_to_sql({"conditions": conds})
        jm = con.execute(f"SELECT count(*) FROM t WHERE {where}", params).fetchone()[0]
        w._proxy_model.set_advanced_filter({"conditions": conds})
        T.pump(50)
        normal = w._proxy_model.rowCount()
        check(label, core == jm == normal == want,
              f"expected {want}; Normal {normal}, Juggernaut SQL {jm}, parse-time {core}")
    w.close()
    T.pump(100)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
