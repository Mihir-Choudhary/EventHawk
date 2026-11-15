"""A profile's computers, users and levels are applied, not silently dropped.

Gemini audit 11-01 (Critical): build_combined_filter merged a profile's
computers / users / levels with dict.setdefault, but empty_filter() already
holds those keys as None (and the Filter dialog's config as []), so setdefault
did nothing: a profile "4624 on SYNTH-DC-01 by synth_admin, level Error" also
matched 4624 events from every other host, user and level -- in the CLI, in
Normal mode and in Juggernaut SQL.

Expected: the profile's restrictions apply when the base filter does not set its
own (None or []), in all three engines; a base filter's own value is kept.
Synthetic data only.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, computer, user, level):
    names = {0: "Information", 2: "Error", 4: "Information"}
    return {"record_id": rid, "event_id": 4624, "timestamp": "2026-01-01T00:00:00.000000Z", "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing", "computer": computer, "user_id": user,
            "level": level, "level_name": names[level], "keywords": "0x8020000000000000",
            "event_data": {"TargetUserName": user}, "source_file": "a.evtx", "task": 0}


EVS = [ev(1, "SYNTH-DC-01", "synth_admin", 2),   # matches the profile
       ev(2, "OTHER-WS", "synth_admin", 2),      # wrong host
       ev(3, "SYNTH-DC-01", "guest", 2),         # wrong user
       ev(4, "SYNTH-DC-01", "synth_admin", 4)]   # wrong level


def main() -> int:
    import duckdb
    from evtx_tool.core import filters
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.profiles.manager import ProfileManager

    con = duckdb.connect()
    con.execute("CREATE TABLE t (record_id INTEGER, event_id INTEGER, computer VARCHAR, user_id VARCHAR, "
                "level INTEGER, level_name VARCHAR, channel VARCHAR, provider VARCHAR, keywords VARCHAR, "
                "ed_flat_json VARCHAR, process_id BIGINT, thread_id BIGINT, task INTEGER, timestamp_utc VARCHAR, "
                "ed_subject_user VARCHAR, ed_target_user VARCHAR, ed_subject_sid VARCHAR, ed_target_sid VARCHAR)")
    con.executemany("INSERT INTO t VALUES (?, 4624, ?, ?, ?, ?, 'Security', 'Microsoft-Windows-Security-Auditing', "
                    "'0x8020000000000000', '{}', NULL, NULL, 0, '2026-01-01 00:00:00', NULL, ?, NULL, NULL)",
                    [[e["record_id"], e["computer"], e["user_id"], e["level"], e["level_name"], e["user_id"]] for e in EVS])

    def core(fc):
        return sorted(e["record_id"] for e in EVS if filters.passes_filter(e, fc))

    def jm(fc):
        where, params = filter_config_to_sql(fc)
        return sorted(r[0] for r in con.execute(f"SELECT record_id FROM t WHERE {where}", params).fetchall())

    def normal(fc):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
        QApplication.instance() or QApplication([])
        m = EventTableModel()
        m.set_events([dict(e) for e in EVS])
        p = EventFilterProxyModel()
        p.setSourceModel(m)
        p.set_advanced_filter(fc)
        return sorted(m.get_event(p.mapToSource(p.index(r, 0)).row())["record_id"] for r in range(p.rowCount()))

    d = tempfile.mkdtemp(prefix="eh_prof_")
    pm = ProfileManager(user_dir=d)
    prof = {"name": "StrictAdmin", "event_ids": [4624], "computers": ["SYNTH-DC-01"],
            "users": ["synth_admin"], "levels": ["Error"]}
    pm.create(prof)
    fc = pm.build_filter(["StrictAdmin"])
    for eng, fn in (("parse-time / CLI", core), ("Juggernaut SQL", jm), ("Normal mode", normal)):
        got = fn(fc)
        check(f"{eng}: the profile selects only the event on its host, by its user, at its level", got == [1],
              f"selected {got}; computers={fc.get('computers')} users={fc.get('users')} levels={fc.get('levels')}")

    # A base filter from the Filter dialog carries [] for unset fields
    base = filters.empty_filter()
    base.update({"computers": [], "users": [], "levels": []})
    fc2 = filters.build_combined_filter(base, [prof])
    check("with a dialog base ([] fields) the profile's restrictions still apply", core(fc2) == [1], str(core(fc2)))
    # A base filter's own value wins
    base3 = filters.empty_filter()
    base3["computers"] = ["OTHER-WS"]
    fc3 = filters.build_combined_filter(base3, [prof])
    check("a base filter's own computers are kept", fc3.get("computers") == ["OTHER-WS"], str(fc3.get("computers")))

    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
