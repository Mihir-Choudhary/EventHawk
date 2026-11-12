"""Level 0 reads "Information", as in Windows Event Viewer (the user, 2026-11-12).

Level 0 (the level of every Security audit event and most classic events) was
named "LogAlways" everywhere; Event Viewer shows it as "Information".  The user
chose: "Information" everywhere, and ONE Information box in the Filter dialog
that matches level 0 and level 4 together.

Expected:
- every place that names a level calls level 0 "Information"; the level NUMBER
  is unchanged, so 0 and 4 can still be told apart (CSV, JSON and XML carry it);
- the level name "Information" in a filter selects level 0 and level 4, in
  Normal mode, in Juggernaut SQL and at parse time / on the command line;
- a filter saved earlier with "LogAlways" still means level 0 only, and a level
  NUMBER still means exactly that level;
- the Filter dialog has no LogAlways box; a loaded "level 0 only" filter is
  kept (shown as a restriction with no field), not widened and not dropped;
- a condition "level equals 0" selects level 0 alone.
Synthetic events only.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


LEVELS = [0, 0, 0, 4, 4, 2, 3, 5, 1]


def main() -> int:
    import duckdb
    from evtx_tool.core import parser, filters
    from evtx_tool.core.heavyweight import engine as hw_engine
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    from evtx_tool.output import exporters
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    from evtx_tool.gui.filter_dialog import FilterDialog
    from evtx_tool import cli
    from PySide6.QtWidgets import QApplication, QCheckBox
    app = QApplication.instance() or QApplication([])   # noqa: F841

    # ── names
    names = {"Normal parser": parser.LEVEL_NAMES, "Juggernaut engine": hw_engine._LEVEL_MAP,
             "exports": exporters.LEVEL_NAMES}
    for where, m in names.items():
        check(f"{where}: level 0 is named Information", m[0] == "Information" and m[4] == "Information", m[0])
    name_of = parser.LEVEL_NAMES
    evs = []
    for i, lv in enumerate(LEVELS):
        e = T.ev(r"C:\s\Security.evtx", i + 1, "HOST-A", T.T0, 4624)
        e["level"], e["level_name"] = lv, name_of[lv]
        evs.append(e)
    check("the level number is unchanged", [e["level"] for e in evs] == LEVELS)

    # ── the three evaluators
    con = duckdb.connect()
    con.execute("CREATE TABLE t (rid INTEGER, level INTEGER, level_name VARCHAR, keywords VARCHAR, "
                "ed_flat_json VARCHAR, process_id BIGINT, thread_id BIGINT)")
    con.executemany("INSERT INTO t VALUES (?, ?, ?, '0x8000000000000000', '{}', NULL, NULL)",
                    [[e["record_id"], e["level"], e["level_name"]] for e in evs])
    model = EventTableModel()
    model.set_events(evs) if hasattr(model, "set_events") else model.load_events(evs)
    proxy = EventFilterProxyModel()
    proxy.setSourceModel(model)

    def three(cfg):
        full = dict(filters.empty_filter(), **cfg)
        core = sorted(e["level"] for e in evs if filters.matches(e, full)) if hasattr(filters, "matches") else None
        if core is None:
            core = sorted(e["level"] for e in evs
                          if (not full.get("levels") or filters._level_passes(e, full["levels"]))
                          and filters._conditions_pass(e, full.get("conditions") or [], False))
        where, params = filter_config_to_sql(full)
        jm = sorted(r[0] for r in con.execute(f"SELECT level FROM t WHERE {where}", params).fetchall())
        proxy.set_advanced_filter(full)
        normal = sorted(evs[proxy.mapToSource(proxy.index(r, 0)).row()]["level"] for r in range(proxy.rowCount()))
        return normal, jm, core

    cases = [
        ('the name "Information" selects level 0 and level 4', {"levels": ["Information"]}, [0, 0, 0, 4, 4]),
        ('"Information" + "Error"', {"levels": ["Information", "Error"]}, [0, 0, 0, 2, 4, 4]),
        ('a saved "LogAlways" still means level 0 only', {"levels": ["LogAlways"]}, [0, 0, 0]),
        ("the number 4 means level 4 only", {"levels": [4]}, [4, 4]),
        ("the number 0 means level 0 only", {"levels": [0]}, [0, 0, 0]),
        ('"Warning" alone is unchanged', {"levels": ["Warning"]}, [3]),
        ('a condition "level equals 0" selects level 0 alone',
         {"conditions": [{"name": "level", "operator": "equals", "value": "0"}]}, [0, 0, 0]),
    ]
    for label, cfg, want in cases:
        normal, jm, core = three(cfg)
        check(label, normal == jm == core == want, f"expected {want}; Normal {normal}, Juggernaut {jm}, parse-time {core}")

    # ── command line
    fc = cli._build_filter(None, "information", None, None, None, None, None, None, "AND", None, None)
    check("command line --level information selects level 0 and level 4", sorted(fc.get("levels") or []) == [0, 4],
          f"{fc.get('levels')}")
    fc = cli._build_filter(None, "logalways", None, None, None, None, None, None, "AND", None, None)
    check("command line --level logalways still selects level 0", sorted(fc.get("levels") or []) == [0])

    # ── Filter dialog
    dlg = FilterDialog(metadata={}, current_filter={})
    boxes = [c.text() for c in dlg.findChildren(QCheckBox)]
    check("the Filter dialog has no LogAlways box, and one Information box",
          "LogAlways" not in boxes and boxes.count("Information") == 1)
    for c in dlg._level_checks.values():
        c.setChecked(False)
    dlg._level_checks["Information"].setChecked(True)
    check("ticking Information alone gives the name Information", dlg.get_filter_config()["levels"] == ["Information"])

    def reload(levels):
        d = FilterDialog(metadata={}, current_filter={"levels": levels})
        return d, d.get_filter_config()["levels"], d._level_checks["Information"].isChecked()
    d, out, ticked = reload(["LogAlways"])
    normal, jm, core = three({"levels": out})
    check('a loaded "LogAlways" filter is kept as level 0 only, Information not ticked',
          not ticked and normal == jm == core == [0, 0, 0] and d._hidden.get("levels"),
          f"ticked {ticked}, saved {out}, selects {normal}")
    d, out, ticked = reload([4])
    normal, jm, core = three({"levels": out})
    check("a loaded number 4 is kept as level 4 only", not ticked and normal == jm == core == [4, 4],
          f"ticked {ticked}, saved {out}, selects {normal}")
    d, out, ticked = reload([0, 4])
    normal, jm, core = three({"levels": out})
    check("loaded numbers 0 and 4 tick Information", ticked and out == ["Information"]
          and normal == jm == core == [0, 0, 0, 4, 4], f"ticked {ticked}, saved {out}")
    d, out, ticked = reload(["LogAlways", "Information", "Error"])
    check('a loaded "LogAlways" + "Information" ticks Information, nothing kept aside',
          ticked and sorted(out) == ["Error", "Information"] and not d._hidden.get("levels"), f"saved {out}")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
