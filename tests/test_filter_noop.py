"""Filter setters skip the full re-filter when nothing changes.

Each pass runs filterAcceptsRow on every row (about 28 us a row through
PySide6): on 460k events that is ~13 s of "Not responding".  Clearing a
filter that was not set did a full pass, and the parse-reset path cleared
three of them in a row before loading the new events (the user's freeze,
2026-11-14).  A real change must still re-filter.

Run: QT_QPA_PLATFORM=offscreen python tests/test_filter_noop.py
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.models import EventFilterProxyModel, EventTableModel
    evs = [{"event_id": 4624 + (i % 3), "timestamp": f"2025-06-29T12:00:{i % 60:02d}.000000Z", "computer": "WS1",
            "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "level_name": "Information",
            "record_id": i, "source_file": "Security.evtx", "event_data": {"TargetUserName": "alice"}}
           for i in range(300)]
    src = EventTableModel()
    src.set_events(evs)
    px = EventFilterProxyModel()
    px.setSourceModel(src)
    passes = {"n": 0}
    px.filtering_started.connect(lambda: passes.__setitem__("n", passes["n"] + 1))

    def count(fn):
        passes["n"] = 0
        fn()
        return passes["n"]

    check("clearing an unset tactic filter does not re-filter", count(lambda: px.set_tactic_filter(None)) == 0)
    check("clearing an unset advanced filter does not re-filter", count(px.clear_advanced_filter) == 0)
    check("clearing no quick filters does not re-filter", count(px.clear_quick_filters) == 0)
    check("clearing an unset session filter does not re-filter", count(lambda: px.set_session_filter(None)) == 0)
    check("setting the same (empty) search text does not re-filter", count(lambda: px.set_filter_text("")) == 0)

    check("a real tactic filter does re-filter", count(lambda: px.set_tactic_filter("Discovery")) == 1)
    check("...the same one again does not", count(lambda: px.set_tactic_filter("discovery")) == 0)
    check("...clearing it does", count(lambda: px.set_tactic_filter(None)) == 1)
    check("a quick filter re-filters, the same list again does not",
          count(lambda: px.set_quick_filters([{"key": "event_id", "value": "4624", "include": True}])) == 1
          and count(lambda: px.set_quick_filters([{"key": "event_id", "value": "4624", "include": True}])) == 0)
    check("...and the rows are filtered", px.rowCount() == 100, str(px.rowCount()))
    check("clearing quick filters re-filters and shows every row", count(px.clear_quick_filters) == 1
          and px.rowCount() == 300, str(px.rowCount()))
    check("search text change re-filters", count(lambda: px.set_filter_text("alice")) == 1)

    import gc
    gc.unfreeze()
    big = [dict(evs[i % len(evs)], record_id=i) for i in range(60_000)]
    src.set_events(big)
    check("a big load is frozen out of later garbage-collector passes", gc.get_freeze_count() > 0,
          str(gc.get_freeze_count()))
    gc.unfreeze()
    src.set_events(evs)
    check("a small load does not freeze", gc.get_freeze_count() == 0, str(gc.get_freeze_count()))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
