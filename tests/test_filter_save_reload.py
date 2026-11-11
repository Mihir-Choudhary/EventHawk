"""A filter saved from the Advanced Filter loads back with the same meaning (Codex RA-1/RA-2).

RA-1: a CLI one-sided date filter (--date-to only) loaded correctly, but Save
wrote the open side as null with the Date/Time boxes ticked, and Load of that
file put the picker's default date in the null side: to-only showed 36 -> 0
events; from-only gained an upper bound.
RA-2: Load of an Error preset, then Load of an empty preset `{}`, kept Error
(27 rows instead of 81) and still said "Loaded".
Expected: after Save -> Load (JSON round trip, a new dialog) the Normal view
shows exactly the events the CLI's own evaluator keeps, in UTC and another
display time zone; Load of `{}` leaves no restriction.  Synthetic events only.
"""
import json
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events():
    out, n = [], 0
    names = {2: "Error", 4: "Information", 0: "LogAlways"}
    for day in (1, 2, 3):
        for hour in (0, 5, 22):
            for lv in (0, 2, 4):
                for word in ("powershell run", "cmd start", "other"):
                    n += 1
                    out.append({"event_id": 4100 + lv, "level": lv, "level_name": names[lv],
                                "provider": "P", "channel": "C", "computer": "PC", "record_id": n,
                                "timestamp": f"2024-01-0{day}T{hour:02d}:30:00.000000Z",
                                "event_data": {"Msg": word}, "source_file": "s.evtx"})
    # Later than any default picker date: a from-only filter must keep it.
    out.append(dict(out[-1], record_id=n + 1, timestamp="2099-06-01T12:00:00.000000Z"))
    return out


def normal_view(cfg, evs):
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    m = EventTableModel()
    m.set_events(evs) if hasattr(m, "set_events") else m.load_events(evs)
    p = EventFilterProxyModel()
    p.setSourceModel(m)
    p.set_advanced_filter(cfg)
    return {evs[p.mapToSource(p.index(r, 0)).row()]["record_id"] for r in range(p.rowCount())}


def main() -> int:
    from evtx_tool.core.filters import empty_filter, passes_filter
    from evtx_tool.gui.filter_dialog import FilterDialog
    from evtx_tool.gui import models
    evs = events()
    base = empty_filter()
    cases = {
        "to only": dict(base, date_to="2024-01-01T23:59:59"),
        "from only": dict(base, date_from="2024-01-02T05:00:00"),
        "from and to": dict(base, date_from="2024-01-02T05:00:00", date_to="2024-01-03T04:59:59"),
    }
    try:
        for tzname, tz in (("UTC", ("utc",)), ("UTC+05:30", ("custom", "Asia/Kolkata", 330))):
            models.set_tz_config(*tz)
            for name, cli in cases.items():
                want = {e["record_id"] for e in evs if passes_filter(e, cli)}
                try:
                    saved = json.loads(json.dumps(
                        FilterDialog(metadata={}, current_filter=cli).get_filter_config()))
                    again = json.loads(json.dumps(
                        FilterDialog(metadata={}, current_filter=saved).get_filter_config()))
                    got = normal_view(FilterDialog(metadata={}, current_filter=again).get_filter_config(), evs)
                except Exception as exc:                          # noqa: BLE001
                    got = {"error": repr(exc)}
                check(f"[{tzname}] CLI {name} -> Save -> Load -> Save -> Load: same events as the CLI",
                      got == want and 0 < len(want) < len(evs),
                      f"got {len(got)} vs {len(want)} of {len(evs)}")
        models.set_tz_config("utc")
        dlg = FilterDialog(metadata={}, current_filter=dict(base, levels=[2]))
        dlg._restore_state({})
        got = normal_view(dlg.get_filter_config(), evs)
        check("RA-2 Load '{}' after an Error preset: no restriction left", len(got) == len(evs),
              f"got {len(got)} of {len(evs)}")
    finally:
        models.set_tz_config("utc")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
