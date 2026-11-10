"""A CLI-saved filter loaded in the Advanced Filter keeps its meaning (Codex FO-6/7/8).

`evtx_tool parse ... --save-filter f.json` writes levels as numbers, date bounds
as UTC ISO text with no dialog flags, and multi-term / NOT searches as a list
plus search_mode.  Loaded in the GUI:
  FO-6  levels [2] ticked no box, so no level restriction (690 -> 83,851);
  FO-8  the date bounds were not read (wrong text format, no flags): no date
        restriction (201 -> 83,851);
  FO-7  NOT search kept, but the Normal view treated NOT as AND: the opposite
        events (73,911 expected, 9,940 shown).
Expected: the Normal view after Load + OK shows exactly the events the CLI's own
evaluator (core passes_filter on the saved file) keeps, in UTC and in another
display time zone.  Synthetic events only.
"""
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
    names = {1: "Critical", 2: "Error", 3: "Warning", 4: "Information", 5: "Verbose", 0: "LogAlways"}
    for day in (1, 2, 3):
        for hour in (0, 5, 22):
            for lv in (0, 2, 4):
                for word in ("powershell run", "cmd start", "other"):
                    n += 1
                    out.append({"event_id": 4100 + lv, "level": lv, "level_name": names[lv],
                                "provider": "P", "channel": "C", "computer": "PC", "record_id": n,
                                "timestamp": f"2024-01-0{day}T{hour:02d}:30:00.000000Z",
                                "event_data": {"Msg": word}, "source_file": "s.evtx"})
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
        "FO-6 level Error (saved as [2])": dict(base, levels=[2]),
        "FO-8 date range (saved as UTC ISO)": dict(base, date_from="2024-01-02T05:00:00",
                                                   date_to="2024-01-03T04:59:59"),
        "FO-8 one-sided date (from only)": dict(base, date_from="2024-01-02T05:00:00"),
        "FO-7 NOT search": dict(base, text_search=["powershell"], search_mode="NOT"),
        "FO-7 NOT with two terms": dict(base, text_search=["powershell", "cmd"], search_mode="NOT"),
        "OR search (control)": dict(base, text_search=["powershell", "cmd"], search_mode="OR"),
    }
    try:
        for tzname, tz in (("UTC", ("utc",)), ("UTC+05:30", ("custom", "Asia/Kolkata", 330))):
            models.set_tz_config(*tz)
            for name, saved in cases.items():
                want = {e["record_id"] for e in evs if passes_filter(e, saved)}
                try:
                    got = normal_view(FilterDialog(metadata={}, current_filter=saved).get_filter_config(), evs)
                except Exception as exc:                          # noqa: BLE001
                    got = {"error": repr(exc)}
                check(f"[{tzname}] {name}: Normal view after Load = the CLI's own result",
                      got == want and 0 < len(want) < len(evs),
                      f"got {len(got)} vs {len(want)} of {len(evs)}")
        # FO-10: Load after Load starts from a clear dialog.  A saved file
        # that does not set a field (null) kept the previous Load's value:
        # Error preset, then a provider-only preset -> still Error.
        models.set_tz_config("utc")
        nothing = dict(base, sources=["P"])
        for first in ("FO-6 level Error (saved as [2])", "FO-8 date range (saved as UTC ISO)",
                      "FO-7 NOT search"):
            dlg = FilterDialog(metadata={}, current_filter=cases[first])
            dlg._restore_state(nothing)
            want = {e["record_id"] for e in evs if passes_filter(e, nothing)}
            got = normal_view(dlg.get_filter_config(), evs)
            check(f"FO-10 Load after '{first}': nothing of it is kept", got == want,
                  f"got {len(got)} vs {len(want)}")
    finally:
        models.set_tz_config("utc")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
