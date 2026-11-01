"""The Timestamp filter tree has an hour level under each day (spec R-1).

User (2026-11-01): the popup is "a Year -> Month -> Day -> Time tree" with a
chevron on every expandable node, days included -- but days were leaves.
Expected: a day shows a chevron before its hours are known; its hours load on
first expand (once); unticking some hours of a day filters exactly those hours
out, in Normal and in Juggernaut; a fully ticked or unticked day keeps the
date-level filter; reopening the popup shows the hour selection again; a
400-day popup with one partial day filters exactly (never "show all").
Display time zone forced to UTC so the oracle is the raw timestamp.  Synthetic.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events(days=3):
    out, rid = [], 0
    base = datetime(2024, 5, 14, tzinfo=timezone.utc)
    for d in range(days):
        for h in (0, 9, 10, 10, 11, 23):
            rid += 1
            out.append(T.ev(r"C:\s\Security.evtx", rid, "HOST-A", base + timedelta(days=d, hours=h, minutes=rid % 50), 4624))
    return out


def hour_of(e):
    return e["timestamp"][:13].replace("T", " ")


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication, QTreeWidgetItem
    import evtx_tool.gui.main_window as mw
    import evtx_tool.gui.models as M
    from evtx_tool.gui.main_window import ColumnFilterPopup
    M._tz_state["mode"] = "utc"
    date_col = next(i for i, k in ColumnFilterPopup.FILTERABLE.items() if k == "timestamp_date")

    # ── the popup itself ────────────────────────────────────────────────────
    calls = []

    def provider(day):
        calls.append(day)
        return {"10": 2, "11": 1}
    p = ColumnFilterPopup(date_col, {"2024-05-14": 3, "2024-05-15": 6}, hour_provider=provider)
    day = next(p._checkboxes[i]._item for i in range(len(p._checkboxes))
               if p._checkboxes[i].property("filter_value") == "2024-05-14")
    check("a day shows an expand indicator before its hours are loaded",
          day.childIndicatorPolicy() == QTreeWidgetItem.ChildIndicatorPolicy.ShowIndicator and day.childCount() == 0)
    day.setExpanded(True); day.setExpanded(False); day.setExpanded(True)
    check("expanding loads the hours once", calls == ["2024-05-14"] and day.childCount() == 2, f"calls {calls}")
    emitted = []
    p.filterApplied.connect(lambda c, m, v: emitted.append((m, sorted(v))))
    day.child(0).setCheckState(0, Qt.CheckState.Unchecked)          # untick 10:00 on the 14th
    check("unticking one hour leaves the day partly ticked",
          day.checkState(0) == Qt.CheckState.PartiallyChecked)
    p._apply()
    want_unchecked = ["2024-05-14 10"]
    check("a partial day emits hour-level values (smaller side: exclude the one hour)",
          emitted == [("exclude", want_unchecked)], str(emitted[:1])[:160])

    # ── Normal and Juggernaut filter exactly the chosen hours ─────────────────
    for jm in (False, True):
        mode = "JM" if jm else "Normal"
        evs = events()
        w = mw.MainWindow()
        T.Mode(mw, jm).load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)        # as _on_hw_finished does
        T.pump(200)

        def count():
            if jm:
                T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30); T.pump(300)
                return w._hw_model.rowCount()
            return w._proxy_model.rowCount()
        w._on_col_filter_applied(date_col, "exclude", ["2024-05-14 10"])
        want = sum(1 for e in evs if hour_of(e) != "2024-05-14 10")
        check(f"{mode}: excluding one hour hides exactly that hour", count() == want, f"{count()} vs {want}")
        keep = ["2024-05-15 09", "2024-05-15 11", "2024-05-16 23"]
        w._on_col_filter_applied(date_col, "include", keep)
        want = sum(1 for e in evs if hour_of(e) in keep)
        check(f"{mode}: including three hours shows exactly those", count() == want, f"{count()} vs {want}")
        w._on_col_filter_applied(date_col, "include", ["2024-05-15"])
        want = sum(1 for e in evs if e["timestamp"].startswith("2024-05-15"))
        check(f"{mode}: a whole-day selection still filters by date", count() == want, f"{count()} vs {want}")
        w._on_col_filter_applied(date_col, "exclude", ["2024-05-14 10"])
        values = {"2024-05-14": 6, "2024-05-15": 6, "2024-05-16": 6}
        w._show_col_filter_popup(date_col, values)
        T.pump(200)
        pops = [t for t in QApplication.topLevelWidgets() if isinstance(t, ColumnFilterPopup) and t.isVisible()]
        ok = False
        if pops:
            pop = pops[-1]
            d14 = next(c._item for c in pop._checkboxes if c.property("filter_value") == "2024-05-14")
            hours = {d14.child(i).data(0, Qt.ItemDataRole.UserRole + 1): d14.child(i).checkState(0)
                     for i in range(d14.childCount())}
            ok = (d14.checkState(0) == Qt.CheckState.PartiallyChecked
                  and hours.get("2024-05-14 10") == Qt.CheckState.Unchecked
                  and hours.get("2024-05-14 11") == Qt.CheckState.Checked)
            pop.close()
        check(f"{mode}: reopening the popup shows the hour selection", ok)
        w._on_col_filter_applied(date_col, "clear", [])
        check(f"{mode}: clear restores every event", count() == len(evs))
        w.close(); T.pump(100)

    # ── 400 days, one partial day: exact, never fail-open ─────────────────────
    evs = events(400)
    w = mw.MainWindow()
    T.Mode(mw, False).load(w, evs)
    vals = {}
    for e in evs:
        vals[e["timestamp"][:10]] = vals.get(e["timestamp"][:10], 0) + 1
    pop = ColumnFilterPopup(date_col, vals, hour_provider=lambda d: {"00": 1, "09": 1, "10": 2, "11": 1, "23": 1})
    got = []
    pop.filterApplied.connect(lambda c, m, v: got.append((m, list(v))))
    d = next(c._item for c in pop._checkboxes if c.property("filter_value") == "2024-12-01")
    d.setExpanded(True)
    d.child(0).setCheckState(0, Qt.CheckState.Unchecked)            # 00:00 on 2024-12-01
    pop._apply()
    m, v = got[0]
    w._on_col_filter_applied(date_col, m, v)
    want = sum(1 for e in evs if hour_of(e) != "2024-12-01 00")
    check("400 days with one partial day: exactly that hour is hidden",
          w._proxy_model.rowCount() == want and want < len(evs), f"{w._proxy_model.rowCount()} vs {want}")
    w.close(); T.pump(100)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
