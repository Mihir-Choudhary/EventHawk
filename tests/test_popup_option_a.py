"""Column filter popup: says when its list is partial; search finds every value; dates never capped.

User (2026-11-06, option A): keep the 1,000 most common values in the list but
say so, make the popup's search return every matching value, and always list
every date.  A value outside the 1,000 was reachable by search but nothing
said the list was partial, and a broad search stopped at 1,000 matches too.

Expected, both modes, through the real header click:
  * 7,001 event IDs: 1,000 listed, a line "Showing the 1,000 most common of
    7,001 values. Search to find any of them."; 3 computers: no such line;
  * 1,200 different dates: all 1,200 in the date tree;
  * the search worker returns every match (7,001 for "1"... see below);
  * a broad search adds 5,000 checkboxes, says how many matched, and still
    includes the exact value typed; the rare 4624 is found and filters exactly.
Synthetic events only.
"""
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


def dataset():
    evs, n = [], 0
    for eid in range(10000, 17000):              # 7,000 IDs, 2 events each, 1,200 days
        for _ in range(2):
            n += 1
            evs.append(T.ev(r"C:\c\Security.evtx", n, f"WS{n % 3}", T.T0 + timedelta(days=n % 1200, seconds=n), eid))
    n += 1
    evs.append(T.ev(r"C:\c\Security.evtx", n, "WS0", T.T0 + timedelta(seconds=n), 4624))   # rarest
    return evs


def open_popup(w, col):
    w._col_popup = None
    w._on_col_header_clicked(col)
    T.wait_for(lambda: getattr(w, "_col_popup", None) is not None, 60)
    T.pump(200)
    return w._col_popup


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import COL_EID, COL_COMPUTER, COL_TS
    evs = dataset()
    for jm in (False, True):
        tag = "Juggernaut" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
        T.pump(300)

        p = open_popup(w, COL_EID)
        vals = {x.property("filter_value") for x in p._checkboxes}
        note = p._lbl_partial.text() if not p._lbl_partial.isHidden() else ""
        check(f"{tag}: 7,001 event IDs: 1,000 listed and the popup says so",
              len(vals) == 1000 and "1,000 most common of 7,001 values" in note, f"{len(vals)} / {note!r}")
        check(f"{tag}: the rare 4624 is not in the list before searching", "4624" not in vals)
        p._inp_search.setText("4624")
        T.pump(2500)
        got = {}
        p.filterApplied.connect(lambda c, mo, v: got.update(mode=mo, values=list(v)))
        for cb in p._checkboxes:
            cb.setChecked(cb.property("filter_value") == "4624")
        p._apply(); T.pump(300)
        check(f"{tag}: searching finds 4624 and it filters to exactly that value",
              got.get("mode") == "include" and got.get("values") == ["4624"], str(got))
        p.close(); T.pump(100)
        # OK really filtered the view to 4624: back to every event.
        w._clear_all_filters()
        T.wait_for(lambda: m.main_count(w) == len(evs), 60)
        T.pump(500)

        # A broad search: every event ID contains "1" except 4624 -> 7,000 matches.
        p = open_popup(w, COL_EID)
        p._inp_search.setText("1")
        T.pump(4000)
        n_box = len(p._checkboxes)
        note = p._lbl_partial.text()
        check(f"{tag}: a broad search shows 5,000 matches and says 7,000 matched",
              "5,000 of 7,000 matching values" in note and n_box <= 6000, f"{n_box} boxes / {note!r}")
        p._inp_search.setText(""); T.pump(200)
        check(f"{tag}: clearing the search restores the list notice",
              "most common of 7,001" in p._lbl_partial.text() and not p._lbl_partial.isHidden())
        p._inp_search.setText("16999")
        T.pump(2500)
        check(f"{tag}: the exact value typed is offered", "16999" in {x.property("filter_value") for x in p._checkboxes})
        p.close(); T.pump(100)

        # The search provider returns every match, no 1,000 cap.
        box = []
        w._make_col_search_provider("event_id")("1", box.append)
        T.wait_for(lambda: bool(box), 60)
        check(f"{tag}: the search returns every matching value (7,000)", box and len(box[0]) == 7000,
              str(len(box[0]) if box else None))

        p = open_popup(w, COL_COMPUTER)
        check(f"{tag}: 3 computers: all listed, no partial-list notice",
              len(p._checkboxes) == 3 and p._lbl_partial.isHidden(), f"{len(p._checkboxes)}")
        p.close(); T.pump(100)

        p = open_popup(w, COL_TS)
        days = {x.property("filter_value") for x in p._checkboxes}
        check(f"{tag}: 1,200 different dates: every one is in the date tree", len(days) == 1200, str(len(days)))
        p.close(); T.pump(100)
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
