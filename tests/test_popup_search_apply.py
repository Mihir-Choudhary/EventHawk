"""Column popup: OK on a searched selection filters to exactly that selection (Codex CK88-1).

_apply treated "every listed value ticked" as "no filter" (clear) even while a
search was active - but during a search the list holds only the matches.
  * 1,001 case spellings of one Computer (2 events each) + 1 unrelated control:
    search the word, accept the automatic selection -> 2,003 rows, the control
    included (expected 2,002);
  * 7,000 event IDs containing "1": search "1" (5,000 of 7,000 shown), All,
    OK -> 14,001 rows (expected 10,000: the 5,000 values chosen).
Expected, both modes: the table holds exactly the rows of the values selected;
with no search, all ticked still means no filter.  Synthetic events only.
"""
import os
import sys
from datetime import timedelta
from itertools import product

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_popup_option_a import dataset, open_popup                 # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def apply_and_count(p, m, w):
    got = {}
    p.filterApplied.connect(lambda c, mo, v: got.update(mode=mo, n=len(list(v))))
    before = m.main_count(w)
    p._apply()
    T.wait_for(lambda: m.main_count(w) != before, 30)
    T.pump(1500)                                   # let the filter generation finish
    return got, m.main_count(w)


def case_dataset():
    word = "syntheticvalue"
    names = ["".join(c) for c in product(*[(ch, ch.upper()) for ch in word])][:1001]
    evs, n = [], 0
    for name in names:
        for _ in range(2):
            n += 1
            evs.append(T.ev(r"C:\c\Security.evtx", n, name, T.T0 + timedelta(seconds=n)))
    n += 1
    evs.append(T.ev(r"C:\c\Security.evtx", n, "UNRELATED-CONTROL", T.T0 + timedelta(seconds=n)))
    return word, evs


def run(jm, evs, body):
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    m = T.Mode(mw, jm)
    m.load(w, evs)
    if jm:
        w._table.setModel(w._hw_model)
    T.pump(300)
    try:
        body(w, m, "Juggernaut" if jm else "Normal")
    finally:
        T.teardown(w, jm, m)


def main() -> int:
    from evtx_tool.gui.models import COL_EID, COL_COMPUTER
    word, cevs = case_dataset()
    big = dataset()

    def auto_selection(w, m, tag):
        p = open_popup(w, COL_COMPUTER)
        p._inp_search.setText(word)
        T.wait_for(lambda: sum(1 for cb in p._checkboxes if not cb.isHidden()) == 1001, 60)
        T.pump(1500)
        shown = sum(1 for cb in p._checkboxes if not cb.isHidden() and cb.isChecked())
        got, rows = apply_and_count(p, m, w)
        check(f"{tag}: search '{word}', accept the automatic selection -> exactly its 2,002 rows",
              rows == 2002, f"{shown} ticked, emitted {got.get('mode')}, {rows:,} rows")

    def select_all(w, m, tag):
        p = open_popup(w, COL_EID)
        p._inp_search.setText("1")
        T.wait_for(lambda: "7,000 matching" in p._lbl_partial.text(), 60)
        T.pump(1500)
        p._check_all()
        ticked = sum(1 for cb in p._checkboxes if not cb.isHidden() and cb.isChecked())
        got, rows = apply_and_count(p, m, w)
        check(f"{tag}: search '1', All, OK -> exactly the rows of the {ticked:,} values chosen",
              rows == 2 * ticked and ticked == 5000, f"emitted {got.get('mode')}, {rows:,} rows")

    def no_search_all(w, m, tag):
        p = open_popup(w, COL_EID)
        got, rows = apply_and_count(p, m, w)
        check(f"{tag}: no search, every value ticked, OK -> no filter (all 14,001 rows)",
              got.get("mode") == "clear" and rows == len(big), f"emitted {got.get('mode')}, {rows:,} rows")

    for jm in (False, True):
        run(jm, cevs, auto_selection)
        run(jm, big, select_all)
        run(jm, big, no_search_all)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
