"""Column popup: after every search, the matches shown and the notice are true (Codex CK91-4).

Each full-dataset search added its matches as checkboxes and they stayed for the
next search; a broad search picked its 5,000 without counting matches already
listed.  Sequence "16999" -> "1" -> "16999" on 7,001 event IDs (7,000 contain
"1"): the broad search showed 5,001 (Normal) / 5,952 (Juggernaut) matches while
saying "5,000 of 7,000", and the narrow search kept saying "5,000 of 7,000".
Expected, both modes, after each search: at most 5,000 matching values shown;
a notice saying "N of M" names exactly the N shown; a search that shows every
match leaves no stale notice.  Synthetic events only.
"""
import os
import sys

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


def state(p):
    shown = sum(1 for cb in p._checkboxes if not cb.isHidden())
    note = "" if p._lbl_partial.isHidden() else p._lbl_partial.text()
    return shown, note


def search(p, term, ready):
    p._inp_search.setText(term)
    T.wait_for(lambda: ready(p), 60)
    T.pump(1500)                                 # let any late merge land


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import COL_EID, COL_COMPUTER
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

        search(p, "16999", lambda p: any(cb.property("filter_value") == "16999" for cb in p._checkboxes))
        shown, note = state(p)
        check(f"{tag}: rare search shows its 1 match, no stale notice", shown == 1 and "of 7,0" not in note,
              f"{shown} / {note!r}")

        search(p, "1", lambda p: "7,000 matching" in p._lbl_partial.text())
        shown, note = state(p)
        check(f"{tag}: broad search shows at most 5,000 matches", shown <= 5000, str(shown))
        check(f"{tag}: its notice names exactly the matches shown, of 7,000",
              f"{shown:,} of 7,000 matching values" in note, f"{shown} / {note!r}")

        search(p, "16999", lambda p: sum(1 for cb in p._checkboxes if not cb.isHidden()) == 1)
        shown, note = state(p)
        check(f"{tag}: narrowing again shows 1 match and drops the 7,000 notice",
              shown == 1 and "7,000" not in note, f"{shown} / {note!r}")

        search(p, "zzzz", lambda p: True)
        shown, note = state(p)
        check(f"{tag}: a search with no match shows none and no stale notice",
              shown == 0 and "7,000" not in note, f"{shown} / {note!r}")

        p._inp_search.setText(""); T.pump(300)
        shown, note = state(p)
        check(f"{tag}: clearing the search restores the 1,000-value list and its notice",
              shown == 1000 and "most common of 7,001" in note, f"{shown} / {note!r}")
        p.close(); T.pump(100)
        T.teardown(w, jm, m)

    # Codex CK76-1: every value equal to the term ignoring case was put ahead
    # of the 5,000 bound and never counted against it - 7,001 case spellings
    # of one word rendered 7,001 checkboxes.  The literal value typed must
    # still be offered, inside the bound.
    from itertools import product
    from datetime import timedelta
    word = "syntheticvalue"
    spellings = ["".join(c) for c in product(*[(ch, ch.upper()) for ch in word])]
    spellings.remove(word)
    names = spellings[:7000] + [word]                    # 7,001 distinct, the literal one last
    cv = [T.ev(r"C:\c\Security.evtx", i + 1, n, T.T0 + timedelta(seconds=i)) for i, n in enumerate(names)]
    for jm in (False, True):
        tag = "Juggernaut" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        m.load(w, cv)
        if jm:
            w._table.setModel(w._hw_model)
        T.pump(300)
        p = open_popup(w, COL_COMPUTER)
        search(p, word, lambda p: "7,001 matching" in p._lbl_partial.text()
               or sum(1 for cb in p._checkboxes if not cb.isHidden()) > 5000)
        shown, note = state(p)
        lit = [cb for cb in p._checkboxes if cb.property("filter_value") == word]
        check(f"{tag}: 7,001 case spellings of one word: at most 5,000 shown", shown <= 5000, str(shown))
        check(f"{tag}: the notice names exactly the matches shown, of 7,001",
              f"{shown:,} of 7,001 matching values" in note, f"{shown} / {note!r}")
        check(f"{tag}: the literal value typed is offered and checked",
              len(lit) == 1 and not lit[0].isHidden() and lit[0].isChecked())
        p.close(); T.pump(100)
        T.teardown(w, jm, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
