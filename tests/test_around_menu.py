"""The "Around this event" menu, its custom window and the filter question.

The menu says how many names "this host" covers and offers the suggested
names separately (only when there are some); an event without a readable
timestamp gets a disabled item that says why.  The filter question is asked
only when the clicked table has a filter on, and "only events that pass the
current filters" hands that table's own model to the pivot.
"""
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtCore import QTimer                                   # noqa: E402
from PySide6.QtWidgets import QApplication, QMenu, QMessageBox      # noqa: E402

app = QApplication.instance() or QApplication([])
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_around_pivot as tap                                     # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def around_menu(w, ev, source):
    menu = QMenu()
    w._add_around_menu(menu, ev, source)
    # The entry's glyph prefix became an icon; match the label itself.
    act = next((a for a in menu.actions() if "Around this event" in a.text()), None)
    return menu, act


def sub_texts(act):
    return [a.text() for a in act.menu().actions()] if act and act.menu() else []


def click_later(button_text, seen):
    """Answer the next modal question by clicking *button_text*."""
    def _go():
        box = QApplication.activeModalWidget()
        seen.append(box)
        if isinstance(box, QMessageBox):
            for b in box.buttons():
                if b.text() == button_text:
                    b.click()
                    return
            box.reject()
    QTimer.singleShot(50, _go)


def menu_checks(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== menu, {tag} ===", flush=True)
    m = tap.Mode(mw, jm)
    w = mw.MainWindow()
    evs = tap.dataset()
    m.load(w, evs)
    src = m.main_source(w)

    _menu, act = around_menu(w, dict(evs[0]), src)
    texts = sub_texts(act)
    check(f"{tag}: menu has the three scopes", texts == [
        "On this host (3 names)", "On this host + 1 suggested name", "On all hosts"], str(texts))
    host = act.menu().actions()[0]
    tip = host.toolTip()
    check(f"{tag}: 'On this host' tooltip lists each name and why",
          all(s in tip for s in ("OLD-NAME", "ws01.corp.local", "rename", "domain suffix")), tip)
    presets = [a.text() for a in host.menu().actions()]
    check(f"{tag}: presets then Custom", presets == [
        "±1 min", "±5 min", "±15 min", "±1 hour", "±1 day", "Custom…"], str(presets))

    _menu, act = around_menu(w, dict(evs[9]), src)          # OTHER: one name, no suggestion
    check(f"{tag}: no '+ suggested' item without suggestions",
          sub_texts(act) == ["On this host (1 name)", "On all hosts"], str(sub_texts(act)))

    nots = dict(evs[12])                                    # no timestamp
    _menu, act = around_menu(w, nots, src)
    check(f"{tag}: no-timestamp anchor greys the item, saying why",
          act is not None and not act.isEnabled()
          and act.toolTip() == "This event has no readable timestamp.",
          f"{act and act.isEnabled()} / {act and act.toolTip()!r}")

    # Filter question: not asked without a filter.
    seen = []
    click_later("Only events that pass the current filters", seen)
    got = w._ask_around_filter_scope(src)
    tap.pump(150)
    check(f"{tag}: no filter -> no question, all loaded events", got == "all" and not any(seen),
          f"{got} / {seen}")

    # With a quick filter: asked; "filtered" passes the clicked table's model.
    m.quick_filter_main(w, "event_id", "4624")
    calls = []
    w._open_around_tab = lambda *a, **k: calls.append((a, k))
    _menu, act = around_menu(w, dict(evs[0]), src)
    five = next(a for a in act.menu().actions()[2].menu().actions() if a.text() == "±5 min")
    seen = []
    click_later("Only events that pass the current filters", seen)
    five.trigger()
    tap.pump(150)
    check(f"{tag}: the filter question is asked when a filter is on",
          any(isinstance(b, QMessageBox) for b in seen), str(seen))
    ok = (len(calls) == 1 and calls[0][0][1:4] == (timedelta(minutes=5), timedelta(minutes=5), "all")
          and (calls[0][0][4] if len(calls[0][0]) > 4 else calls[0][1].get("filtered_from")) is src)
    check(f"{tag}: 'only filtered' hands the clicked table's model to the pivot", ok, str(calls))

    calls.clear()
    click_later("Include all loaded events", seen)
    five.trigger()
    tap.pump(150)
    check(f"{tag}: 'include all' opens over all loaded events",
          len(calls) == 1 and (calls[0][0][4] if len(calls[0][0]) > 4
                               else calls[0][1].get("filtered_from")) is None, str(calls))

    calls.clear()
    click_later("Cancel", seen)
    five.trigger()
    tap.pump(150)
    check(f"{tag}: cancel opens nothing", not calls, str(calls))
    del w._open_around_tab
    tap.teardown(w, jm, m)


def custom_dialog(mw):
    print("\n=== custom window dialog ===", flush=True)
    w = mw.MainWindow()
    dlg = mw._AroundCustomDialog(w)
    ok_btn = dlg._ok_button

    def set_side(i, n, unit):
        spin, combo = dlg._sides[i]
        combo.setCurrentText(unit)
        spin.setValue(n)

    set_side(0, 0, "minutes")
    set_side(1, 0, "minutes")
    check("custom: accepts 0 / 0", ok_btn.isEnabled() and dlg.values() == (timedelta(0), timedelta(0)),
          str(dlg.values()))
    set_side(0, 366, "days")
    check("custom: rejects 366 days", not ok_btn.isEnabled())
    set_side(0, 365, "days")
    set_side(1, 90, "minutes")
    check("custom: 365 days / 90 minutes",
          ok_btn.isEnabled() and dlg.values() == (timedelta(days=365), timedelta(minutes=90)),
          str(dlg.values()))
    set_side(1, 525_600, "hours")
    check("custom: 525,600 hours is over the limit", not ok_btn.isEnabled())
    dlg.close()
    w.close()


def main() -> int:
    import evtx_tool.gui.main_window as mw
    menu_checks(mw, False)
    menu_checks(mw, True)
    custom_dialog(mw)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
