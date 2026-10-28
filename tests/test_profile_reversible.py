"""A profile is a view, never a cut: untick it, apply None or Clear All Filters
and every parsed event is back -- no re-parse.

Reported by the user on main: removing a filter did not bring the events back
("unselecting the filter and applying no filter doesn't help, nor does Clear
filter"); they had to re-parse the whole winevt folder.  Cause: a profile
ticked when Parse is clicked went into the PARSE as its filter, in both
modes, so the events outside it were never loaded.  Every later "remove the
filter" could only filter what was there.  The Tools (WiFi, Logon Sessions,
Remote sessions) read the loaded events too, so they came up empty or short.

Also pinned here, because the view must mean one thing -- Advanced Filter AND
the profiles last applied:
  * Normal mode: clearing the Advanced Filter wiped an applied profile while
    its box stayed ticked;
  * Juggernaut: clearing the Advanced Filter applied a profile that was only
    ticked, never applied.

Real data: the win7-x86 public baseline (EVTX_TEST_LOGS_ONLINE).  Expected
totals come from reading the files with pyevtx-rs directly.
"""
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtCore import Qt                                       # noqa: E402
from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])

CHECKS = []
PROFILE = "PowerShell Execution"
NAMES = ["Security.evtx", "Windows PowerShell.evtx", "Microsoft-Windows-PowerShell%4Operational.evtx",
         "Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def pump(ms=50):
    end = time.perf_counter() + ms / 1000.0
    while time.perf_counter() < end:
        app.processEvents()
        time.sleep(0.005)


def wait_for(pred, timeout_s=120):
    end = time.perf_counter() + timeout_s
    while time.perf_counter() < end:
        app.processEvents()
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(0.01)
    return False


def raw_total(files):
    import evtx
    return sum(1 for f in files for r in evtx.PyEvtxParser(f).records_json() if isinstance(r, dict))


def tick(w, names):
    m = w._profile_combo._chk_model
    for i in range(m.rowCount()):
        m.item(i).setCheckState(Qt.CheckState.Checked if m.item(i).text() in names else Qt.CheckState.Unchecked)


def run(mode, files, total):
    import evtx_tool.gui.main_window as mw
    jm = mode == "JM"
    print(f"\n=== {mode} ===", flush=True)
    w = mw.MainWindow(initial_paths=files)
    w._recommended_max_size = lambda: 10 ** 13     # no volume prompt in Normal mode
    tick(w, [PROFILE])

    def loaded():
        return len(w._hw_model._full_table) if jm else len(w._events)

    def shown():
        if jm:
            wait_for(lambda: w._hw_model._filter_thread._q.empty(), 120)
            pump(600)
            return w._hw_model.rowCount()
        pump(200)
        return w._proxy_model.rowCount()

    if jm:
        w._launch_juggernaut_mode(files)
        ok = wait_for(lambda: w._hw_model is not None and w._btn_parse.isEnabled(), 600)
    else:
        w._on_parse_clicked()
        ok = wait_for(lambda: w._btn_parse.isEnabled() and w._worker is None and len(w._events) > 0, 600)
    pump(1500)
    check(f"{mode}: parse finished", ok)
    if not ok:
        return None

    n_loaded = loaded()
    check(f"{mode}: a profile ticked at Parse loads every event (it filters the view, not the parse)",
          n_loaded == total, f"loaded {n_loaded:,} of {total:,}")
    n_prof = shown()
    check(f"{mode}: ...and the ticked profile is applied to the view", 0 < n_prof < total,
          f"shown {n_prof:,} of {total:,}")
    w._update_count_label()
    check(f"{mode}: the event count says how many are shown of how many",
          w._lbl_count.text() == f"{n_prof:,} / {total:,} events", w._lbl_count.text())

    tick(w, [])
    w._btn_apply_profiles.click()
    n = shown()
    check(f"{mode}: untick + Apply Profiles shows every event again, no re-parse", n == total, f"{n:,} of {total:,}")

    tick(w, [PROFILE])
    w._btn_apply_profiles.click()
    n_again = shown()
    check(f"{mode}: Apply Profiles again gives the same view", n_again == n_prof, f"{n_again:,} vs {n_prof:,}")

    w._clear_advanced_filter()
    n = shown()
    check(f"{mode}: clearing the Advanced Filter keeps the applied profile", n == n_prof, f"{n:,} vs {n_prof:,}")

    w._btn_clear_all_filters.click()
    n = shown()
    check(f"{mode}: Clear All Filters shows every event and unticks the profiles",
          n == total and not w._get_checked_profiles(), f"{n:,} of {total:,}; ticked {w._get_checked_profiles()}")
    w._update_count_label()
    check(f"{mode}: ...and the event count says so", w._lbl_count.text() == f"{total:,} events", w._lbl_count.text())

    tick(w, [PROFILE])                              # ticked, NOT applied
    w._clear_advanced_filter()
    n = shown()
    check(f"{mode}: a profile that is only ticked (not applied) does not filter", n == total, f"{n:,} of {total:,}")

    try:
        w._clear_results()
    except Exception:
        pass
    w.close()
    pump(300)
    return n_prof


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE", "")
    folder = os.path.join(root, "win7-x86", "win7-x86")
    files = [os.path.join(folder, n) for n in NAMES]
    if not root or not all(os.path.exists(f) for f in files):
        print("EVTX_TEST_LOGS_ONLINE (with win7-x86) not set -- skipped")
        return 0
    total = raw_total(files)
    print(f"{len(files)} files, {total:,} records read directly", flush=True)
    res = {m: run(m, files, total) for m in ("Normal", "JM")}
    check("Normal and Juggernaut show the same profile view", res["Normal"] == res["JM"] and res["JM"] is not None,
          str(res))
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
