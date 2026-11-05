"""Juggernaut WiFi / Remote Assistance / session filter load every event; a large load asks first.

User (2026-11-06): "I wanted to look at everything, but give a warning in
Juggernaut mode that enabling this Wi-Fi and remote tool ... and logon session
tool might increase the memory usage".  The tools stopped at 200,000 events
(WiFi, Remote Assistance) and the session filter at 500,000, disclosed but
still hidden.  The tools load only when opened, so the choice is offered there:
count first; above JM_LOAD_CONFIRM_ROWS ask "load N events (about X MB)?".

Expected: the fetches return every event (210,000 > the old 200,000); a load
below the threshold opens without asking; above it the question is asked and
"No" loads nothing; the session key fetch returns every key (600,000 > 500,000).
Synthetic data only.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import wlan                             # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import duckdb
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QMessageBox
    N = 210_000
    evs = [wlan("HOST-A", i + 1, i, 8001 if i % 2 == 0 else 8003, f"Net{i % 7}") for i in range(N)]
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, evs)

    got = []
    wk = mw._WifiJMFetchWorker(w._hw_db_path)
    wk.finished.connect(lambda e, t: got.append((len(e), t)))
    wk.run()
    check("WiFi fetch returns every event (210,000 > the old 200,000) and is not truncated",
          got and got[0] == (N, False), str(got))
    cnt = []
    wk = mw._WifiJMFetchWorker(w._hw_db_path, count_only=True)
    wk.counted.connect(cnt.append)
    wk.run()
    check("the count-only query counts the same events", cnt == [N], str(cnt))
    cnt = []
    wk = mw._RemoteAssistJMFetchWorker(w._hw_db_path, count_only=True)
    wk.counted.connect(cnt.append)
    wk.run()
    check("Remote Assistance has the count-only query too", cnt == [0], str(cnt))

    # Opening the tool: above the threshold it asks; No loads nothing.
    asked = []
    real_q = QMessageBox.question
    QMessageBox.question = staticmethod(lambda *a, **k: (asked.append(a[2] if len(a) > 2 else k),
                                                         QMessageBox.StandardButton.No)[1])
    opened = []
    real_ready = w._on_wifi_jm_events_ready
    w._on_wifi_jm_events_ready = lambda e, t: opened.append(len(e))
    try:
        w._on_show_wifi_history()
        T.wait_for(lambda: bool(asked) or bool(opened), 60)
        T.pump(500)
        check("above the threshold, opening asks first, naming the count and memory",
              asked and f"{N:,}" in str(asked[0]) and "MB" in str(asked[0]), str(asked)[:200])
        check("...and No loads nothing", not opened, str(opened))
        asked.clear()
        mw.JM_LOAD_CONFIRM_ROWS, keep = N + 1, mw.JM_LOAD_CONFIRM_ROWS
        try:
            w._on_show_wifi_history()
            T.wait_for(lambda: bool(opened), 120)
            T.pump(300)
        finally:
            mw.JM_LOAD_CONFIRM_ROWS = keep
        check("below the threshold it opens without asking, with every event", not asked and opened == [N],
              f"asked {len(asked)}, opened {opened}")
    finally:
        QMessageBox.question = real_q
        w._on_wifi_jm_events_ready = real_ready
    T.teardown(w, True, m)

    # Session filter key fetch: no hard cap.
    keys = []
    sw = mw._JMSessionFetchWorker(duckdb, "(SELECT 'f.evtx' AS source_file, range AS record_id FROM range(600000))",
                                  "1=1", [], None)
    sw.count_ready.connect(lambda n: sw.proceed(True))
    sw.rows_ready.connect(keys.append)
    sw.run()
    check("the session filter fetches every key (600,000 > the old 500,000)", keys and len(keys[0]) == 600_000,
          str(len(keys[0]) if keys else None))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
