"""In Separate View the session tools read every loaded file, as Merged and Juggernaut do.

Gemini audit 8-11 (Medium): in Normal-mode Separate View, WiFi History,
Logon Sessions, Remote Assistance, System Activity and Computer
Normalisation read only the active tab's events.  With the WLAN log's tab
active, a restart logged in System.evtx (another tab) was not seen, so a
connection across it kept its duration (Merged and Juggernaut voided it).

Expected: with the WLAN (or Security) tab active, the restart in the System
tab still bounds the session.  Synthetic events.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import kernel_boot, wlan                # noqa: E402

CHECKS = []
H = "SYNTH-HOST-01"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    wl = [wlan(H, 1, 0, 8001, "Net"), wlan(H, 2, 7200, 8003, "Net")]
    boot = kernel_boot(H, 3, 3600, start=3599)
    sec_f = rf"C:\c\{H}-Security.evtx"
    sec = [T.ev(sec_f, 4, H, T.T0, 4624, data={"TargetLogonId": "0x61", "LogonType": "2", "TargetUserName": "u"}),
           T.ev(sec_f, 5, H, T.T0 + timedelta(seconds=7200), 4634, data={"TargetLogonId": "0x61"})]
    evs = wl + [boot] + sec
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    try:
        m.load(w, evs)
        w._view_mode = "separate"
        files = {}
        for e in evs:
            files.setdefault(e["source_file"], []).append(e)
        w._per_file_data = {f: {"events": x, "search_cache": []} for f, x in files.items()}
        for f in files:
            w._create_file_tab(f)

        w._active_file_tab = wl[0]["source_file"]
        w._on_show_wifi_history()
        T.pump(100)
        d = getattr(w, "_wifi_history_dlg", None)
        ss = d._all_sessions if d is not None else []
        check("WiFi (WLAN tab active): the restart in the System tab voids the duration",
              len(ss) == 1 and ss[0]["duration_secs"] < 0 and "reboot_between" in ss[0]["anomaly_flags"],
              str([(s["duration"], s["anomaly_flags"]) for s in ss]))
        if d is not None:
            d.close()

        w._active_file_tab = sec_f
        w._close_logon_sessions_dlg()
        w._on_show_logon_sessions()
        T.pump(100)
        d = getattr(w, "_logon_sessions_dlg", None)
        ss = d._all_sessions if d is not None else []
        paired = [s for s in ss if s["logon_ev"] and s["logoff_ts"]]
        check("Logon (Security tab active): the restart splits the LogonId (no logon paired across it)",
              d is not None and not paired, str([(s["user"], s["logoff_ts"]) for s in ss]))
        if d is not None:
            d.close()
    finally:
        T.teardown(w, False, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
