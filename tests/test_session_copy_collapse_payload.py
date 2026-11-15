"""Session tools collapse true copies of a log only, and count a copied record once.

Gemini audit 8-09 (Medium):
1. Logon Sessions and Remote Assistance collapsed records that shared host,
   event ID, time and record ID even when their content differed (logs of
   cloned hosts), so one of two genuine sessions vanished;
2. WiFi did not collapse copies: a log loaded twice counted each 11006
   authentication failure twice;
3. WiFi's final session dedup ignored the host: identical sessions of two
   hosts became one row.

Expected: 2 logon sessions, 2 RA sessions, 1 auth failure (both modes), 2
WiFi sessions.  Contract: core/record_identity (same identity AND content).
Synthetic events.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_jm_computer import wlan                              # noqa: E402

CHECKS = []
RA = "Microsoft-Windows-RemoteAssistance/Operational"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def at(s):
    return T.T0 + timedelta(seconds=s)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])

    # 1a. Logon: two cloned-host logs, same ids and times, different logons.
    def logon(sf, user, lid):
        return [T.ev(sf, 10, "CLONE", at(0), 4624, data={"TargetLogonId": lid, "LogonType": "2", "TargetUserName": user}),
                T.ev(sf, 11, "CLONE", at(60), 4634, data={"TargetLogonId": lid})]
    evs = logon(r"C:\a\Security.evtx", "alice", "0x11") + logon(r"C:\b\Security.evtx", "bob", "0x22")
    d = mw._LogonSessionDialog(events=evs, on_filter_fn=lambda *a: None)
    users = sorted(s["user"] for s in d._all_sessions)
    d.close()
    check("Logon: two cloned-host logons with different content stay two sessions", users == ["alice", "bob"], str(users))
    evs = logon(r"C:\a\Security.evtx", "alice", "0x11") + logon(r"C:\a\Security - Copy.evtx", "alice", "0x11")
    d = mw._LogonSessionDialog(events=evs, on_filter_fn=lambda *a: None)
    n = len(d._all_sessions)
    d.close()
    check("Logon: a true copy still collapses (one session)", n == 1, str(n))

    # 1b. Remote Assistance.
    def ra(sf, user):
        out = []
        for rid, eid, s in ((1, 16, 0), (2, 18, 300)):
            e = T.ev(sf, rid, "CLONE", at(s), eid, "Microsoft-Windows-RemoteAssistance",
                     {"LocalFQDNName": "CLONE", "UserName": user})
            e["channel"] = RA
            out.append(e)
        return out
    rows = [r for r in mw._RemoteAssistanceDialog._build_sessions(ra(r"C:\a\RA.evtx", "SYNTH\\one") +
                                                                  ra(r"C:\b\RA.evtx", "SYNTH\\two"))
            if r["type"] == "Classic RA"]
    check("RA: two cloned-host sessions with different content stay two", len(rows) == 2, str(len(rows)))
    rows = [r for r in mw._RemoteAssistanceDialog._build_sessions(ra(r"C:\a\RA.evtx", "SYNTH\\one") +
                                                                  ra(r"C:\a\RA - Copy.evtx", "SYNTH\\one"))
            if r["type"] == "Classic RA"]
    check("RA: a true copy still collapses, naming both files", len(rows) == 1
          and "RA - Copy.evtx" in rows[0].get("source_log", "") and "RA.evtx" in rows[0].get("source_log", ""),
          str([(r.get("source_log")) for r in rows]))

    # 2. WiFi auth failure in a log loaded twice, both modes.
    def wifi(sf_tag):
        e = [wlan("HOST-A", 1, 0, 8001, "Net"), wlan("HOST-A", 2, 30, 11006, "Net"), wlan("HOST-A", 3, 600, 8003, "Net")]
        for x in e:
            x["source_file"] = rf"C:\c\{sf_tag}.evtx"
        return e
    two = wifi("WLAN") + wifi("WLAN - Copy")
    ss = mw._WifiHistoryDialog._build_sessions(two)
    check("WiFi (Normal): a copied 11006 counts once", [s["auth_failures"] for s in ss] == [1],
          str([s["auth_failures"] for s in ss]))
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, two)
    got = []
    worker = mw._WifiJMFetchWorker(w._hw_db_path)
    worker.finished.connect(lambda events, trunc: got.append(events))
    worker.run()
    T.pump(100)
    ss = mw._WifiHistoryDialog._build_sessions(got[0] if got else [])
    check("WiFi (Juggernaut): a copied 11006 counts once", [s["auth_failures"] for s in ss] == [1],
          str([s["auth_failures"] for s in ss]))
    T.teardown(w, True, m)

    # 3. Two hosts, identical sessions.
    a = [wlan("HOST-A", 1, 0, 8001, "Net"), wlan("HOST-A", 2, 600, 8003, "Net")]
    b = [wlan("HOST-B", 1, 0, 8001, "Net"), wlan("HOST-B", 2, 600, 8003, "Net")]
    ss = mw._WifiHistoryDialog._build_sessions(a + b)
    check("WiFi: identical sessions of two hosts stay two rows", sorted(s["computer"] for s in ss) == ["host-a", "host-b"],
          str([s["computer"] for s in ss]))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
