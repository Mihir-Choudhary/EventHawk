"""A WiFi session never spans a reboot of its host.

Found by Codex in audit-5b (A5B-WIFI): one Juggernaut WiFi row showed a
numeric duration of 95,422 s (26.5 h) between a connect and a disconnect with
an OS boot of the same host (Kernel-General 12, independently re-read) 67,451 s
after the connect.  A connection cannot survive a restart: the log does not
say when that session ended, so a number there is fabricated.  The pairing had
no boot barrier, and the JM fetch did not even load boot events.

Expected, in both modes: a session with a boot of ITS host between connect
and disconnect reads "Unavailable", with no numeric duration; an open session
followed by a boot is not "Active"; a boot of another host changes nothing.
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

CHECKS = []
WLAN = "Microsoft-Windows-WLAN-AutoConfig/Operational"
GUID = "{11111111-2222-3333-4444-555555555555}"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def wlan(host, rid, secs, eid, ssid):
    e = T.ev(rf"C:\c\{host}-WLAN.evtx", rid, host, T.T0 + timedelta(seconds=secs), eid,
             "Microsoft-Windows-WLAN-AutoConfig",
             {"InterfaceGuid": GUID, "InterfaceDescription": "Adapter", "SSID": ssid,
              "BSSID": "00-11-22-33-44-55", "AuthenticationAlgorithm": "WPA2-Personal",
              "CipherAlgorithm": "AES-CCMP", "Reason": "x"})
    e["channel"] = WLAN
    return e


def kernel_boot(host, rid, secs):
    e = T.ev(rf"C:\c\{host}-System.evtx", rid, host, T.T0 + timedelta(seconds=secs), 12,
             "Microsoft-Windows-Kernel-General", {"StartTime": "x"})
    e["channel"] = "System"
    return e


def security_boot(host, rid, secs):
    e = T.ev(rf"C:\c\{host}-Security.evtx", rid, host, T.T0 + timedelta(seconds=secs), 4608,
             "Microsoft-Windows-Security-Auditing", {})
    e["channel"] = "Security"
    return e


def dataset():
    return [
        # HOST-A: connect 0, Kernel boot 100, disconnect 500 -> no duration.
        wlan("HOST-A", 1, 0, 8001, "NetA"), kernel_boot("HOST-A", 1, 100),
        wlan("HOST-A", 2, 500, 8003, "NetA"),
        # HOST-A: connect 1000, Security 4608 boot 1200, never disconnected.
        wlan("HOST-A", 3, 1000, 8001, "NetA2"), security_boot("HOST-A", 1, 1200),
        # HOST-B: connect 50, disconnect 400; HOST-A's boot at 100 is not its own.
        wlan("HOST-B", 1, 50, 8001, "NetB"), wlan("HOST-B", 2, 400, 8003, "NetB"),
    ]


def by_ssid(sessions):
    return {s["ssid"]: s for s in sessions}


def grade(tag, sessions):
    s = by_ssid(sessions)
    a, a2, b = s.get("NetA"), s.get("NetA2"), s.get("NetB")
    check(f"{tag}: a session across its host's reboot has no numeric duration",
          a is not None and a["duration_secs"] < 0 and str(a["duration"]).startswith("Unavailable"),
          str(a and (a["duration"], a["duration_secs"])))
    check(f"{tag}: an open session followed by its host's reboot is not 'Active'",
          a2 is not None and a2["duration"] != "Active" and a2["duration_secs"] < 0,
          str(a2 and (a2["duration"], a2["duration_secs"])))
    check(f"{tag}: another host's reboot leaves a session's duration alone",
          b is not None and b["duration_secs"] == 350.0, str(b and (b["duration"], b["duration_secs"])))


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = dataset()
    grade("Normal", mw._WifiHistoryDialog._build_sessions(evs))

    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, evs)
    got = []
    worker = mw._WifiJMFetchWorker(w._hw_db_path)
    worker.finished.connect(lambda events, trunc: got.append(events))
    worker.run()                                     # synchronous: the query itself
    T.pump(100)
    grade("JM", mw._WifiHistoryDialog._build_sessions(got[0] if got else []))
    T.teardown(w, True, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
