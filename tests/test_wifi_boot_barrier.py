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

Codex retest (R17): a Kernel-General 12 record carries the boot's StartTime
and can be written later.  The barrier used only the record time, so a boot
before the connect whose record was written inside the session voided a
valid duration ("restarted in between"), and a boot inside the session
written after the disconnect left a numeric duration across it.  On the
corpus a StartTime also sat exactly one hour before its record with nothing
logged in between, so neither time alone proves when the host restarted
(ruling R19): the restart lies somewhere from the earlier to the later of the
two.  Inside the session for certain: "restarted in between".  Wholly before
or after: the duration stands.  Overlapping the connect or the disconnect:
no duration, and the reason says the restart time is uncertain (never the
"restarted in between" claim).  Synthetic events.
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


def kernel_boot(host, rid, secs, start=None):
    st = T.iso(T.T0 + timedelta(seconds=start)) if start is not None else "x"
    e = T.ev(rf"C:\c\{host}-System.evtx", rid, host, T.T0 + timedelta(seconds=secs), 12,
             "Microsoft-Windows-Kernel-General", {"StartTime": st})
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
        # R17 cases, connect 100 / disconnect 300 (boot StartTime / record time):
        # C: 50 / 200 -- overlaps the connect: uncertain.
        wlan("HOST-C", 1, 100, 8001, "NetC"), kernel_boot("HOST-C", 1, 200, 50),
        wlan("HOST-C", 2, 300, 8003, "NetC"),
        # D: 200 / 400 -- overlaps the disconnect: uncertain.
        wlan("HOST-D", 1, 100, 8001, "NetD"), kernel_boot("HOST-D", 1, 400, 200),
        wlan("HOST-D", 2, 300, 8003, "NetD"),
        # E: 150 / 151 -- inside for certain.
        wlan("HOST-E", 1, 100, 8001, "NetE"), kernel_boot("HOST-E", 1, 151, 150),
        wlan("HOST-E", 2, 300, 8003, "NetE"),
        # F: 10 / 20 -- before the connect: 200 s stands.
        kernel_boot("HOST-F", 1, 20, 10), wlan("HOST-F", 1, 100, 8001, "NetF"),
        wlan("HOST-F", 2, 300, 8003, "NetF"),
        # G: 400 / 401 -- after the disconnect: 200 s stands.
        wlan("HOST-G", 1, 100, 8001, "NetG"), wlan("HOST-G", 2, 300, 8003, "NetG"),
        kernel_boot("HOST-G", 1, 401, 400),
        # H: open session from 100; boot 50 / 150 overlaps the connect.
        wlan("HOST-H", 1, 100, 8001, "NetH"), kernel_boot("HOST-H", 1, 150, 50),
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

    def uncertain(x):
        return (x is not None and x["duration_secs"] < 0 and "uncertain" in str(x["duration"])
                and "reboot_between" not in x["anomaly_flags"])
    show = lambda x: str(x and (x["duration"], x["duration_secs"], x["anomaly_flags"]))   # noqa: E731
    check(f"{tag}: boot window overlapping the connect: no duration, restart time uncertain",
          uncertain(s.get("NetC")), show(s.get("NetC")))
    check(f"{tag}: boot inside but written after the disconnect: no duration, uncertain",
          uncertain(s.get("NetD")), show(s.get("NetD")))
    e = s.get("NetE")
    check(f"{tag}: boot inside for certain: restarted in between",
          e is not None and e["duration_secs"] < 0 and "reboot_between" in e["anomaly_flags"], show(e))
    check(f"{tag}: boot wholly before the connect: duration stands",
          s.get("NetF") is not None and s["NetF"]["duration_secs"] == 200.0, show(s.get("NetF")))
    check(f"{tag}: boot wholly after the disconnect: duration stands",
          s.get("NetG") is not None and s["NetG"]["duration_secs"] == 200.0, show(s.get("NetG")))
    h = s.get("NetH")
    check(f"{tag}: open session, boot overlapping its connect: not Active, uncertain",
          h is not None and h["duration"] != "Active" and uncertain(h), show(h))


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
