"""The Juggernaut WiFi browser keeps each event's host, as Normal mode does.

Found by Codex in audit-5 (E5-15): the Juggernaut WiFi fetch selected only
event ID, time and event data, so every row lost its Computer (51 of 51 on
the corpus) and sessions were paired by interface GUID alone.  Two hosts
whose adapters share a GUID (cloned images) then had one host's connect
paired with the other host's disconnect: a fabricated session and duration.
Expected: JM sessions equal Normal sessions, each with its own host.
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


def key(s):
    return (s["computer"], s["ssid"], s["connect_ts"], s["disconnect_ts"], s["duration_secs"])


def main() -> int:
    import evtx_tool.gui.main_window as mw
    # Host A: 0 s -> 20 s.  Host B: 10 s -> 600 s.  Same interface GUID.
    evs = [wlan("HOST-A", 1, 0, 8001, "NetA"), wlan("HOST-B", 1, 10, 8001, "NetB"),
           wlan("HOST-A", 2, 20, 8003, "NetA"), wlan("HOST-B", 2, 600, 8003, "NetB")]
    normal = sorted(key(s) for s in mw._WifiHistoryDialog._build_sessions(evs))

    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, evs)
    got = []
    worker = mw._WifiJMFetchWorker(w._hw_db_path)
    worker.finished.connect(lambda events, trunc: got.append(events))
    worker.run()                                     # synchronous: the query itself
    T.pump(100)
    events = got[0] if got else []
    check("JM: the fetch returns every WLAN event", len(events) == len(evs), str(len(events)))
    check("JM: every fetched event carries its host", all(e.get("computer") for e in events),
          str(sorted({e.get("computer", "") for e in events})))
    check("JM: every fetched event carries its source file", all(e.get("source_file") for e in events))
    jm = sorted(key(s) for s in mw._WifiHistoryDialog._build_sessions(events))
    check("JM sessions equal Normal sessions (host, network, endpoints, duration)", jm == normal,
          f"JM={jm} Normal={normal}")
    check("no session pairs one host's connect with another host's disconnect",
          all(s[0] in ("host-a", "host-b") for s in jm) and len(jm) == 2, str(jm))
    T.teardown(w, True, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
