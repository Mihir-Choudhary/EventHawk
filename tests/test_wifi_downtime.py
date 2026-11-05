"""A WiFi session across a clean restart gets its downtime subtracted, and says so.

User decision (2026-11-05, "Both"): when the host was shut down and started
again during a session, the Duration shows connect-to-disconnect minus the
time the host was down, marked "(downtime subtracted)"; Notes gives every
part -- before the shutdown, the downtime, after the restart -- and says the
part after the restart is not proven, because no reconnect was logged.
Without a logged shutdown (an unexpected one: 6008 / Kernel-Power 41) or with
a startup time that is uncertain, there is no duration, and Notes says why.

Synthetic events, both modes (Normal builder; Juggernaut fetch + builder).
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
KG, KP = "Microsoft-Windows-Kernel-General", "Microsoft-Windows-Kernel-Power"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def sysev(host, rid, secs, eid, provider, data=None, channel="System"):
    e = T.ev(rf"C:\c\{host}-{channel}.evtx", rid, host, T.T0 + timedelta(seconds=secs), eid, provider, data or {})
    e["channel"] = channel
    return e


def at(secs):
    return T.iso(T.T0 + timedelta(seconds=secs))


def down_up(host, rid, down, up, up_start=None):
    """A clean shutdown at *down* (Kernel-General 13 with StopTime, 6006) and a start at *up*."""
    return [sysev(host, rid, down - 2, 1074, "User32"),
            sysev(host, rid + 1, down, 13, KG, {"StopTime": at(down)}),
            sysev(host, rid + 2, down, 6006, "EventLog"),
            sysev(host, rid + 3, up, 12, KG, {"StartTime": at(up if up_start is None else up_start)})]


def dataset():
    evs = []
    # S: connect 0, down 1000 -> up 1600, disconnect 2000: 2000 - 600 = 1400 s.
    evs += [wlan("HOST-S", 1, 0, 8001, "NetS"), *down_up("HOST-S", 10, 1000, 1600), wlan("HOST-S", 2, 2000, 8003, "NetS")]
    # U: unexpected shutdown (no shutdown record; 41 + 6008 at the next start).
    evs += [wlan("HOST-U", 1, 0, 8001, "NetU"), sysev("HOST-U", 10, 1600, 12, KG, {"StartTime": at(1600)}),
            sysev("HOST-U", 11, 1601, 41, KP), sysev("HOST-U", 12, 1602, 6008, "EventLog"),
            wlan("HOST-U", 2, 2000, 8003, "NetU")]
    # M: two restarts: 3000 - (500 + 300) = 2200 s.
    evs += [wlan("HOST-M", 1, 0, 8001, "NetM"), *down_up("HOST-M", 10, 1000, 1500),
            *down_up("HOST-M", 20, 2000, 2300), wlan("HOST-M", 2, 3000, 8003, "NetM")]
    # O: open session, clean restart after it: ended by the shutdown at the latest.
    evs += [wlan("HOST-O", 1, 0, 8001, "NetO"), *down_up("HOST-O", 10, 1000, 1600)]
    # W: startup record an hour after its StartTime: startup time uncertain.
    evs += [wlan("HOST-W", 1, 0, 8001, "NetW"), *down_up("HOST-W", 10, 1000, 5200, up_start=1600),
            wlan("HOST-W", 2, 9000, 8003, "NetW")]
    # P: the only shutdown record is before the connect: no measurable downtime.
    evs += [sysev("HOST-P", 10, 50, 6006, "EventLog"), wlan("HOST-P", 1, 100, 8001, "NetP"),
            sysev("HOST-P", 11, 1600, 12, KG, {"StartTime": at(1600)}), wlan("HOST-P", 2, 2000, 8003, "NetP")]
    # C: the same restart in four copies of the logs, plus Security 4608 five
    # seconds after Kernel-General 12 (one startup, several records).  The
    # startup is taken as its latest record (never less downtime): 2000 - 605.
    for cp in range(4):
        evs += [dict(e, source_file=e["source_file"].replace(".evtx", f" - Copy ({cp}).evtx"))
                for e in down_up("HOST-C", 10, 1000, 1600)]
        evs.append(dict(sysev("HOST-C", 20, 1605, 4608, "Microsoft-Windows-Security-Auditing",
                              channel="Security"), source_file=rf"C:\c\HOST-C-Security - Copy ({cp}).evtx"))
    evs += [wlan("HOST-C", 1, 0, 8001, "NetC"), wlan("HOST-C", 2, 2000, 8003, "NetC")]
    return evs


def grade(tag, sessions):
    s = {x["ssid"]: x for x in sessions}
    show = lambda x: str(x and (x["duration"], x["duration_secs"], x["anomaly_flags"], x.get("notes", "")[:160]))  # noqa: E731
    a = s.get("NetS")
    check(f"{tag}: clean restart: 1400 s, marked '(downtime subtracted)'",
          a is not None and a["duration_secs"] == 1400.0 and a["duration"].endswith("(downtime subtracted)")
          and "downtime_subtracted" in a["anomaly_flags"], show(a))
    n = (a or {}).get("notes", "")
    check(f"{tag}: Notes give the downtime, every part, and say the after-restart part is not proven",
          "10m 00s subtracted" in n and "16m 40s before the shutdown" in n and "10m 00s down" in n
          and "6m 40s after the restart (not proven" in n and "(Kernel-General 13) to" in n, n[:300])
    u = s.get("NetU")
    check(f"{tag}: unexpected shutdown: no duration, Notes say why",
          u is not None and u["duration_secs"] < 0 and "unexpected" in u.get("notes", ""), show(u))
    m = s.get("NetM")
    check(f"{tag}: two restarts: both downtimes subtracted (2200 s)",
          m is not None and m["duration_secs"] == 2200.0 and "13m 20s subtracted" in m.get("notes", ""), show(m))
    o = s.get("NetO")
    check(f"{tag}: open session then restart: not Active; Notes bound it by the shutdown",
          o is not None and o["duration_secs"] < 0 and o["duration"] != "Active"
          and "until the shutdown at the latest (16m 40s)" in o.get("notes", ""), show(o))
    w = s.get("NetW")
    check(f"{tag}: startup time uncertain: no duration, Notes say why",
          w is not None and w["duration_secs"] < 0 and "startup time is uncertain" in w.get("notes", ""), show(w))
    c = s.get("NetC")
    check(f"{tag}: copies of the logs and a 4608 beside the 12 are one restart (1395 s)",
          c is not None and c["duration_secs"] == 1395.0
          and "(Kernel-General 12 + Security 4608)" in c.get("notes", ""), show(c))
    p = s.get("NetP")
    check(f"{tag}: shutdown logged only before the connect: no duration",
          p is not None and p["duration_secs"] < 0 and "not after the session's start" in p.get("notes", ""), show(p))


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
    worker.run()
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
