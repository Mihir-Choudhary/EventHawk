"""Time the host spent asleep during a WiFi or remote session is subtracted, and the Notes say so.

User (2026-11-06): "sleep and resume should be counted as resumed like downtime
for Wi-Fi and remote assistance ... it should be mentioned in the notes properly".

Expected, both modes (Normal builder; Juggernaut fetch + builder):
  * a sleep wholly inside a session (Power-Troubleshooter 1 SleepTime -> WakeTime,
    or Kernel-Power 566's sleep session, or Kernel-Power 42 to a "doze to
    hibernate") is subtracted, marked
    "(downtime subtracted)", and Notes name the sleep, its times and source, and
    say the time after waking is not proven;
  * a disconnect logged as the host goes to sleep (overlap <= 60 s) changes nothing;
  * a disconnect logged inside the sleep (Windows logs it on waking) means the
    connection ended by the sleep at the latest: the time asleep is subtracted and
    the Notes say the disconnect was logged while asleep or waking;
  * a connect logged deep inside a sleep contradicts itself: no duration;
  * copies of the logs count each sleep once; a sleep and a restart in one session
    are both subtracted.
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
from test_wifi_boot_barrier import wlan                             # noqa: E402
from test_wifi_downtime import sysev, at, down_up, KP               # noqa: E402
from test_ra_downtime import rdp                                    # noqa: E402

CHECKS = []
PT = "Microsoft-Windows-Power-Troubleshooter"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def sleep_pt(host, rid, a, b, copy=""):
    e = sysev(host, rid, b + 1, 1, PT, {"SleepTime": at(a), "WakeTime": at(b), "TargetState": "4"})
    if copy:
        e["source_file"] = e["source_file"].replace(".evtx", f" - Copy{copy}.evtx")
    return e


def dataset():
    evs = []
    # SL: connect 0, asleep 1000 -> 1600 (Power-Troubleshooter 1), disconnect 2000: 1400 s.
    evs += [wlan("HOST-SL", 1, 0, 8001, "NetSL"), sleep_pt("HOST-SL", 10, 1000, 1600),
            wlan("HOST-SL", 2, 2000, 8003, "NetSL")]
    # SK: Kernel-Power 42 at 1000, 107 at 1002 (written with the pre-sleep clock,
    # as on the test logs), nothing else: the wake time is unknown, so no duration
    # (it used to subtract the 2 s from 42 to 107).
    evs += [wlan("HOST-SK", 1, 0, 8001, "NetSK"), sysev("HOST-SK", 10, 1000, 42, KP, {"TargetState": "4"}),
            sysev("HOST-SK", 11, 1002, 107, KP, {"TargetState": "4"}), wlan("HOST-SK", 2, 2000, 8003, "NetSK")]
    # SM: Kernel-Power 566 says a sleep session of 600 s ended at 1600: 1400 s.
    evs += [wlan("HOST-SM", 1, 0, 8001, "NetSM"), sysev("HOST-SM", 10, 1000, 42, KP, {"TargetState": "4"}),
            sysev("HOST-SM", 11, 1600, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "600000000", "Reason": "20"}),
            wlan("HOST-SM", 2, 2000, 8003, "NetSM")]
    # SP (Codex SA-3): Power-Troubleshooter 1 says asleep 1300 -> 1600; a Kernel-Power 566
    # for the same sleep says it began at 1000 (its start is derived from the clock).
    # One physical sleep: the Power-Troubleshooter times win (2000 - 300 = 1700 s),
    # and the Notes say the two disagree.  The union subtracted 600 s.
    evs += [wlan("HOST-SP", 1, 0, 8001, "NetSP"),
            sysev("HOST-SP", 10, 1601, 1, PT, {"SleepTime": at(1300), "WakeTime": at(1600), "TargetState": "4",
                                              "WakeSourceType": "1"}),
            sysev("HOST-SP", 11, 1600, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "600000000", "Reason": "20"}),
            wlan("HOST-SP", 2, 2000, 8003, "NetSP")]
    # SB: sleep at 1000 (42), hibernated 1300 -> 1600 (Power-Troubleshooter 1), no doze record,
    # and Kernel-Power 566 confirms one sleep session 1000 -> 1600: 1400 s, no conflict.
    evs += [wlan("HOST-SB", 1, 0, 8001, "NetSB"), sysev("HOST-SB", 10, 1000, 42, KP, {"TargetState": "4"}),
            sysev("HOST-SB", 11, 1601, 1, PT, {"SleepTime": at(1300), "WakeTime": at(1600), "TargetState": "5",
                                              "WakeSourceType": "1"}),
            sysev("HOST-SB", 12, 1600, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "600000000", "Reason": "20"}),
            wlan("HOST-SB", 2, 2000, 8003, "NetSB")]
    # Codex SA3-R1: 42 at 1000, doze at 1300, PT hibernation 1330 -> 1600, a 566 sleep
    # session 1000 -> 1600; session 900 -> 1700.  The doze closes the sleep part, so
    # 1300 -> 1330 was awake: down 300 + 270, connected 800 - 570 = 230 s.
    evs += [wlan("HOST-SG", 1, 900, 8001, "NetSG"), sysev("HOST-SG", 10, 1000, 42, KP, {"TargetState": "4"}),
            sysev("HOST-SG", 11, 1301, 1, PT, {"SleepTime": at(1300), "WakeTime": at(1300), "TargetState": "0",
                                              "WakeSourceType": "3"}),
            sysev("HOST-SG", 12, 1601, 1, PT, {"SleepTime": at(1330), "WakeTime": at(1600), "TargetState": "5",
                                              "WakeSourceType": "1"}),
            sysev("HOST-SG", 13, 1600, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "600000000", "Reason": "20"}),
            wlan("HOST-SG", 2, 1700, 8003, "NetSG")]
    # Codex SA3-R2: 42 at 1000, PT 1330 -> 1600, a 566 1000 -> 1600 (explained by the 42)
    # and a second 566 880 -> 1600 that nothing explains: 200 s, and the Notes disclose it.
    evs += [wlan("HOST-SX", 1, 900, 8001, "NetSX"), sysev("HOST-SX", 10, 1000, 42, KP, {"TargetState": "4"}),
            sysev("HOST-SX", 11, 1601, 1, PT, {"SleepTime": at(1330), "WakeTime": at(1600), "TargetState": "5",
                                              "WakeSourceType": "1"}),
            sysev("HOST-SX", 12, 1600, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "600000000", "Reason": "20"}),
            sysev("HOST-SX", 13, 1600, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "720000000", "Reason": "1"}),
            wlan("HOST-SX", 2, 1700, 8003, "NetSX")]
    # Codex SA3-R2 (wake): PT 1000 -> 1600, a 566 for it ends 20 s later: PT used (200 s), disclosed.
    evs += [wlan("HOST-SW", 1, 900, 8001, "NetSW"),
            sysev("HOST-SW", 10, 1601, 1, PT, {"SleepTime": at(1000), "WakeTime": at(1600), "TargetState": "4",
                                              "WakeSourceType": "1"}),
            sysev("HOST-SW", 11, 1620, 566, KP, {"PreviousSessionType": "3", "NextSessionType": "1",
                                               "PreviousSessionDurationInUs": "620000000", "Reason": "20"}),
            wlan("HOST-SW", 2, 1700, 8003, "NetSW")]
    # SD: sleep at 1000 (42), doze to hibernate at 1300, hibernated 1300 -> 1600: 1400 s.
    evs += [wlan("HOST-SD", 1, 0, 8001, "NetSD"), sysev("HOST-SD", 10, 1000, 42, KP, {"TargetState": "4"}),
            sysev("HOST-SD", 11, 1301, 1, PT, {"SleepTime": at(1300), "WakeTime": at(1300), "TargetState": "0",
                                              "WakeSourceType": "3"}),
            sysev("HOST-SD", 12, 1601, 1, PT, {"SleepTime": at(1300), "WakeTime": at(1600), "TargetState": "5",
                                              "WakeSourceType": "1"}),
            wlan("HOST-SD", 2, 2000, 8003, "NetSD")]
    # ST: disconnect logged 1 s after going to sleep: unchanged (1001 s), no note.
    evs += [wlan("HOST-ST", 1, 0, 8001, "NetST"), sleep_pt("HOST-ST", 10, 1000, 1600),
            wlan("HOST-ST", 2, 1001, 8003, "NetST")]
    # SU: asleep 1000 -> 5000, disconnect logged at 2000 (inside the sleep): connected 1000 s.
    evs += [wlan("HOST-SU", 1, 0, 8001, "NetSU"), sleep_pt("HOST-SU", 10, 1000, 5000),
            wlan("HOST-SU", 2, 2000, 8003, "NetSU")]
    # SV: asleep 0 -> 3000, connect logged at 1000 (deep inside the sleep): no duration.
    evs += [sleep_pt("HOST-SV", 10, 0, 3000), wlan("HOST-SV", 1, 1000, 8001, "NetSV"),
            wlan("HOST-SV", 2, 4000, 8003, "NetSV")]
    # SC: the same sleep in three copies of the log: once (1400 s).
    evs += [wlan("HOST-SC", 1, 0, 8001, "NetSC"), wlan("HOST-SC", 2, 2000, 8003, "NetSC")]
    evs += [sleep_pt("HOST-SC", 10, 1000, 1600, copy=f" ({c})") for c in range(3)]
    # SR: asleep 500 -> 700, then a clean restart 1000 -> 1600: 2000 - 200 - 600 = 1200 s.
    evs += [wlan("HOST-SR", 1, 0, 8001, "NetSR"), sleep_pt("HOST-SR", 10, 500, 700),
            *down_up("HOST-SR", 20, 1000, 1600), wlan("HOST-SR", 2, 2000, 8003, "NetSR")]
    # RDP outbound on HOST-RS: connected 20, asleep 1000 -> 1600, disconnect 2000: 1380 s.
    evs += [rdp("HOST-RS", 1, 0, 1024), rdp("HOST-RS", 2, 20, 1025), sleep_pt("HOST-RS", 10, 1000, 1600),
            rdp("HOST-RS", 3, 2000, 1026)]
    return evs


def grade(tag, wifi, ra):
    s = {x["ssid"]: x for x in wifi}
    show = lambda x: str(x and (x["duration"], x["duration_secs"], x["anomaly_flags"], x.get("notes", "")[:200]))  # noqa: E731
    a = s.get("NetSL")
    n = (a or {}).get("notes", "")
    check(f"{tag}: sleep inside (Power-Troubleshooter 1): 1400 s, marked",
          a is not None and a["duration_secs"] == 1400.0 and a["duration"].endswith("(downtime subtracted)"), show(a))
    check(f"{tag}: Notes name the sleep, its source and times, and the unproven part after waking",
          "10m 00s subtracted" in n and "asleep" in n and "Power-Troubleshooter 1" in n
          and "10m 00s asleep (subtracted)" in n and "after waking (not proven" in n, n[:300])
    k = s.get("NetSK")
    check(f"{tag}: a sleep with no logged wake time (only 42, 107): no duration, Notes say why",
          k is not None and k["duration_secs"] < 0 and "wake time is not logged" in k.get("notes", "")
          and "107" in k.get("notes", ""), show(k))
    m = s.get("NetSM")
    check(f"{tag}: sleep from Kernel-Power 566's sleep session: 1400 s, source named",
          m is not None and m["duration_secs"] == 1400.0 and "Kernel-Power 566" in m.get("notes", ""), show(m))
    p_ = s.get("NetSP")
    check(f"{tag}: Power-Troubleshooter and a disagreeing 566 for one sleep: PT wins (1700 s), Notes say so",
          p_ is not None and p_["duration_secs"] == 1700.0 and "disagree" in p_.get("notes", ""), show(p_))
    b_ = s.get("NetSB")
    check(f"{tag}: sleep then hibernation with no doze record, 42 and 566 agree: 1400 s, no conflict",
          b_ is not None and b_["duration_secs"] == 1400.0 and "disagree" not in b_.get("notes", ""), show(b_))
    g = s.get("NetSG")
    check(f"{tag}: a doze before the hibernation closes the sleep part (230 s, the awake 30 s kept)",
          g is not None and g["duration_secs"] == 230.0, show(g))
    x = s.get("NetSX")
    check(f"{tag}: one 566 explained by the 42, another unexplained: 200 s and the disagreement disclosed",
          x is not None and x["duration_secs"] == 200.0 and "disagree" in x.get("notes", ""), show(x))
    wk = s.get("NetSW")
    check(f"{tag}: a 566 whose wake differs from Power-Troubleshooter's: PT used (200 s), disclosed",
          wk is not None and wk["duration_secs"] == 200.0 and "disagree" in wk.get("notes", ""), show(wk))
    d = s.get("NetSD")
    check(f"{tag}: sleep then hibernation (42 to the doze, then Power-Troubleshooter): 1400 s",
          d is not None and d["duration_secs"] == 1400.0 and "doze to hibernate" in d.get("notes", ""), show(d))
    t = s.get("NetST")
    check(f"{tag}: disconnect logged as the host goes to sleep: unchanged, no note",
          t is not None and t["duration_secs"] == 1001.0 and not t.get("notes"), show(t))
    u = s.get("NetSU")
    check(f"{tag}: disconnect logged inside the sleep: connected until the sleep (1000 s), Notes say so",
          u is not None and u["duration_secs"] == 1000.0
          and "the disconnect was logged" in u.get("notes", ""), show(u))
    v = s.get("NetSV")
    check(f"{tag}: connect logged deep inside a sleep: no duration, Notes say why",
          v is not None and v["duration_secs"] < 0 and "asleep" in v.get("notes", ""), show(v))
    c = s.get("NetSC")
    check(f"{tag}: copies of the log count the sleep once (1400 s)", c is not None and c["duration_secs"] == 1400.0, show(c))
    r = s.get("NetSR")
    check(f"{tag}: a sleep and a restart in one session: both subtracted (1200 s)",
          r is not None and r["duration_secs"] == 1200.0 and "asleep" in r.get("notes", "")
          and "down" in r.get("notes", ""), show(r))
    o = next((x for x in ra if x["type"] == "RDP (Outbound)" and x["computer"] == "HOST-RS"), None)
    check(f"{tag}: outbound RDP across a sleep: 1380 s, marked, Notes",
          o is not None and o["duration_secs"] == 1380.0 and "DOWNTIME_SUBTRACTED" in o["flags"]
          and "asleep" in o.get("notes", ""),
          str(o and (o["duration"], o["duration_secs"], o["flags"], o.get("notes", "")[:150])))


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = dataset()
    grade("Normal", mw._WifiHistoryDialog._build_sessions(evs), mw._RemoteAssistanceDialog._build_sessions(evs))
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, evs)
    got, got2 = [], []
    wk = mw._WifiJMFetchWorker(w._hw_db_path)
    wk.finished.connect(lambda e, t: got.append(e))
    wk.run()
    rk = mw._RemoteAssistJMFetchWorker(w._hw_db_path)
    rk.finished.connect(lambda e, t: got2.append(e))
    rk.run()
    T.pump(100)
    grade("JM", mw._WifiHistoryDialog._build_sessions(got[0] if got else []),
          mw._RemoteAssistanceDialog._build_sessions(got2[0] if got2 else []))
    T.teardown(w, True, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
