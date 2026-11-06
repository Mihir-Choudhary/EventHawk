"""System Activity: on / screen / sleep / hibernate / shut down / locked periods (user request 2026-11-07).

A synthetic machine shaped like a real test-log sequence: a start (fast startup),
screen on, screen off, idle sleep that turns into hibernation, woken by the power
button (Kernel-Power 107 written with the old clock), screen sessions, a lock,
a clean shutdown, a start, a sleep with no logged wake, then a crash reported
at the next start.  Every expected period below is worked out by hand from the
events, not from the code.  Also: a copy of the log counts once, and
Juggernaut's timestamp form ("YYYY-MM-DD HH:MM:SS.ffffff") gives the same.
Synthetic data only.
"""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


KG, KP = "Microsoft-Windows-Kernel-General", "Microsoft-Windows-Kernel-Power"
PT, KB = "Microsoft-Windows-Power-Troubleshooter", "Microsoft-Windows-Kernel-Boot"
SEC = "Microsoft-Windows-Security-Auditing"
N = [0]


def ev(ts, prov, eid, chan="System", **data):
    N[0] += 1
    return {"timestamp": ts, "provider": prov, "event_id": eid, "channel": chan, "computer": "PC1",
            "source_file": "C:\\logs\\System.evtx", "record_id": N[0], "event_data": data}


def s566(ts, prev, nxt, dur_s, reason):
    return ev(ts, KP, 566, PreviousSessionType=str(prev), NextSessionType=str(nxt),
              PreviousSessionDurationInUs=str(int(round(dur_s * 1_000_000))), Reason=str(reason))


def scenario():
    return [
        ev("2025-11-12T19:16:59.000000Z", "User32", 1074,
           Data={"#text": ["C:\\Windows\\System32\\winlogon.exe (PC1)", "PC1", "Other (Unplanned)",
                           "0x500ff", "power off", "", "PC1\\alice"]}),
        ev("2025-11-12T19:17:04.000000Z", KG, 13, StopTime="2025-11-12T19:17:04.000000Z"),
        ev("2025-11-12T19:17:04.000000Z", "EventLog", 6006),
        ev("2025-11-13T13:23:23.000000Z", KG, 12, StartTime="2025-11-13T13:23:22.500000Z"),
        ev("2025-11-13T13:23:30.000000Z", KB, 27, BootType="1"),
        s566("2025-11-13T13:53:01.000000Z", 0, 1, 1778.5, 12),
        s566("2025-11-13T14:03:06.000000Z", 1, 3, 605, 20),
        ev("2025-11-13T14:03:07.000000Z", KP, 42, TargetState="4", Reason="7"),
        ev("2025-11-13T14:03:09.000000Z", KP, 107, TargetState="4"),
        ev("2025-11-13T14:18:10.000000Z", PT, 1, SleepTime="2025-11-13T14:18:09.963981Z",
           WakeTime="2025-11-13T14:18:09.963981Z", TargetState="0", WakeSourceType="3"),
        ev("2025-11-13T14:18:12.000000Z", KP, 42, TargetState="5", Reason="6"),
        ev("2025-11-13T17:34:17.141136Z", PT, 1, SleepTime="2025-11-13T14:18:09.963981Z",
           WakeTime="2025-11-13T17:34:17.141136Z", TargetState="5", WakeSourceType="1"),
        s566("2025-11-13T17:34:17.141136Z", 3, 1, 12671.177155, 20),
        s566("2025-11-13T17:34:18.000000Z", 1, 0, 0.858864, 1),
        ev("2025-11-13T18:00:00.000000Z", SEC, 4800, "Security", TargetUserName="alice", TargetLogonId="0x1"),
        ev("2025-11-13T18:10:00.000000Z", SEC, 4801, "Security", TargetUserName="alice", TargetLogonId="0x1"),
        s566("2025-11-13T19:30:12.000000Z", 0, 1, 6954, 12),
        s566("2025-11-13T19:30:59.000000Z", 1, 0, 47, 31),
        ev("2025-11-13T19:35:35.000000Z", KP, 109, ShutdownActionType="6", ShutdownReason="5"),
        ev("2025-11-13T19:35:37.000000Z", KG, 13, StopTime="2025-11-13T19:35:37.000000Z"),
        ev("2025-11-14T08:00:00.000000Z", KG, 12, StartTime="2025-11-14T08:00:00.000000Z"),
        ev("2025-11-14T08:30:00.000000Z", KP, 42, TargetState="4", Reason="0"),
        ev("2025-11-14T08:30:02.000000Z", KP, 107, TargetState="4"),
        ev("2025-11-14T09:00:00.000000Z", KG, 12, StartTime="2025-11-14T09:00:00.000000Z"),
        ev("2025-11-14T09:00:15.000000Z", "EventLog", 6008,
           Data={"#text": ["8:45:10 AM", "\u200e11/\u200e14/\u200e2025", "", "", "17", "", ""]}),
        ev("2025-11-14T09:00:20.000000Z", KP, 41),
    ]


def D(s):
    return datetime.fromisoformat(s)


EXPECT_POWER = [
    ("Shut down", D("2025-11-12 19:17:04"), D("2025-11-13 13:23:22.5"), "Kernel-General 13", "Kernel-General 12"),
    ("On", D("2025-11-13 13:23:22.5"), D("2025-11-13 14:03:06"), "Kernel-General 12", "Kernel-Power 566"),
    ("Sleep", D("2025-11-13 14:03:06"), D("2025-11-13 14:18:09.963981"), "Kernel-Power 566",
     "Power-Troubleshooter 1 (S4 Doze to Hibernate)"),
    ("Hibernate", D("2025-11-13 14:18:09.963981"), D("2025-11-13 17:34:17.141136"),
     "Power-Troubleshooter 1 (SleepTime)", "Power-Troubleshooter 1 (WakeTime)"),
    ("On", D("2025-11-13 17:34:17.141136"), D("2025-11-13 19:35:37"), "Power-Troubleshooter 1 (WakeTime)",
     "Kernel-General 13"),
    ("Shut down", D("2025-11-13 19:35:37"), D("2025-11-14 08:00:00"), "Kernel-General 13", "Kernel-General 12"),
    ("On", D("2025-11-14 08:00:00"), D("2025-11-14 08:30:00"), "Kernel-General 12", "Kernel-Power 42"),
    ("Sleep", D("2025-11-14 08:30:00"), None, "Kernel-Power 42", "Unavailable"),
    ("Off (unexpected shutdown)", None, D("2025-11-14 09:00:00"), "Unavailable", "Kernel-General 12"),
    ("On", D("2025-11-14 09:00:00"), None, "Kernel-General 12", "Unavailable"),
]
EXPECT_SCREEN = [
    ("Screen on (session type 0)", D("2025-11-13 13:23:22.5"), D("2025-11-13 13:53:01")),
    ("Screen off (session type 1)", D("2025-11-13 13:53:01"), D("2025-11-13 14:03:06")),
    ("Screen off (session type 1)", D("2025-11-13 17:34:17.141136"), D("2025-11-13 17:34:18")),
    ("Screen on (session type 0)", D("2025-11-13 17:34:18"), D("2025-11-13 19:30:12")),
    ("Screen off (session type 1)", D("2025-11-13 19:30:12"), D("2025-11-13 19:30:59")),
    ("Screen on (session type 0)", D("2025-11-13 19:30:59"), D("2025-11-13 19:35:37")),
]


def layer(res, name, cols):
    return [tuple(r[c] for c in cols) for r in res["rows"] if r["layer"] == name]


def main() -> int:
    from evtx_tool.analysis import system_activity as SA
    evs = scenario()
    res = SA.build(evs)
    check("one computer", res["hosts"] == ["PC1"], str(res["hosts"]))
    got = layer(res, "Power", ("state", "start", "end", "started_by", "ended_by"))
    check("power periods: on / sleep / hibernate / shut down / unexpected, exact times and evidence",
          got == EXPECT_POWER, "\n        " + "\n        ".join(map(str, got)))
    got_s = layer(res, "Screen", ("state", "start", "end"))
    check("screen periods from Kernel-Power 566 (sleep excluded, last one ends at the shutdown)",
          got_s == EXPECT_SCREEN, "\n        " + "\n        ".join(map(str, got_s)))
    lock = layer(res, "Lock", ("state", "start", "end"))
    check("locked 18:00 to 18:10", lock == [("Locked", D("2025-11-13 18:00:00"), D("2025-11-13 18:10:00"))],
          str(lock))
    rows = {(r["layer"], r["state"], r["start"]): r for r in res["rows"]}
    sl = rows[("Power", "Sleep", D("2025-11-14 08:30:00"))]
    check("a sleep with no wake time says why and does not use Kernel-Power 107's time",
          sl["end"] is None and "107" in sl["notes"] and "before the sleep" in sl["notes"], sl["notes"])
    ux = rows[("Power", "Off (unexpected shutdown)", None)]
    check("an unexpected shutdown shows Windows' own text, start Unavailable",
          '8:45:10 AM 11/14/2025' in ux["notes"] and ux["start"] is None, ux["notes"])
    first = rows[("Power", "Shut down", D("2025-11-12 19:17:04"))]
    check("the fast-startup boot type is noted on the start", "fast startup" in first["notes"], first["notes"])
    hib = rows[("Power", "Hibernate", D("2025-11-13 14:18:09.963981"))]
    check("hibernation notes the wake source", "Power Button" in hib["notes"], hib["notes"])
    check("durations are exact (Hibernate 3h 16m 07.177155s)",
          fmt(hib["duration"]) == "3h 16m 07.177155s", fmt(hib["duration"]))
    pts = {p["what"]: p for p in res["points"]}
    check("moments: who requested the shutdown (User32 1074)",
          "winlogon.exe" in pts["Shutdown or restart requested"]["details"]
          and "power off" in pts["Shutdown or restart requested"]["details"])
    check("moments: Kernel-Power 109 action and reason as Windows names them",
          "Shutdown (power off) (6)" in pts["Shutdown transition started"]["details"]
          and "Kernel API (5)" in pts["Shutdown transition started"]["details"])
    check("moments: sleep reason as Windows names it", any("Button or Lid (0)" in p["details"]
                                                          for p in res["points"] if p["what"] == "Going to sleep"))
    check("every row and moment carries its evidence event for the Around pivot",
          all((r["start"] is None or r["start_ev"] is not None) for r in res["rows"])
          and all(p["ev"] is not None for p in res["points"]))

    # Windows' clock correction on waking is stamped with the stopped clock,
    # inside the sleep: it must not void the hibernation's length (it did, on
    # every Hibernate row of the test logs).
    corr = ev("2025-11-13T14:25:00.000000Z", KG, 1, OldTime="2025-11-13T14:25:00.000000Z",
              NewTime="2025-11-13T17:34:19.000000Z")
    hib2 = next(r for r in SA.build(evs + [corr])["rows"] if r["state"] == "Hibernate")
    check("a clock correction stamped inside a sleep (the resume) does not void its length",
          hib2["duration"] is not None and "length Unavailable" not in hib2["notes"], hib2["notes"])

    copy = [dict(e, source_file="C:\\logs\\System - Copy.evtx", record_id=e["record_id"] + 1000) for e in evs]
    res2 = SA.build(evs + copy)
    check("a copy of the same log counts once", len(res2["rows"]) == len(res["rows"])
          and len(res2["points"]) == len(res["points"]), f"{len(res2['rows'])} vs {len(res['rows'])}")
    jm = [dict(e, timestamp=e["timestamp"].replace("T", " ").replace("Z", "")) for e in evs]
    res3 = SA.build(jm)
    key = ("layer", "state", "start", "end", "started_by", "ended_by", "notes")
    check("Juggernaut's timestamp form gives the same periods",
          [tuple(r[k] for k in key) for r in res3["rows"]] == [tuple(r[k] for k in key) for r in res["rows"]])
    check("relevant(): unrelated events are ignored",
          not SA.relevant(ev("2025-11-13T10:00:00Z", SEC, 4624, "Security", LogonType="3"))
          and SA.relevant(ev("2025-11-13T10:00:00Z", SEC, 4624, "Security", LogonType="7"))
          and not SA.relevant(ev("2025-11-13T10:00:00Z", "Microsoft-Windows-Sysmon", 12)))

    # Cases the real test logs exposed (2026-11-07), on a second machine.
    def pc2(ts, prov, eid, chan="System", **data):
        return dict(ev(ts, prov, eid, chan, **data), computer="PC2")
    evs2 = [
        # Woke from hibernation before any logged start, then crashed.
        pc2("2025-01-01T12:00:01Z", PT, 1, SleepTime="2025-01-01T10:00:00Z", WakeTime="2025-01-01T12:00:00Z",
            TargetState="5", WakeSourceType="1"),
        pc2("2025-01-01T12:00:05Z", KP, 566, PreviousSessionType="1", NextSessionType="0",
            PreviousSessionDurationInUs="1000000", Reason="1"),
        pc2("2025-01-01T13:00:00Z", KG, 12, StartTime="2025-01-01T13:00:00Z"),
        pc2("2025-01-01T13:00:10Z", KP, 41),
        # Screen: the second 566 continues the first; its length is 10 s off.
        s566("2025-01-01T13:10:00Z", 0, 1, 600, 12) | {"computer": "PC2"},
        s566("2025-01-01T13:20:00Z", 1, 0, 590, 32) | {"computer": "PC2"},
        # The clock moved +2h inside the on-period.
        pc2("2025-01-01T13:30:00Z", KG, 1, OldTime="2025-01-01T13:30:00Z", NewTime="2025-01-01T15:30:00Z"),
        pc2("2025-01-01T16:00:00Z", KG, 13, StopTime="2025-01-01T16:00:00Z"),
        # Two starts with no shutdown between: the first on-period ends before the second start.
        pc2("2025-01-01T17:00:00Z", KG, 12, StartTime="2025-01-01T17:00:00Z"),
        pc2("2025-01-01T18:00:00Z", KG, 12, StartTime="2025-01-01T18:00:00Z"),
        # A sleep the events place across a start: both kept, both flagged.
        pc2("2025-01-01T19:00:01Z", PT, 1, SleepTime="2025-01-01T17:30:00Z", WakeTime="2025-01-01T19:00:00Z",
            TargetState="4", WakeSourceType="1"),
    ]
    r2 = [r for r in SA.build(evs2)["rows"] if r["host"] == "PC2"]
    pw = [(r["state"], r["start"], r["end"]) for r in r2 if r["layer"] == "Power"]
    check("PC2: a wake before the first logged start opens an On period that ends Unavailable",
          ("On", D("2025-01-01 12:00:00"), None) in pw
          and any(r["state"] == "On" and r["start"] == D("2025-01-01 12:00:00")
                  and "before the start at 2025-01-01 13:00:00" in r["notes"] for r in r2), str(pw))
    check("PC2: two starts with no shutdown between: no duplicate or unbounded On periods",
          len(pw) == len(set(pw)) and ("On", D("2025-01-01 17:00:00"), D("2025-01-01 17:30:00")) in pw
          and ("On", D("2025-01-01 18:00:00"), None) in pw
          and not any(s == "On" and a is not None and a >= D("2025-01-01 18:00:00") and a != D("2025-01-01 18:00:00")
                      for s, a, b in pw), str(pw))
    on13 = next(r for r in r2 if r["state"] == "On" and r["start"] == D("2025-01-01 13:00:00"))
    check("PC2: a clock change inside a period makes its length Unavailable and says why",
          on13["duration"] is None and "changed by +2h 00m 00s" in on13["notes"], on13["notes"])
    sc = [(r["state"], r["start"], r["end"], r["notes"]) for r in r2 if r["layer"] == "Screen"]
    off = next(s for s in sc if s[0].startswith("Screen off") and s[2] == D("2025-01-01 13:20:00"))
    check("PC2: consecutive 566 records are the boundaries; a length mismatch is noted",
          off[1] == D("2025-01-01 13:10:00") and "10s different" in off[3], str(off))
    trail = next(s for s in sc if s[1] == D("2025-01-01 12:00:05"))
    check("PC2: a screen period with no closing record ends Unavailable before the crash's start",
          trail[2] is None and "before the start at 2025-01-01 13:00:00" in trail[3], str(trail))
    flagged = [r for r in r2 if "the logged events disagree" in r["notes"]]
    check("PC2: a sleep the events place across a start is kept and flagged",
          any(r["state"] == "Sleep" and "a start is logged at 2025-01-01 18:00:00" in r["notes"] for r in flagged),
          str([(r["state"], r["start"]) for r in flagged]))
    srt = sorted((r for r in r2 if r["layer"] == "Screen" and r["start"] and r["end"]), key=lambda r: r["start"])
    check("PC2: screen periods never overlap", all(b["start"] >= a["end"] for a, b in zip(srt, srt[1:])))

    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


def fmt(td):
    from evtx_tool.analysis.host_power import fmt_secs
    return fmt_secs(td) if td is not None else None


if __name__ == "__main__":
    sys.exit(main())
