"""A Remote Assistance / RDP session across a restart of its host: downtime subtracted, or no duration.

User request (2026-11-05): "The same thing, remote assistance if the system
was shut down in between".  Outbound RDP (1025 -> 1026) and Classic RA rows had
no restart barrier at all: a session spanning a shutdown read as one long
connection.  Expected, both modes, as for WiFi (decision "Both"): across a
clean restart the Duration is the span minus the downtime, marked
"(downtime subtracted)", flag DOWNTIME_SUBTRACTED, Notes with every part and
the after-restart part "not proven"; across an unexpected shutdown no
duration, flag REBOOT_BETWEEN, Notes say why; no restart: unchanged.
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
from test_wifi_downtime import down_up, sysev, KG, KP, at           # noqa: E402

CHECKS = []
CH = "Microsoft-Windows-TerminalServices-RDPClient/Operational"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rdp(host, rid, secs, eid):
    e = T.ev(rf"C:\c\{host}-RDPClient.evtx", rid, host, T.T0 + timedelta(seconds=secs), eid,
             "Microsoft-Windows-TerminalServices-ClientActiveXCore", {"Value": "SYNTH-DEST"})
    e["channel"] = CH
    return e


def session(host):
    return [rdp(host, 1, 0, 1024), rdp(host, 2, 20, 1025), rdp(host, 3, 2000, 1026)]


def dataset():
    return (session("HOST-R") + down_up("HOST-R", 10, 1000, 1600)
            + session("HOST-X") + [sysev("HOST-X", 10, 1600, 12, KG, {"StartTime": at(1600)}),
                                   sysev("HOST-X", 11, 1601, 41, KP)]
            + session("HOST-N"))


def grade(tag, rows):
    s = {r["computer"]: r for r in rows if r["type"] == "RDP (Outbound)"}
    show = lambda x: str(x and (x["duration"], x["duration_secs"], x["flags"], x.get("notes", "")[:150]))  # noqa: E731
    r = s.get("HOST-R")
    check(f"{tag}: outbound RDP across a clean restart: 1380 s, marked",
          r is not None and r["duration_secs"] == 1380.0 and r["duration"].endswith("(downtime subtracted)")
          and "DOWNTIME_SUBTRACTED" in r["flags"], show(r))
    check(f"{tag}: Notes give the downtime and say the after-restart part is not proven",
          r is not None and "10m 00s subtracted" in r.get("notes", "")
          and "6m 40s after the restart (not proven" in r.get("notes", ""), show(r))
    x = s.get("HOST-X")
    check(f"{tag}: across an unexpected shutdown: no duration, Notes say why",
          x is not None and x["duration_secs"] < 0 and "REBOOT_BETWEEN" in x["flags"]
          and "unexpected" in x.get("notes", ""), show(x))
    n = s.get("HOST-N")
    check(f"{tag}: no restart: duration unchanged (1980 s), no note",
          n is not None and n["duration_secs"] == 1980.0 and not n.get("notes"), show(n))


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = dataset()
    grade("Normal", mw._RemoteAssistanceDialog._build_sessions(evs))
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, evs)
    got = []
    worker = mw._RemoteAssistJMFetchWorker(w._hw_db_path)
    worker.finished.connect(lambda events, trunc: got.append(events))
    worker.fetch_error.connect(lambda k, d: print("fetch error", k, d))
    worker.run()
    T.pump(100)
    grade("JM", mw._RemoteAssistanceDialog._build_sessions(got[0] if got else []))
    T.teardown(w, True, m)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
