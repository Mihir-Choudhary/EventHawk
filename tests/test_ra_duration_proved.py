"""Remote Assistance / Remote Help rows show a duration only for a logged start AND end.

Codex audit-2 A2: a Classic Remote Assistance start plus a control event,
with no end, showed "10 seconds"; two Remote Help events sharing a SessionId
showed "10 seconds" although Remote Help's start/end event semantics are not
documented.  Standing rule: a duration the log does not prove reads
Unavailable.  A Classic RA session with its start and end keeps its duration.
Synthetic data only.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)
RA = "Microsoft-Windows-RemoteAssistance/Operational"
RH = "Microsoft-Windows-RemoteHelp/Operational"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    evs = []

    def add(ch, eid, sec, data, host):
        e = T.ev(r"C:\synthetic\\" + ch.replace("/", "_") + ".evtx", len(evs) + 1, host,
                 BASE + timedelta(seconds=sec), eid, data=data)
        e["channel"] = e["provider"] = ch
        evs.append(e)
    for eid, sec in [(1, 0), (2, 10), (3, 60)]:            # start, control, end
        add(RA, eid, sec, {"LocalFQDNName": "SYNTH-RA", "UserName": "SYNTH-USER"}, "SYNTH-RA")
    for eid, sec in [(1, 120), (2, 130)]:                  # start, control, no end
        add(RA, eid, sec, {"LocalFQDNName": "SYNTH-RA", "UserName": "SYNTH-OTHER"}, "SYNTH-RA")
    add(RH, 1, 0, {"SessionId": "SYNTH-RH"}, "SYNTH-RH")
    add(RH, 2, 10, {"SessionId": "SYNTH-RH"}, "SYNTH-RH")
    return evs


def run(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    m.load(w, dataset())
    w._on_show_remote_assist()
    T.wait_for(lambda: getattr(w, "_ra_dlg", None) is not None, 20)
    rows = w._ra_dlg._all_sessions
    ra = sorted((s for s in rows if s["type"] == "Classic RA"), key=lambda s: s.get("start_ts", ""))
    rh = [s for s in rows if s["type"] == "Remote Help"]
    check(f"{tag}: two Classic RA rows and one Remote Help row", len(ra) == 2 and len(rh) == 1,
          f"{len(ra)} RA, {len(rh)} RH")
    if len(ra) == 2:
        check(f"{tag}: Classic RA with start and end keeps its 60 s duration",
              ra[0]["duration_secs"] == 60, f"{ra[0]['duration']} ({ra[0]['duration_secs']})")
        check(f"{tag}: Classic RA with no end: duration Unavailable",
              ra[1]["duration_secs"] < 0 and ra[1]["duration"].startswith("Unavailable"),
              f"{ra[1]['duration']} ({ra[1]['duration_secs']})")
    if rh:
        check(f"{tag}: Remote Help (start/end not documented): duration Unavailable",
              rh[0]["duration_secs"] < 0 and rh[0]["duration"].startswith("Unavailable"),
              f"{rh[0]['duration']} ({rh[0]['duration_secs']})")
    try:
        w._ra_dlg.close()
    except RuntimeError:
        pass
    w.close()
    T.pump(200)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    for jm in (False, True):
        run(mw, jm)
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
