"""Juggernaut Logon Sessions respects reboots like Normal Mode (Codex C3-1).

A logon ID is unique only within one boot.  The session builder treats a
loaded Security 4608 or Kernel-General 12 as a hard boundary, but the
Juggernaut fetch loaded only 4624/4634/4672/4688 and no channel/provider, so
in Juggernaut a logon ID from one boot collected records from the next
(32 real sessions crossed a logged boot; "Filter to Selected Session" showed a
record from after the reboot).
Expected: the same sessions in both modes; filtering to the first session
shows only its own boot's records.  Synthetic events only.
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
SEC = r"C:\c\Security.evtx"
SYS = r"C:\c\System.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    t = T.T0
    lid = "0x3e7a"
    return [
        T.ev(SEC, 1, "WS1", t, 4608),
        T.ev(SEC, 2, "WS1", t + timedelta(seconds=60), 4624,
             data={"TargetLogonId": lid, "LogonType": "2", "TargetUserName": "alice"}),
        T.ev(SEC, 3, "WS1", t + timedelta(seconds=61), 4672, data={"SubjectLogonId": lid}),
        dict(T.ev(SYS, 4, "WS1", t + timedelta(seconds=3600), 12, "Microsoft-Windows-Kernel-General",
                  {"StartTime": T.iso(t + timedelta(seconds=3600))}), channel="System"),
        T.ev(SEC, 5, "WS1", t + timedelta(seconds=3700), 4688, data={"SubjectLogonId": lid}),
        T.ev(SEC, 6, "WS1", t + timedelta(seconds=3800), 4634, data={"TargetLogonId": lid}),
    ]


def shown(w, jm):
    if jm:
        T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
        T.pump(500)
        t = w._hw_model._display_table
        return sorted(zip(t["source_file"].to_pylist(), t["record_id"].to_pylist()))
    T.pump(200)
    return sorted((w._proxy_model.get_source_event(r)["source_file"], w._proxy_model.get_source_event(r)["record_id"])
                  for r in range(w._proxy_model.rowCount()))


def main() -> int:
    import evtx_tool.gui.main_window as mw
    sessions = {}
    for jm in (False, True):
        tag = "Juggernaut" if jm else "Normal"
        m = T.Mode(mw, jm)
        w = mw.MainWindow()
        m.load(w, dataset())
        if jm:
            w._table.setModel(w._hw_model)
        w._on_show_logon_sessions()
        T.wait_for(lambda: getattr(w, "_logon_sessions_dlg", None) is not None, 20)
        dlg = w._logon_sessions_dlg
        ss = [s for s in dlg._all_sessions if s.get("lid") == "0x3e7a"]
        norm = lambda v: str(v or "").replace("T", " ").rstrip("Z")          # noqa: E731  display form only
        sessions[tag] = sorted((norm(s.get("start_ts")), norm(s.get("logoff_ts"))) for s in ss)
        first = min(ss, key=lambda s: str(s.get("start_ts") or "~"), default=None)
        check(f"{tag}: the logon ID reused after the reboot is two sessions", len(ss) == 2, str(sessions[tag]))
        if first is not None:
            dlg._on_filter_fn(first["lid"], first)
            got = shown(w, jm)
            check(f"{tag}: filtering to the first session shows only its own boot's records",
                  got == [(SEC, 2), (SEC, 3)], str(got))
            w._clear_session_filter()
        try:
            dlg.close()
        except RuntimeError:
            pass
        T.teardown(w, jm, m)
    check("both modes list the same sessions", sessions.get("Normal") == sessions.get("Juggernaut"),
          f"{sessions.get('Normal')} vs {sessions.get('Juggernaut')}")
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
