"""A session of a blank-Computer log filters to that log's host only, in both modes.

Gemini audit 8-10 (Medium): the session filter's host check was "if a
computer is set", so a session whose Computer is blank ("") had no host
check at all, and another host's events with the same LogonId were shown in
it (Normal proxy and the Juggernaut SQL alike).

Expected: filtering the blank-host session shows its own two events, not the
other host's 4688.  Synthetic data.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_jm_session_filter import shown_ids                        # noqa: E402

CHECKS = []
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    lid = {"TargetLogonId": "0x3e7a1", "SubjectLogonId": "0x3e7a1", "TargetUserName": "u", "LogonType": "2"}
    return [T.ev(r"C:\s\blank\Security.evtx", 1, "", BASE, 4624, data=dict(lid)),
            T.ev(r"C:\s\blank\Security.evtx", 2, "", BASE + timedelta(seconds=5), 4688, data=dict(lid)),
            T.ev(r"C:\s\other\Security.evtx", 3, "SYNTH-HOST-02", BASE + timedelta(seconds=10), 4688, data=dict(lid))]


def main() -> int:
    import evtx_tool.gui.main_window as mw
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        m = T.Mode(mw, jm)
        w = mw.MainWindow()
        try:
            m.load(w, dataset())
            w._on_show_logon_sessions()
            T.wait_for(lambda: getattr(w, "_logon_sessions_dlg", None) is not None, 20)
            dlg = w._logon_sessions_dlg
            s = next((x for x in dlg._all_sessions if x.get("lid") == "0x3e7a1" and x.get("logon_ev")), None)
            check(f"{tag}: the blank-host session is listed", s is not None)
            if s is not None:
                dlg._on_filter_fn(s["lid"], s)
                got = shown_ids(w, jm)
                check(f"{tag}: its filter shows its own 2 events, not the other host's", got == [1, 2], str(got))
            w._clear_session_filter()
            dlg.close()
        finally:
            T.teardown(w, jm, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
