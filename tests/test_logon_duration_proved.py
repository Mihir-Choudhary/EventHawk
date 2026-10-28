"""A logon session's duration is shown only when the log proves both ends.

Codex audit-2 A2: the Logon Session Browser took a session's End from the
logoff when there was one, and otherwise from the last event seen or the next
logon's start, then showed a Duration from that.  On a public baseline 393 of
406 sessions carried a duration with no logoff behind it.  Standing rule: a
duration the log does not prove reads Unavailable.

Expected:
  * logon 4624 + logoff 4634       -> End = the logoff, Duration = 4s
  * logon 4624, activity, no 4634  -> End "Not logged", Duration Unavailable,
                                      Last Activity = the last event seen
The session filter keeps the observed scope (its events are unchanged).
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
SEC = r"C:\synthetic\Security.evtx"
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    def e(rid, eid, sec, lid, kind="Target"):
        return T.ev(SEC, rid, "SYNTH-HOST", BASE + timedelta(seconds=sec), eid,
                    data={f"{kind}LogonId": lid, "TargetUserName": "SYNTH-USER", "LogonType": "2"})
    return [
        e(1, 4624, 0, "0xa01"), e(2, 4672, 1, "0xa01", "Subject"), e(3, 4634, 4, "0xa01"),        # proved
        e(4, 4624, 100, "0xb02"), e(5, 4672, 101, "0xb02", "Subject"), e(6, 4688, 130, "0xb02", "Subject"),  # no logoff
    ]


def cells(dlg, lid):
    hdr = [dlg._tbl.horizontalHeaderItem(c).text() for c in range(dlg._tbl.columnCount())]
    for r in range(dlg._tbl.rowCount()):
        row = {hdr[c]: (dlg._tbl.item(r, c).text() if dlg._tbl.item(r, c) else "") for c in range(len(hdr))}
        if row.get("Session ID") == lid:
            return row
    return {}


def run(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    m.load(w, dataset())
    w._on_show_logon_sessions()
    T.wait_for(lambda: getattr(w, "_logon_sessions_dlg", None) is not None, 20)
    dlg = w._logon_sessions_dlg
    a, b = cells(dlg, "0xa01"), cells(dlg, "0xb02")
    check(f"{tag}: proved session: Duration from logon to logoff", a.get("Duration") == "4s", str(a))
    check(f"{tag}: proved session: End is the logoff", a.get("End", "").startswith("2024-01-01 00:00:04"), a.get("End"))
    check(f"{tag}: no logoff: Duration is Unavailable, not a span",
          b.get("Duration", "").startswith("Unavailable"), b.get("Duration"))
    check(f"{tag}: no logoff: End says the logoff is not logged", b.get("End") == "Not logged", b.get("End"))
    check(f"{tag}: no logoff: Last Activity shows the last event seen",
          b.get("Last Activity", "").startswith("2024-01-01 00:02:10"), b.get("Last Activity"))
    s = next(x for x in dlg._all_sessions if x["lid"] == "0xb02")
    dlg._on_filter_fn(s["lid"], s)
    if jm:
        T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
        T.pump(500)
        got = sorted(w._hw_model._display_table["record_id"].to_pylist())
    else:
        T.pump(200)
        got = sorted(w._proxy_model.get_source_event(r)["record_id"] for r in range(w._proxy_model.rowCount()))
    check(f"{tag}: the session filter still shows every event of the unclosed session", got == [4, 5, 6], str(got))
    w._clear_session_filter()
    try:
        dlg.close()
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
