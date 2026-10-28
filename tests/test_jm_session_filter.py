"""The Logon Sessions filter shows every event of the session, in both modes.

Codex audit-2 A1: in Juggernaut Mode the session query compared the Parquet
``timestamp_utc`` column (text) with ``CAST(? AS TIMESTAMP)``.  The query
failed, the code logged it and quietly fell back to the session browser's own
input events, so the filtered view looked complete but was not: 4 of these
5 events (the 4663 was missing), 2 of 35 on a real baseline session.

Expected: all five events of logon 0xa01 in both modes; and if the query ever
does fail, the analyst is told the view is incomplete (never a silent subset).
Synthetic data only.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from PySide6.QtWidgets import QMessageBox                           # noqa: E402

CHECKS = []
SEC = r"C:\synthetic\Security.evtx"
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    evs = []
    for i, (eid, sec) in enumerate([(4624, 0), (4672, 1), (4663, 2), (4688, 3), (4634, 4)]):
        evs.append(T.ev(SEC, i + 1, "SYNTH-HOST", BASE + timedelta(seconds=sec), eid,
                        data={"TargetLogonId": "0xa01", "SubjectLogonId": "0xa01",
                              "TargetUserName": "SYNTH-USER", "LogonType": "2"}))
    # Another logon on the same host: must not appear.
    evs.append(T.ev(SEC, 9, "SYNTH-HOST", BASE + timedelta(seconds=2), 4663,
                    data={"SubjectLogonId": "0xb02"}))
    return evs


def shown_ids(w, jm):
    if jm:
        T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
        T.pump(500)
        return sorted(w._hw_model._display_table["record_id"].to_pylist())
    T.pump(200)
    return sorted(w._proxy_model.get_source_event(r)["record_id"] for r in range(w._proxy_model.rowCount()))


def run(mw, jm, boxes):
    tag = "JM" if jm else "Normal"
    print(f"\n=== {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    m.load(w, dataset())
    w._on_show_logon_sessions()
    T.wait_for(lambda: getattr(w, "_logon_sessions_dlg", None) is not None, 20)
    dlg = w._logon_sessions_dlg
    s = next((x for x in dlg._all_sessions if x.get("lid") == "0xa01"), None)
    check(f"{tag}: the session browser lists logon 0xa01", s is not None)
    if s is None:
        w.close()
        return
    n_boxes = len(boxes)
    dlg._on_filter_fn(s["lid"], s)
    got = shown_ids(w, jm)
    check(f"{tag}: the session filter shows all five of its events, and only them", got == [1, 2, 3, 4, 5], str(got))
    check(f"{tag}: ...with no warning box", len(boxes) == n_boxes, str(boxes[n_boxes:]))
    w._clear_session_filter()
    try:
        dlg.close()
    except RuntimeError:
        pass
    w.close()
    T.pump(200)


def failure_is_disclosed(mw, boxes):
    """Force the JM query to fail: the view must say it is incomplete."""
    print("\n=== JM: a failed session query is disclosed ===", flush=True)
    m = T.Mode(mw, True)
    w = mw.MainWindow()
    m.load(w, dataset())
    w._on_show_logon_sessions()
    T.wait_for(lambda: getattr(w, "_logon_sessions_dlg", None) is not None, 20)
    dlg = w._logon_sessions_dlg
    s = next((x for x in dlg._all_sessions if x.get("lid") == "0xa01"), None)
    real = mw._JMSessionFetchWorker

    class Failing(real):
        def run(self):
            self.query_failed.emit("synthetic failure")
    mw._JMSessionFetchWorker = Failing
    n_boxes = len(boxes)
    try:
        dlg._on_filter_fn(s["lid"], s)
        T.pump(300)
    finally:
        mw._JMSessionFetchWorker = real
    new = boxes[n_boxes:]
    check("JM: a failed session query tells the analyst the view is incomplete",
          any("INCOMPLETE" in b.upper() for b in new), str(new))
    w._clear_session_filter()
    try:
        dlg.close()
    except RuntimeError:
        pass
    w.close()
    T.pump(200)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    boxes = []

    def _box(kind):
        def f(parent, title, text, *a, **k):
            boxes.append(f"{kind}: {title}: {text}")
            return QMessageBox.StandardButton.Ok
        return f
    QMessageBox.warning = staticmethod(_box("warning"))
    QMessageBox.critical = staticmethod(_box("critical"))
    QMessageBox.information = staticmethod(_box("information"))
    for jm in (False, True):
        run(mw, jm, boxes)
    failure_is_disclosed(mw, boxes)
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    tempfile.tempdir = None
    sys.exit(main())
