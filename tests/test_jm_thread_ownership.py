"""Juggernaut background work belongs to the window and never blocks it (Gemini 12-04).

Three gaps:
1. the session-filter worker had no parent, so the window's close and its
   Parquet clean-up could not see it (the folder could be deleted under a
   running query), and nothing could stop it while it waited up to five
   minutes for the "large session" answer;
2. the filter-dialog metadata was computed on a plain daemon thread whose
   result was applied whenever it arrived, also after another dataset had
   been loaded (the old dataset's values then filled the new filter dialog);
3. Logon Sessions in Juggernaut ran its event query (every 4624/4634/4647/
   4672/4688) on the window's own thread, freezing the window.

Expected: 1. the worker takes a parent and stops at once on request_stop()
while waiting, with no rows delivered; 2. a metadata result for a dataset
that is no longer loaded is ignored, and the loader is a thread the window
owns; 3. the logon query runs off the window's thread.
Synthetic data only.
"""
import os
import sys
import tempfile
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
import test_jm_session_filter as S                                  # noqa: E402
from PySide6.QtCore import QThread                                  # noqa: E402
from PySide6.QtWidgets import QMessageBox                           # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import duckdb
    import evtx_tool.gui.main_window as mw
    for k in ("warning", "critical", "information"):
        setattr(QMessageBox, k, staticmethod(lambda *a, **kw: QMessageBox.StandardButton.Ok))

    # 1. the session-filter worker
    m = T.Mode(mw, True)
    w = mw.MainWindow()
    m.load(w, S.dataset())
    shards = w._hw_model._get_shard_paths()
    from evtx_tool.core.heavyweight.sql_paths import sql_path_list
    scan = f"parquet_scan({sql_path_list(shards)})"
    try:
        wk = mw._JMSessionFetchWorker(duckdb, scan, "1=1", [], None, parent=w)
        made = True
    except TypeError as e:
        wk, made = None, False
        check("the session worker takes a parent", False, str(e))
    if made:
        check("the session worker takes a parent", wk.parent() is w)
        got = []
        wk.count_ready.connect(lambda n: got.append(("count", n)))
        wk.rows_ready.connect(lambda k: got.append(("rows", len(k))))
        wk.start()
        T.wait_for(lambda: any(g[0] == "count" for g in got), 10)
        t0 = time.time()
        stop = getattr(wk, "request_stop", None)
        if callable(stop):
            stop()
        ended = wk.wait(3000)
        check("waiting for the answer, request_stop() ends it at once", callable(stop) and ended,
              f"{time.time() - t0:.1f}s, request_stop={'yes' if callable(stop) else 'no'}")
        T.pump(100)
        check("...and delivers no rows", not any(g[0] == "rows" for g in got), str(got))
        if wk.isRunning():
            wk.proceed(False)
            wk.wait(5000)

    # 2. metadata for a dataset that is no longer loaded
    old_table = w._hw_model._full_table
    applied = []
    real = mw.MainWindow._on_jm_metadata_loaded

    def spy(self, *a):
        applied.append(a)
        return real(self, *a)
    mw.MainWindow._on_jm_metadata_loaded = spy
    try:
        w._metadata = {}
        before = {t for t in w.findChildren(QThread)}
        w._load_jm_metadata(w._hw_db_path)
        owned = [t for t in w.findChildren(QThread) if t not in before]
        check("the metadata loader is a thread the window owns", bool(owned), f"{len(owned)} new owned thread(s)")
        T.wait_for(lambda: bool(applied), 10)
        check("metadata for the loaded dataset is applied", bool(w._metadata.get("event_id")), str(list(w._metadata)))
        # now a result arrives for a table that is not loaded any more
        w._metadata = {}
        try:
            w._on_jm_metadata_loaded({"event_id": {"1": 1}}, object())
            stale_ok = not w._metadata
        except TypeError:
            stale_ok = False              # old signature: no dataset to compare with
        check("a result for a dataset no longer loaded is ignored", stale_ok, str(w._metadata))
    finally:
        mw.MainWindow._on_jm_metadata_loaded = real

    # 3. the logon query runs off the window's thread
    main_id = threading.get_ident()
    seen = []
    real_connect = duckdb.connect

    class Con:
        def __init__(self, c):
            self._c = c

        def execute(self, sql, *a):
            if "4624" in sql and "4688" in sql:
                seen.append(threading.get_ident())
            return self._c.execute(sql, *a)

        def __getattr__(self, n):
            return getattr(self._c, n)
    duckdb.connect = lambda *a, **k: Con(real_connect(*a, **k))
    try:
        w._on_show_logon_sessions()
        T.wait_for(lambda: getattr(w, "_logon_sessions_dlg", None) is not None, 20)
    finally:
        duckdb.connect = real_connect
    check("Logon Sessions opened", getattr(w, "_logon_sessions_dlg", None) is not None)
    check("its event query ran off the window's thread", seen and all(t != main_id for t in seen),
          f"{len(seen)} query/queries, on main thread: {sum(t == main_id for t in seen)}")
    dlg = getattr(w, "_logon_sessions_dlg", None)
    if dlg is not None:
        s = next((x for x in dlg._all_sessions if x.get("lid") == "0xa01"), None)
        check("...and found the session", s is not None)
        dlg.close()
    w.close()
    T.pump(300)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    tempfile.tempdir = None
    sys.exit(main())
