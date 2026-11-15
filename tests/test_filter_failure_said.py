"""A filter that cannot be applied says so, in both modes; shard paths with ' work.

Gemini audit 3-07 (High):
1. Normal view: a profile or preset whose condition regex does not compile
   (the dialog blocks it, profiles and presets do not) was skipped silently,
   so the table showed every row as if filtered.
2. Juggernaut: with no Parquet shard list the text/condition phase returned
   the metadata-only rows, again silently.
3. Juggernaut: shard paths were put into parquet_scan('...') unescaped, so a
   folder with an apostrophe broke the event-data phase.

The project's rule for a filter that cannot run (Codex audit-5 E5-05): show
every event (never hide evidence) and warn that the table is NOT filtered.

Expected: (1) the Normal proxy reports the bad condition and the window warns
"NOT filtered"; (2) Juggernaut reports the missing shards the same way;
(3) an event-data search on shards under a folder with "'" gives the right count
and no failure.  Synthetic events.
"""
import os
import shutil
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = [T.ev(r"C:\c\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i), 4624,
                data={"Cmd": "qzx7tok" if i < 2 else "plain"}) for i in range(5)]
    bad = {"conditions": [{"name": "Cmd", "operator": "regex", "value": "[unclosed"}]}

    # 1. Normal view
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    m.load(w, evs)
    warned = []
    w._warn_blocking = lambda title, text, **k: warned.append((title, text))
    w._proxy_model.set_advanced_filter(bad)
    T.pump(300)
    check("Normal: an uncompilable condition regex is reported as NOT filtered",
          warned and "not filtered" in warned[-1][1].lower(), str(warned[-1:])[:160])
    check("Normal: nothing is hidden", w._proxy_model.rowCount() == len(evs), str(w._proxy_model.rowCount()))
    T.teardown(w, False, m)

    # 2. Juggernaut, shard list missing
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    m.load(w, evs)
    w._table.setModel(w._hw_model)
    w._connect_jm_model_signals(w._hw_model)
    warned = []
    w._warn_blocking = lambda title, text, **k: warned.append((title, text))
    w._hw_model._filter_thread._get_shard_paths = lambda: []     # what the filter thread reads
    w._hw_model.apply_filter({"text_search": "qzx7tok"})
    T.wait_for(lambda: warned, 20); T.pump(300)
    check("Juggernaut: missing shards are reported as NOT filtered",
          warned and "not filtered" in warned[-1][1].lower(), str(warned[-1:])[:160])
    T.teardown(w, True, m)

    # 3. Juggernaut, shards under a folder with an apostrophe
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    tmp = tempfile.mkdtemp(prefix="o'brien_")
    try:
        table = T.write_jm(evs, tmp)
        mdl = ArrowTableModel(table, parquet_dir=tmp)
        T.wait_for(lambda: mdl.rowCount() == len(evs), 30)
        failed = []
        if hasattr(mdl, "filter_failed"):
            mdl.filter_failed.connect(lambda msg: failed.append(msg))
        mdl.apply_filter({"text_search": "qzx7tok"})     # searched in the shards' event data
        T.wait_for(lambda: mdl.rowCount() == 2 or failed, 30); T.pump(300)
        check("Juggernaut: an event-data search on shards under a folder with ' works",
              mdl.rowCount() == 2 and not failed, f"rows {mdl.rowCount()}, failed {failed[:1]}")
        if hasattr(mdl, "close"):
            mdl.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
