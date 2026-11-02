"""Custom columns in Juggernaut: the same values as Normal mode, as a real column.

Spec item 4: one evaluator for both modes; Juggernaut streams the System
columns and event_data_json from the Parquet shards, evaluates the same code
and attaches the result to the tab's table.  Checked here: parity with
Normal mode on the same synthetic events; the column in the Arrow model (values,
header, numeric sort, popup counts, column filter, remove; another tab's model
untouched); and, with EVTX_TEST_LOGS, every value on the real Security and
System logs against an extractor that reads the EVTX files with pyevtx-rs
directly, plus the time for the whole 1.71M-event corpus when that is the
folder given.
"""
import glob
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
TYPES = ["3", "10", "2", "3", None, "3", "11", "10"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec, arrow_column_values
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.gui.models import COLUMNS
    from evtx_tool.gui.jm_col_worker import ColValueWorker

    evs = []
    for i, lt in enumerate(TYPES):
        ed = {"LogonType": lt, "TargetUserName": f"user{i}"} if lt is not None else {"Other": "x"}
        evs.append(T.ev(r"C:\c\Security.evtx", i + 1, f"HOST-{i % 2}", T.T0 + timedelta(seconds=i), 4624, data=ed))
    tmp = tempfile.mkdtemp(prefix="jm_cc_")
    try:
        table = T.write_jm(evs, tmp)
        shards = sorted(glob.glob(os.path.join(tmp, "*.parquet")))
        for template in ("{Data[LogonType]}", "{EventID} on {Computer}", "{Data[2]}", "{TimeCreated[SystemTime]}",
                         "{Data[TargetUserName]}@{Provider[Name]}"):
            c = compile_spec(CustomColumnSpec(col_id=1, title="x", template=template))
            jm = arrow_column_values(c, table, shards)
            by_key = {(e["source_file"], e["record_id"]): e for e in evs}
            normal = [c.value(by_key[(sf, rid)]) for sf, rid in
                      zip(table["source_file"].to_pylist(), table["record_id"].to_pylist())]
            check(f"JM = Normal for {template}", jm == normal, f"{jm[:3]} vs {normal[:3]}")

        main_m = ArrowTableModel(table, parquet_dir=tmp)
        tab_m = ArrowTableModel(table, parquet_dir=tmp)
        T.wait_for(lambda: tab_m.rowCount() == len(evs), 30)
        col = compile_spec(CustomColumnSpec(col_id=202, title="Logon Type", template="{Data[LogonType]}", kind="int"))
        idx = tab_m.add_custom_column(col, arrow_column_values(col, tab_m._full_table, shards))
        T.wait_for(lambda: tab_m._filter_thread._q.empty(), 30); T.pump(300)
        check("the column is added after the built-in ones", idx == len(COLUMNS) and tab_m.columnCount() == len(COLUMNS) + 1)
        check("its header is the title", tab_m.headerData(idx, Qt.Orientation.Horizontal) == "Logon Type")
        check("another tab's model is untouched", main_m.columnCount() == len(COLUMNS)
              and "cc_202" not in main_m._full_table.column_names)
        tab_m.sort(idx, Qt.SortOrder.AscendingOrder)
        T.wait_for(lambda: tab_m._filter_thread._q.empty(), 30); T.pump(400)
        got = [tab_m.data(tab_m.index(r, idx)) for r in range(tab_m.rowCount())]
        check("an Integer column sorts by number, empty last (as in Normal mode)",
              got == ["2", "3", "3", "3", "10", "10", "11", ""], str(got))
        vals = {}
        wk = ColValueWorker(tab_m._full_table, "custom:202")
        wk.finished.connect(lambda d: vals.update(d))
        wk.run()
        check("the column popup counts its values (empty included)",
              vals.get("3") == 3 and vals.get("10") == 2 and vals.get("") == 1, str(vals))
        tab_m.set_quick_filters([{"key": "custom:202", "value": "3", "include": True},
                                 {"key": "custom:202", "value": "11", "include": True}])
        T.wait_for(lambda: tab_m.rowCount() == 4, 30); T.pump(300)
        check("the column filter keeps exactly the chosen values", tab_m.rowCount() == 4, str(tab_m.rowCount()))
        tab_m.set_quick_filters([])
        tab_m.remove_custom_column(202)
        T.wait_for(lambda: tab_m._filter_thread._q.empty(), 30); T.pump(300)
        check("removing drops the column", tab_m.columnCount() == len(COLUMNS)
              and "cc_202" not in tab_m._full_table.column_names and tab_m.rowCount() == len(evs))
        for m in (main_m, tab_m):
            m._filter_thread.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    tab_warning_leg()
    real_leg()
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


def tab_warning_leg() -> None:
    """A file tab's column is computed over that file only (audit-5 E5-11): a
    field only another file has must raise the 'no event in this tab' warning,
    as it does in Normal mode, and the other file's rows get no value."""
    import evtx_tool.gui.main_window as mw
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec
    A, B = r"C:\c\A.evtx", r"C:\c\B.evtx"
    evs = [T.ev(A, i + 1, "H", T.T0 + timedelta(seconds=i), 4624, data={"X": "a"}) for i in range(3)]
    evs += [T.ev(B, i + 10, "H", T.T0 + timedelta(seconds=10 + i), 4624, data={"OnlyInB": "b"}) for i in range(3)]
    w = mw.MainWindow()
    w._view_mode = "separate"
    m = T.Mode(mw, True)
    m.load(w, evs)
    w._table.setModel(w._hw_model)
    w._jm_pending = {f: w._hw_model._full_table for f in (A, B)}
    w._open_jm_file_tab(A)
    T.pump(300)
    w._events_tab_widget.setCurrentIndex(w._events_tab_widget.indexOf(w._file_tabs[A].table))
    T.pump(300)
    warned = []
    w._exec_on_top = lambda box: warned.append(box.text())
    model = w._custom_cols_model()
    w._compute_custom_column(model, compile_spec(CustomColumnSpec(col_id=501, title="B only",
                                                                  template="{Data[OnlyInB]}")), False)
    T.wait_for(lambda: model.columnCount() > 22 and warned, 30); T.pump(300)
    check("JM file tab: a field only another file has raises the 'no event in this tab' warning",
          warned and "OnlyInB" in warned[0], str(warned))
    vals = [v for v in model._full_table["cc_501"].to_pylist() if v]
    check("...and no row of the other file gets a value in this tab's column", vals == [], str(vals))
    T.teardown(w, True, m)


def _direct(files):
    """{(source_file, record_id): (EventData dict, System dict)} read with pyevtx-rs directly."""
    from evtx import PyEvtxParser
    out = {}
    for f in files:
        for rec in PyEvtxParser(f).records_json():
            ev = json.loads(rec["data"])["Event"]
            ed = ev.get("EventData") or ev.get("UserData") or {}
            out[(f, rec["event_record_id"])] = (ed if isinstance(ed, dict) else {}, ev.get("System") or {})
    return out


def real_leg() -> None:
    logs = os.environ.get("EVTX_TEST_LOGS", "")
    files = [p for p in (os.path.join(logs, n) for n in ("Security.evtx", "System.evtx")) if os.path.exists(p)]
    if not files:
        print("  (EVTX_TEST_LOGS not set -- real-log leg skipped)")
        return
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec, arrow_column_values
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    direct = _direct(files)
    tmp = tempfile.mkdtemp(prefix="jm_cc_real_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        table = load_arrow_table(pq)
        shards = sorted(glob.glob(os.path.join(pq, "**", "*.parquet"), recursive=True))
        keys = list(zip(table["source_file"].to_pylist(), table["record_id"].to_pylist()))
        for field_name in ("TargetUserName", "LogonType", "IpAddress"):
            c = compile_spec(CustomColumnSpec(col_id=9, title="x", template="{Data[%s]}" % field_name))
            got = arrow_column_values(c, table, shards)
            bad = 0
            for k, v in zip(keys, got):
                ed = direct.get(k, ({}, {}))[0]
                want = ed.get(field_name)
                want = "" if want in (None, "") else str(want)
                bad += v != want
            nonempty = sum(1 for v in got if v)
            check(f"{{Data[{field_name}]}} on the real logs equals pyevtx-rs read directly",
                  bad == 0 and nonempty > 0, f"{bad:,} mismatches, {nonempty:,} non-empty of {len(got):,}")
        c = compile_spec(CustomColumnSpec(col_id=9, title="x", template="{Computer}"))
        got = arrow_column_values(c, table, shards)
        bad = sum(1 for k, v in zip(keys, got) if v != str(direct.get(k, ({}, {}))[1].get("Computer", "")))
        check("{Computer} on the real logs equals pyevtx-rs", bad == 0, f"{bad:,} mismatches")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if os.path.basename(os.path.normpath(logs)).lower() != "logs":
        return
    all_files = sorted(glob.glob(os.path.join(logs, "**", "*.evtx"), recursive=True))
    tmp = tempfile.mkdtemp(prefix="jm_cc_big_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(all_files)
        table = load_arrow_table(pq)
        shards = sorted(glob.glob(os.path.join(pq, "**", "*.parquet"), recursive=True))
        c = compile_spec(CustomColumnSpec(col_id=9, title="x", template="{Data[TargetUserName]}"))
        t = time.perf_counter()
        got = arrow_column_values(c, table, shards)
        dt = time.perf_counter() - t
        check(f"{len(table):,} events: a {{Data[Name]}} column in under 10 s", dt < 10 and len(got) == len(table),
              f"{dt:.1f} s")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
