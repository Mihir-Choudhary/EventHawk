"""System Activity tool through the main window, Normal and Juggernaut (user request 2026-11-07).

The tool opens from Tools in both modes, shows the same periods in both (the
analysis is checked in test_system_activity), only reads the events it needs
(an unlock logon, type 7, is a moment; a network logon, type 3, is not), and
its filters, CSV export and "Events around" jump work.
Synthetic events only.
"""
import csv
import json
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
import test_system_activity as S                                    # noqa: E402

CHECKS = []
KEY = ("layer", "state", "start", "end", "started_by", "ended_by", "notes")


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    evs = S.scenario()
    evs.append(S.ev("2025-11-13T18:10:01.000000Z", S.SEC, 4624, "Security", LogonType="7",
                    TargetUserName="alice", TargetDomainName="PC1"))
    evs.append(S.ev("2025-11-13T18:20:00.000000Z", S.SEC, 4624, "Security", LogonType="3",
                    TargetUserName="bob", TargetDomainName="PC1"))
    evs.append(S.ev("2025-11-13T18:21:00.000000Z", "Microsoft-Windows-Sysmon", 12, "Sysmon"))
    return evs


def write_jm(evs, tmp):
    """Like test_around_pivot.write_jm, plus ed_logon_type as the engine stores it."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME, _make_schema, load_arrow_table
    rows = [{"record_id": e["record_id"], "event_record_id": e["record_id"], "event_id": e["event_id"],
             "level": 4, "level_name": "Information",
             "timestamp_utc": e["timestamp"].replace("T", " ").replace("Z", "")[:26],
             "channel": e["channel"], "provider": e["provider"], "computer": e["computer"],
             "source_file": e["source_file"], "event_data_json": json.dumps(e["event_data"]),
             "ed_logon_type": str(e["event_data"].get("LogonType", "") or "")} for e in evs]
    shard = os.path.join(tmp, "s0.parquet")
    pq.write_table(pa.Table.from_pylist(rows, schema=_make_schema()), shard)
    with open(os.path.join(tmp, _MANIFEST_FILENAME), "w", encoding="utf-8") as fh:
        json.dump([shard], fh)
    return load_arrow_table(tmp)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.analysis.system_activity import build
    evs = dataset()
    want = [tuple(r[k] for k in KEY) for r in build(evs)["rows"]]
    results = {}
    for jm in (False, True):
        tag = "Juggernaut" if jm else "Normal"
        w = mw.MainWindow()
        m = T.Mode(mw, jm)
        tmp = None
        if jm:
            tmp = tempfile.mkdtemp(prefix="sysact_")
            table = write_jm(evs, tmp)
            m.load(w, table=table, parquet_dir=tmp)
            w._table.setModel(w._hw_model)
        else:
            m.load(w, evs)
        T.pump(300)
        try:
            w._system_activity_dlg = None
            w._on_show_system_activity()
            T.wait_for(lambda: getattr(w, "_system_activity_dlg", None) is not None, 60)
            dlg = w._system_activity_dlg
            check(f"{tag}: the tool opens from the main window", dlg is not None)
            if dlg is None:
                continue
            got = [tuple(r[k] for k in KEY) for r in dlg._res["rows"]]
            results[tag] = got
            check(f"{tag}: the same periods as the analysis of the loaded events", got == want,
                  f"{len(got)} vs {len(want)}")
            whats = [(p["what"], p["details"]) for p in dlg._res["points"]]
            check(f"{tag}: an unlock logon (type 7) is a moment; a network logon and Sysmon are not read",
                  any(w_ == "Unlocked (logon type 7)" and "alice" in d for w_, d in whats)
                  and not any("bob" in d for _, d in whats))
            # Every period, including the split-second ones hidden by default.
            dlg._chk_short.setChecked(False)
            n_all = dlg._tbl.rowCount()
            dlg._chk["Screen"].setChecked(False)
            n_noscreen = dlg._tbl.rowCount()
            check(f"{tag}: unticking Screen hides the screen periods",
                  n_noscreen == n_all - sum(1 for r in dlg._res["rows"] if r["layer"] == "Screen"),
                  f"{n_all} -> {n_noscreen}")
            dlg._chk["Screen"].setChecked(True)
            dlg._search.setText("hibernate")
            check(f"{tag}: search narrows the timeline", 0 < dlg._tbl.rowCount() < n_all, str(dlg._tbl.rowCount()))
            dlg._search.setText("")
            # Sorting once crashed the process (a recursive __lt__): sort by
            # every column, then check Start and Duration really order.
            from PySide6.QtCore import Qt as _Qt
            for col in range(dlg._tbl.columnCount()):
                dlg._tbl.sortItems(col, _Qt.SortOrder.AscendingOrder)
            dlg._tbl.sortItems(5, _Qt.SortOrder.AscendingOrder)
            durs = [r["duration"] for r in dlg.visible_order(dlg._tbl) if r["duration"] is not None]
            dlg._tbl.sortItems(3, _Qt.SortOrder.AscendingOrder)
            starts = [r["start"] for r in dlg.visible_order(dlg._tbl) if r["start"] is not None]
            check(f"{tag}: sorting by every column works; Duration and Start sort in order",
                  durs == sorted(durs) and starts == sorted(starts) and len(durs) > 5)
            out = os.path.join(tempfile.gettempdir(), f"sysact_{os.getpid()}_{int(jm)}.csv")
            dlg.write_csv(out, timeline=True)
            with open(out, encoding="utf-8-sig", newline="") as fh:
                rows = list(csv.reader(fh))
            os.remove(out)
            check(f"{tag}: CSV export has the header and every shown period", len(rows) == n_all + 1
                  and rows[0][2] == "Activity", f"{len(rows) - 1} rows")
            hib = next(r for r in dlg._res["rows"] if r["state"] == "Hibernate")
            # Codex SA-1: "around this start/end" anchors on the displayed
            # boundary, not on the evidence event's own time (a wake record).
            seen = []
            real = w._open_around_tab
            w._open_around_tab = lambda a, b_, a_, sc, *x, **k: seen.append(a)
            for what, e_, at_ in dlg.around_targets(hib, timeline=True):
                dlg.go_around(e_, timedelta(minutes=5), at_)
            w._open_around_tab = real
            from evtx_tool.core.time_window import parse_event_ts
            got_t = [parse_event_ts(a["timestamp"]).replace(tzinfo=None) for a in seen]
            check(f"{tag}: Around anchors on the displayed start and end, keeping the evidence record",
                  got_t == [hib["start"], hib["end"]]
                  and all(a.get("record_id") == hib["start_ev"]["record_id"] for a in seen[:1]),
                  f"{got_t} vs {[hib['start'], hib['end']]}")
            before = set(k for k in w._file_tabs if k.startswith("__around__"))
            dlg.go_around(hib["start_ev"], timedelta(minutes=5), hib["start"])
            T.pump(300)
            new = [k for k in w._file_tabs if k.startswith("__around__") and k not in before]
            if new:
                T.settle(w, new[0])
            check(f"{tag}: 'Events around this start' opens an Around tab on the evidence event", len(new) == 1,
                  str(len(new)))
            dlg.close()
        finally:
            T.teardown(w, jm, m)
            if tmp:
                shutil.rmtree(tmp, ignore_errors=True)
    check("both modes show identical periods", results.get("Normal") == results.get("Juggernaut"))
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
