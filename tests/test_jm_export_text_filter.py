"""Juggernaut "current view" export writes exactly the events the view shows (Codex FO-9).

A text search in Juggernaut mode is evaluated in two phases: a SQL WHERE over
the Arrow table, then a full-text pass over the Parquet shards.  The export
re-ran only the WHERE: with a text search active, CSV/JSON wrote every event
(83,851 instead of 2,898) and HTML/XML wrote the right number of the WRONG
events.  Expected: every format writes the view's own events, checked against
the core evaluator (passes_filter) on the same events.  Synthetic data.
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

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


WORDS = ["alpha beta", "alpha", "beta gamma", "delta", "alpha beta gamma"]


def write_jm(evs, tmp):
    import pyarrow as pa
    import pyarrow.parquet as pq
    from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME, _make_schema, load_arrow_table
    rows = []
    for e in evs:
        t = e["timestamp"]
        rows.append({"record_id": e["record_id"], "event_id": e["event_id"], "level": 4,
                     "level_name": "Information",
                     "timestamp_utc": t.replace("T", " ").replace("Z", "")[:26],
                     "channel": e["channel"], "provider": e["provider"], "computer": e["computer"],
                     "source_file": e["source_file"], "event_data_json": json.dumps(e["event_data"]),
                     "ed_values": " ".join(str(v) for v in e["event_data"].values()),
                     "ed_flat_json": json.dumps(e["event_data"])})
    shard = os.path.join(tmp, "s0.parquet")
    pq.write_table(pa.Table.from_pylist(rows, schema=_make_schema()), shard)
    with open(os.path.join(tmp, _MANIFEST_FILENAME), "w", encoding="utf-8") as fh:
        json.dump([shard], fh)
    return load_arrow_table(tmp)


def ids_in(path, ext, ts2rid=None):
    if ext == "csv":
        with open(path, encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        key = next(k for k in rows[0] if k.replace(" ", "").lower() in ("recordid", "recordnumber", "record_id"))
        return sorted(int(r[key]) for r in rows)
    if ext == "json":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        evs = data.get("events", data) if isinstance(data, dict) else data
        return sorted(int(e["record_id"]) for e in evs)
    import re
    with open(path, encoding="utf-8") as fh:
        txt = fh.read()
    if ext == "xml":
        return sorted(int(x) for x in re.findall(r"<RecordID>(\d+)</RecordID>", txt)
                      or re.findall(r"<RecordNumber>(\d+)</RecordNumber>", txt))
    # HTML rows carry the timestamp, unique per synthetic event here.
    stamps = [x.replace("T", " ")[:19] for x in re.findall(r"data-ts='([^']*)'", txt)]
    return sorted(ts2rid[x] for x in stamps if x in ts2rid)


def main() -> int:
    from PySide6.QtWidgets import QDialog, QFileDialog
    import evtx_tool.gui.main_window as mw
    from evtx_tool.core.filters import empty_filter, passes_filter

    evs = []
    for i in range(40):
        e = T.ev(r"C:\a\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i),
                 data={"Msg": WORDS[i % len(WORDS)], "N": str(i)})
        evs.append(e)
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    tmp = tempfile.mkdtemp(prefix="jm_txt_")
    m.load(w, table=write_jm(evs, tmp), parquet_dir=tmp)
    w._table.setModel(w._hw_model)
    msgs = []
    w._warn_blocking = lambda title, text, **k: msgs.append(text)
    fmt = {}

    class _Scope(mw._ExportScopeDialog):
        def exec(self):
            self._rb_view.setChecked(True)
            self._fmt_buttons[fmt["ext"]].setChecked(True)
            self._on_ok()
            return QDialog.DialogCode.Accepted

    real = (mw._ExportScopeDialog, QFileDialog.getSaveFileName)
    out = tempfile.mkdtemp(prefix="jm_txt_out_")
    mw._ExportScopeDialog = _Scope
    try:
        for name, cfg in (("AND alpha+beta", dict(empty_filter(), text_search=["alpha", "beta"], search_mode="AND")),
                          ("NOT alpha", dict(empty_filter(), text_search=["alpha"], search_mode="NOT")),
                          ("OR gamma/delta", dict(empty_filter(), text_search=["gamma", "delta"], search_mode="OR"))):
            want = sorted(e["record_id"] for e in evs if passes_filter(e, cfg))
            w._hw_model.apply_filter(cfg)
            T.wait_for(lambda: w._hw_model.rowCount() == len(want), 30); T.pump(300)
            check(f"{name}: the view shows the expected events", w._hw_model.rowCount() == len(want),
                  f"{w._hw_model.rowCount()} vs {len(want)}")
            for ext in ("csv", "json", "xml", "html"):
                fmt["ext"] = ext
                target = os.path.join(out, f"v_{len(want)}_{ext}.{ext}")
                QFileDialog.getSaveFileName = staticmethod(lambda *a, _t=target, **k: (_t, ""))
                n0 = len(msgs)
                w._export_juggernaut()
                T.wait_for(lambda: len(msgs) > n0, 60); T.pump(200)
                try:
                    got = ids_in(target, ext, {e["timestamp"].replace("T", " ")[:19]: e["record_id"] for e in evs})
                except Exception as exc:                       # noqa: BLE001
                    got = repr(exc)
                check(f"{name}: {ext.upper()} export = the view's events", got == want,
                      f"{len(got) if isinstance(got, list) else got} vs {len(want)}; {msgs[n0:][:1]}")
    finally:
        mw._ExportScopeDialog, QFileDialog.getSaveFileName = real
        w.close(); T.pump(100)
        shutil.rmtree(out, ignore_errors=True)
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"\n{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
