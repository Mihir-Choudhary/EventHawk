"""Custom columns are included in exports (spec R-7).

Spec item 4: the extracted value is "included in exports"; R-7: the custom
columns of the tab an export is started from go into every export scope and
format -- CSV / HTML columns, JSON / XML fields named by the column title --
and events outside a column's filter get an empty value.  Without custom
columns every file is what it was before (CSV and JSON byte-identical).
Normal and Juggernaut, synthetic events.
"""
import csv
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
ODD = 'Odd, "title" <x>'


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events():
    out = []
    for i, (eid, lt) in enumerate([(4624, "3"), (4625, "3"), (4624, "10"), (4624, None), (4624, "")]):
        # the last event has EMPTY EventData (audit-5 E5-03: XML dropped its custom fields)
        out.append(T.ev(r"C:\c\Security.evtx", i + 1, f"HOST-{i}", T.T0 + timedelta(seconds=i), eid,
                        data={"LogonType": lt} if lt else ({"X": "y"} if lt is None else {})))
    return out


WANT_LT = ["3", "", "10", "", ""]          # 4625 is outside the column's Event ID filter


def columns():
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec
    return [compile_spec(CustomColumnSpec(col_id=301, title="Logon Type", template="{Data[LogonType]}",
                                          eid_expr="4624", kind="int")),
            compile_spec(CustomColumnSpec(col_id=302, title=ODD, template="{Computer}"))]


def read_outputs(folder, base):
    out = {}
    with open(os.path.join(folder, base + ".csv"), encoding="utf-8-sig") as fh:
        out["csv"] = list(csv.DictReader(fh))
    with open(os.path.join(folder, base + ".json"), encoding="utf-8") as fh:
        out["json"] = json.load(fh)
    with open(os.path.join(folder, base + ".xml"), encoding="utf-8") as fh:
        out["xml"] = fh.read()
    with open(os.path.join(folder, base + ".html"), encoding="utf-8") as fh:
        out["html"] = fh.read()
    return out


def assert_outputs(tag, o):
    by_rid = lambda rows, key: [r for r in sorted(rows, key=lambda r: int(r[key]))]      # noqa: E731
    rows = by_rid(o["csv"], "RecordID")
    check(f"{tag} CSV: a column per custom column, values exact (empty outside the filter)",
          [r.get("Logon Type") for r in rows] == WANT_LT and [r.get(ODD) for r in rows] == [f"HOST-{i}" for i in range(5)],
          str([(r.get("Logon Type"), r.get(ODD)) for r in rows]))
    js = sorted(o["json"], key=lambda e: e["record_id"])
    check(f"{tag} JSON: custom_columns per event, named by title",
          [e.get("custom_columns", {}).get("Logon Type") for e in js] == WANT_LT
          and js[0].get("custom_columns", {}).get(ODD) == "HOST-0", str([e.get("custom_columns") for e in js][:2]))
    x = o["xml"]
    check(f"{tag} XML: a CustomColumns element with the title escaped",
          x.count("<CustomColumns>") == len(WANT_LT) and "Odd, &quot;title&quot; &lt;x&gt;" in x
          and re.search(r'Name="Logon Type">10<', x) is not None, x[x.find("<CustomColumns>"):][:200])
    h = o["html"]
    check(f"{tag} HTML: a header per custom column (escaped) and the values",
          "Logon Type" in h and "Odd, &quot;title&quot; &lt;x&gt;" in h and ">10<" in h)


def main() -> int:
    from PySide6.QtWidgets import QDialog, QFileDialog
    import evtx_tool.gui.main_window as mw
    from evtx_tool.output import exporters
    from evtx_tool.gui.models import compute_custom_values
    from evtx_tool.core.custom_columns import arrow_column_values

    # ── without custom columns nothing changes ─────────────────────────────────
    tmp = tempfile.mkdtemp(prefix="cc_exp_")
    try:
        # (A comparison with the previous exporters module passed before this
        # change landed: CSV and JSON byte-identical.  After it lands that
        # would compare the code with itself, so the lasting check is the
        # layout itself.)
        evs = events()
        exporters.export([dict(e) for e in evs], os.path.join(tmp, "plain.csv"))
        exporters.export([dict(e) for e in evs], os.path.join(tmp, "plain.json"))
        with open(os.path.join(tmp, "plain.csv"), encoding="utf-8-sig") as fh:
            header = next(csv.reader(fh))
        with open(os.path.join(tmp, "plain.json"), encoding="utf-8") as fh:
            plain = json.load(fh)
        # Both XML writers (lxml and the stdlib fallback) write every event's
        # custom columns, including an event with empty EventData.
        from evtx_tool.core.custom_columns import with_custom_columns
        cc_evs = with_custom_columns([dict(e) for e in evs], columns())
        for name, fn in (("lxml", exporters._export_xml_lxml), ("stdlib", exporters._export_xml_stdlib)):
            path = os.path.join(tmp, f"w_{name}.xml")
            fn(cc_evs, path)
            x = open(path, encoding="utf-8").read()
            check(f"XML ({name}): every event has its CustomColumns, empty EventData included",
                  x.count("<CustomColumns>") == len(evs), f"{x.count('<CustomColumns>')} of {len(evs)}")
        # Titles that collide with a built-in header, or with each other once
        # renamed, keep distinct CSV headers and every value (E5-04).
        from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec
        clash = [compile_spec(CustomColumnSpec(col_id=401, title="EventID", template="{Computer}")),
                 compile_spec(CustomColumnSpec(col_id=402, title="EventID (custom)", template="{EventRecordID}")),
                 compile_spec(CustomColumnSpec(col_id=403, title="ED_LogonType", template="{Data[LogonType]}"))]
        path = os.path.join(tmp, "clash.csv")
        exporters.export(with_custom_columns([dict(e) for e in evs], clash), path)
        with open(path, encoding="utf-8-sig") as fh:
            rows_c = list(csv.reader(fh))
        hdr = rows_c[0]
        base = len(exporters.CSV_BASE_KEYS)
        vals = [r[base:base + 3] for r in rows_c[1:]]
        check("clashing custom titles get distinct CSV headers", len(hdr) == len(set(hdr)), str(hdr[base:base + 4]))
        check("...and every custom value is kept",
              vals[0] == ["HOST-0", "1", "3"] and all(v[0] and v[1] for v in vals), str(vals[:2]))
        check("without custom columns the CSV header is the base columns plus EventData only",
              header == exporters.CSV_BASE_KEYS + ["ED_LogonType", "ED_X"], str(header[-4:]))
        check("...and no JSON event has a custom_columns field", not any("custom_columns" in e for e in plain))

        # ── Normal, view and combined scopes ───────────────────────────────────
        for scope in ("view", "combined"):
            folder = os.path.join(tmp, f"normal_{scope}")
            os.makedirs(folder)
            w = mw.MainWindow()
            T.Mode(mw, False).load(w, evs)
            w._per_file_data = {r"C:\c\Security.evtx": {"events": evs}}
            for c in columns():
                w._event_model.add_custom_column(c, compute_custom_values(c, w._event_model._events))
            for ext in ("csv", "json", "xml", "html"):
                class _Scope(mw._ExportScopeDialog):
                    def exec(self, _s=scope):
                        (self._rb_view if _s == "view" else self._rb_combined).setChecked(True)
                        self._on_ok()
                        return QDialog.DialogCode.Accepted
                real = (mw._ExportScopeDialog, QFileDialog.getSaveFileName, mw.QMessageBox.information)
                mw._ExportScopeDialog = _Scope
                QFileDialog.getSaveFileName = staticmethod(
                    lambda *a, _e=ext, **k: (os.path.join(folder, f"out.{_e}"), ""))
                mw.QMessageBox.information = staticmethod(lambda *a, **k: None)
                try:
                    w._on_export_clicked()
                finally:
                    mw._ExportScopeDialog, QFileDialog.getSaveFileName, mw.QMessageBox.information = real
            assert_outputs(f"Normal {scope}:", read_outputs(folder, "out"))
            w.close(); T.pump(50)

        # ── Juggernaut, view and combined scopes ───────────────────────────────
        for scope in ("view", "combined"):
            folder = os.path.join(tmp, f"jm_{scope}")
            os.makedirs(folder)
            w = mw.MainWindow()
            m = T.Mode(mw, True)
            m.load(w, evs)
            w._table.setModel(w._hw_model)
            shards = w._hw_model._get_shard_paths()
            for c in columns():
                w._hw_model.add_custom_column(c, arrow_column_values(c, w._hw_model._full_table, shards))
            T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30); T.pump(300)
            msgs = []
            w._warn_blocking = lambda title, text, **k: msgs.append(text)
            for ext in ("csv", "json", "xml", "html"):
                class _Scope(mw._ExportScopeDialog):
                    def exec(self, _s=scope):
                        (self._rb_view if _s == "view" else self._rb_combined).setChecked(True)
                        self._on_ok()
                        return QDialog.DialogCode.Accepted
                real = (mw._ExportScopeDialog, QFileDialog.getSaveFileName)
                mw._ExportScopeDialog = _Scope
                QFileDialog.getSaveFileName = staticmethod(
                    lambda *a, _e=ext, **k: (os.path.join(folder, f"out.{_e}"), ""))
                try:
                    n0 = len(msgs)
                    w._export_juggernaut()
                    T.wait_for(lambda: len(msgs) > n0, 60); T.pump(200)
                finally:
                    mw._ExportScopeDialog, QFileDialog.getSaveFileName = real
            assert_outputs(f"JM {scope}:", read_outputs(folder, "out"))
            T.teardown(w, True, m)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
