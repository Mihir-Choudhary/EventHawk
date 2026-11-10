"""Repeated <Data Name="X"> values are all kept (Codex FO-1, final output check).

An event can carry several Data elements with the same name: System 1046
lists one <Data Name="Files"> per file.  pyevtx-rs writes them as one JSON
object with the key repeated, and every JSON reader keeps only the LAST
value: on a real System log 83 Files values were read as 27, in every view and
export, in both modes.  Expected: a repeated name keeps every value, in order,
as a list; records without repeats parse exactly as before.

Part 1 is synthetic.  Part 2 (EVTX_TEST_LOGS, counts only) parses a real
System log through the real window in Normal and Juggernaut mode and checks
the repeated values against the record XML pyevtx-rs renders (an independent
rendering path: XML, not JSON).

Run: QT_QPA_PLATFORM=offscreen python tests/test_repeated_data_names.py
"""
import json
import os
import re
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


RAW_DUP = ('{\n  "Event": {\n    "#attributes": {"xmlns": "x"},\n    "System": {"EventID": 1046, '
           '"Provider": {"#attributes": {"Name": "P"}}},\n    "EventData": {\n      "FilesCount": "3",\n'
           '      "Files": "C:\\\\one.dll",\n      "Files": "C:\\\\two.dll",\n      "Files": "C:\\\\three.dll"\n'
           '    }\n  }\n}')
RAW_NESTED = ('{"Event": {"System": {"EventID": 2}, "UserData": {"Op": {"Item": "a", "Item": "b", '
              '"Name": "n"}}}}')
RAW_PLAIN = ('{"Event": {"System": {"EventID": 4104}, "EventData": {"ScriptBlockText": '
             '"$x = @{\\"a\\": 1}; \\"k\\": v", "Path": ""}}}')


def part1():
    print("=== 1. synthetic ===")
    try:
        from evtx_tool.core.record_json import load_record
    except ImportError as exc:
        check("load_record exists", False, repr(exc))
        return
    import orjson
    ed = load_record(RAW_DUP)["Event"]["EventData"]
    check("a repeated name keeps every value, in order",
          ed.get("Files") == ["C:\\one.dll", "C:\\two.dll", "C:\\three.dll"], str(ed.get("Files")))
    check("the other fields are unchanged", ed.get("FilesCount") == "3")
    ud = load_record(RAW_NESTED)["Event"]["UserData"]["Op"]
    check("a repeated name inside UserData too", ud.get("Item") == ["a", "b"] and ud.get("Name") == "n", str(ud))
    check("a record with no repeats parses exactly as before (value holding \"x\": text)",
          load_record(RAW_PLAIN) == orjson.loads(RAW_PLAIN))
    check("bytes input works too", load_record(RAW_DUP.encode())["Event"]["EventData"]["Files"][2] == "C:\\three.dll")
    from evtx_tool.core.parser import _extract_from_json
    ev = _extract_from_json(load_record(RAW_DUP), 1, "2024-01-02T03:04:05Z", "s.evtx")
    check("the event's data holds all three", ev["event_data"].get("Files") == ed["Files"])


def truth_from_xml(path):
    """{record_id: {name: [values]}} for names repeated in a record, from the XML rendering."""
    from evtx import PyEvtxParser
    out = {}
    for rec in PyEvtxParser(path).records():
        names = re.findall(r'<Data Name="([^"]*)"', rec["data"])
        dup = {n for n in names if names.count(n) > 1}
        if dup:
            vals = {}
            for n, v in re.findall(r'<Data Name="([^"]*)">([^<]*)</Data>', rec["data"]):
                if n in dup:
                    vals.setdefault(n, []).append(v)
            out[rec["event_record_id"]] = vals
    return out


def part2():
    root = os.environ.get("EVTX_TEST_LOGS", "")
    path = os.path.join(root, "System.evtx") if root else ""
    if not path or not os.path.exists(path):
        print("=== 2. real log: SKIPPED (set EVTX_TEST_LOGS with a System.evtx) ===")
        return
    print("=== 2. real System log, both modes ===")
    truth = truth_from_xml(path)
    n_vals = sum(len(v) for d in truth.values() for v in d.values())
    check("independent XML: the log has repeated names", n_vals > 0,
          f"{len(truth)} records, {n_vals} repeated values")
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])
    for n in ("warning", "critical", "information"):
        setattr(QMessageBox, n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    from evtx_tool.gui.main_window import MainWindow
    MainWindow._warn_blocking = lambda self, *a, **k: None

    def pump(sec, until=None):
        end = time.time() + sec
        while time.time() < end:
            app.processEvents(); time.sleep(0.02)
            if until and until():
                return True
        return False

    def got_normal():
        w = MainWindow()
        w._add_path(path)
        w._on_parse_clicked()
        pump(300, lambda: w._active_proxy is not None and w._active_proxy.rowCount() > 0
             and w._btn_parse.isEnabled())
        pump(2)
        out = {e.get("record_id"): e.get("event_data") or {} for e in w._active_events
               if e.get("record_id") in truth}
        w.close(); pump(0.5)
        return out

    def got_jm():
        w = MainWindow()
        w._launch_juggernaut_mode([path])
        pump(400, lambda: w._hw_model is not None and w._hw_model.rowCount() > 0)
        pump(3)
        import duckdb
        con = duckdb.connect()
        glob = os.path.join(w._hw_db_path, "**", "*.parquet").replace("\\", "/")
        out = {}
        for rid, ed in con.execute(f"SELECT record_id, event_data_json FROM read_parquet('{glob}')").fetchall():
            if rid in truth:
                out[rid] = json.loads(ed) if ed else {}
        con.close()
        w.close(); pump(0.5)
        return out

    for mode, fn in (("Normal", got_normal), ("Juggernaut", got_jm)):
        got = fn()
        bad = 0
        kept = 0
        for rid, names in truth.items():
            ed = got.get(rid, {})
            for n, vals in names.items():
                g = ed.get(n)
                g = g if isinstance(g, list) else ([] if g is None else [g])
                kept += len(g)
                if [str(x) for x in g] != vals:
                    bad += 1
        check(f"{mode}: every repeated value kept, in order", bad == 0 and kept == n_vals,
              f"{kept}/{n_vals} values kept; {bad} field(s) differ; {len(got)}/{len(truth)} records found")


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    part1()
    part2()
    n = sum(ok for _, ok in CHECKS)
    print(f"\n{n}/{len(CHECKS)} checks passed")
    sys.exit(0 if n == len(CHECKS) else 1)
