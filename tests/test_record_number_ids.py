"""Both modes carry the record header number AND the XML EventRecordID, as EvtxECmd does.

Codex audit-5 E5-16: every EVTX record has two IDs.  The record header holds
the record's number in this file; the XML <System><EventRecordID> holds the
number Windows gave the event when it was logged.  They match in a log
collected whole, and differ in a file saved as part of a larger log (the
header restarts at 1, the XML keeps the original numbers).  Normal mode showed
only the header number, Juggernaut only the XML one, so one event read two
different IDs across the modes, and Event Viewer (which shows the XML one)
matched only Juggernaut.  Worse, Juggernaut told events apart by the XML ID,
which can repeat inside one file: one bookmark selected two events.

User decision (2026-11-05): "let's do like evtxcmd recordnumber and
eventrecordid".  Expected, in both modes: record_id is the header number (it
tells events apart), event_record_id is the XML EventRecordID; the grid shows
"Record Number" and "Event Record ID"; CSV exports RecordNumber and
EventRecordID, JSON record_id and event_record_id.

Ground truth comes from outside EventHawk's parser: header numbers read
straight from the EVTX bytes, XML IDs from Windows' own event-log API
(Get-WinEvent, what Event Viewer uses).  Corpus: the public attack samples
(EVTX_TEST_SAMPLES, default C:\\Users\\Czar\\EventHawk-samples\\EVTX-ATTACK-SAMPLES),
where the two IDs differ on tens of thousands of records.  Counts only.
"""
import csv
import glob
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def raw_header_numbers(path):
    """Record numbers from the record headers, read from the file bytes."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[:8] != b"ElfFile\x00":
        return None
    out, off = [], 4096
    while off + 512 <= len(data):
        ch = data[off:off + 65536]
        if ch[:8] == b"ElfChnk\x00":
            end = min(int.from_bytes(ch[48:52], "little"), len(ch))
            p = 512
            while p + 24 <= end and ch[p:p + 4] == b"\x2a\x2a\x00\x00":
                size = int.from_bytes(ch[p + 4:p + 8], "little")
                out.append(int.from_bytes(ch[p + 8:p + 16], "little"))
                if size < 24:
                    break
                p += size
        off += 65536
    return out


def windows_xml_ids(files, tmp):
    """{file index: [XML EventRecordID in file order]} via Get-WinEvent."""
    lst = os.path.join(tmp, "files.txt")
    with open(lst, "w", encoding="utf-8") as fh:
        fh.write("\n".join(files))
    script = os.path.join(tmp, "xmlids.ps1")
    with open(script, "w", encoding="utf-8") as fh:
        fh.write(
            "$ErrorActionPreference = 'Stop'\n$i = 0\n"
            f"foreach ($f in [IO.File]::ReadAllLines('{lst}')) {{\n"
            "  try { Get-WinEvent -Path $f -Oldest | ForEach-Object {\n"
            "      [string]$i + [char]9 + ([xml]$_.ToXml()).Event.System.EventRecordID } }\n"
            "  catch { [string]$i + [char]9 + 'ERR' }\n"
            "  $i++\n}\n")
    res = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script],
                         capture_output=True, text=True, encoding="utf-8", errors="replace")
    got, bad = {}, set()
    for ln in res.stdout.splitlines():
        if "\t" not in ln:
            continue
        i, v = ln.split("\t", 1)
        if v.strip() == "ERR":
            bad.add(int(i))
        else:
            got.setdefault(int(i), []).append(int(v))
    return got, bad


def pair_mismatch(truth, rows, tag):
    """Files whose (record_id, event_record_id) multiset differs from the truth."""
    by_file = {}
    for sf, rid, xid in rows:
        by_file.setdefault(os.path.normcase(sf), Counter())[(rid, xid)] += 1
    bad = [f for f, c in truth.items() if by_file.get(f, Counter()) != c]
    n = sum(sum(c.values()) for c in truth.values())
    check(f"{tag}: every record carries header number and XML EventRecordID",
          n > 0 and not bad, f"{len(bad)} of {len(truth)} files differ; {n:,} records compared")


def main() -> int:
    root = os.environ.get("EVTX_TEST_SAMPLES",
                          r"C:\Users\Czar\EventHawk-samples\EVTX-ATTACK-SAMPLES")
    if not os.path.isdir(root):
        print(f"sample corpus not found ({root}) -- skipped")
        return 0
    files = sorted(glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True))
    tmp = tempfile.mkdtemp(prefix="recnum_")
    try:
        print(f"{len(files)} files; reading ground truth", flush=True)
        win, win_err = windows_xml_ids(files, tmp)
        truth, skipped, n_diff = {}, [], 0
        for i, fp in enumerate(files):
            hdr = raw_header_numbers(fp)
            xml = win.get(i, [])
            if hdr is None or i in win_err or len(hdr) != len(xml):
                skipped.append((len(hdr or []), len(xml)))
                continue
            truth[os.path.normcase(fp)] = Counter(zip(hdr, xml))
            n_diff += sum(1 for h, x in zip(hdr, xml) if h != x)
        n_truth = sum(sum(c.values()) for c in truth.values())
        print(f"ground truth: {len(truth)} files, {n_truth:,} records, header != XML on {n_diff:,}; "
              f"no usable truth for {len(skipped)} files (header/Windows record counts: {skipped[:6]})")
        check("the corpus exercises the case (header and XML IDs differ)", n_diff > 0, f"{n_diff:,}")

        # ── Normal mode ──────────────────────────────────────────────────────
        from evtx_tool.core.engine import ProcessingEngine
        events = ProcessingEngine(max_workers=2).run(files, None)
        pair_mismatch(truth, [(e.get("source_file", ""), e.get("record_id"), e.get("event_record_id"))
                              for e in events], "Normal")

        # ── Juggernaut mode ──────────────────────────────────────────────────
        from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
        pq = HeavyweightEngine(parquet_dir=os.path.join(tmp, "pq")).run(files)
        table = load_arrow_table(pq)
        cols = set(table.column_names)
        jrows = list(zip(table.column("source_file").to_pylist(), table.column("record_id").to_pylist(),
                         table.column("event_record_id").to_pylist() if "event_record_id" in cols
                         else [None] * len(table)))
        pair_mismatch(truth, jrows, "Juggernaut")
        keys = Counter((os.path.normcase(sf), rid) for sf, rid, _x in jrows)
        dup = sum(c - 1 for c in keys.values() if c > 1)
        check("Juggernaut: (file, record_id) names exactly one event", dup == 0,
              f"{dup} events share a key with another")

        # ── Grid: both columns, both modes ───────────────────────────────────
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QApplication
        _app = QApplication.instance() or QApplication([])
        from evtx_tool.gui import models as M
        from evtx_tool.gui.heavyweight_model import ArrowTableModel
        cn, cx = getattr(M, "COL_RECORD_ID", None), getattr(M, "COL_EVENT_RECORD_ID", None)
        check("grid columns are titled Record Number and Event Record ID",
              cn is not None and cx is not None and M.COLUMNS[cn] == "Record Number"
              and M.COLUMNS[cx] == "Event Record ID", str(M.COLUMNS[18:]))
        if cx is not None:
            nm = M.EventTableModel()
            nm.set_events(events)
            bad = sum(1 for r in range(nm.rowCount())
                      if nm.data(nm.index(r, cn), Qt.ItemDataRole.DisplayRole) != str(events[r]["record_id"])
                      or nm.data(nm.index(r, cx), Qt.ItemDataRole.DisplayRole)
                      != ("" if events[r].get("event_record_id") is None
                          else str(events[r]["event_record_id"])))
            check("Normal grid shows both IDs on every row", bad == 0, f"{bad} of {nm.rowCount()} rows wrong")
            jm = ArrowTableModel(table, parquet_dir=pq)
            want = {(sf, rid): x for sf, rid, x in jrows}
            bad = 0
            # The row's key from the model's own table (get_event would also
            # fetch each row's EventData from Parquet: one query per row).
            _dsf = jm._display_table.column("source_file").to_pylist()
            _drid = jm._display_table.column("record_id").to_pylist()
            for r in range(jm.rowCount()):
                k = (_dsf[r], _drid[r])
                if (jm.data(jm.index(r, cn), Qt.ItemDataRole.DisplayRole) != str(k[1])
                        or jm.data(jm.index(r, cx), Qt.ItemDataRole.DisplayRole)
                        != ("" if want.get(k) is None else str(want[k]))):
                    bad += 1
            check("Juggernaut grid shows both IDs on every row", bad == 0, f"{bad} of {jm.rowCount()} rows wrong")
            jm.close()

        # ── Exports: CSV RecordNumber / EventRecordID, JSON both keys ────────
        from evtx_tool.output.exporters import export_csv, export_json
        from test_export_parity import jm_export, read_csv
        export_csv(events, os.path.join(tmp, "n.csv"))
        export_json(events, os.path.join(tmp, "n.json"))
        e1 = jm_export(table, pq, os.path.join(tmp, "j.csv"), "csv")
        e2 = jm_export(table, pq, os.path.join(tmp, "j.json"), "json")
        check("JM exports ran", not e1 and not e2, f"{e1} {e2}")
        for tag, name in (("Normal", "n"), ("Juggernaut", "j")):
            _bom, hdr, rows = read_csv(os.path.join(tmp, f"{name}.csv"))
            ok = "RecordNumber" in hdr and "EventRecordID" in hdr
            check(f"{tag} CSV has RecordNumber and EventRecordID columns", ok, str(hdr[:4]))
            if ok:
                pair_mismatch(truth, [(r["SourceFile"], int(r["RecordNumber"]),
                                       int(r["EventRecordID"]) if r["EventRecordID"] else None)
                                      for r in rows], f"{tag} CSV")
            with open(os.path.join(tmp, f"{name}.json"), encoding="utf-8") as fh:
                js = json.load(fh)
            pair_mismatch(truth, [(e.get("source_file", ""), e.get("record_id"), e.get("event_record_id"))
                                  for e in js], f"{tag} JSON")
        del table
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
