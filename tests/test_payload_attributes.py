"""Data held in XML attributes of the event data is shown and searchable.

Some providers write values as attributes, not element text: the certificate
lifecycle events carry <CertificateDetails Thumbprint="..."/> and
<CertNotificationData ProcessName="..." AccountName="..." Context="..."/>, an
EKU its OID.  The exports wrote them, but the detail pane hid every attribute
and text search skipped them: a search for a thumbprint found nothing.

Synthetic part: the detail-pane text and the search values hold attribute
values; namespace declarations and the Name label of <Data> / <ComplexData>
stay out.
Corpus part (EVTX_TEST_LOGS / EVTX_TEST_LOGS_ONLINE): every attribute value
Windows' EventLogReader (Get-WinEvent) shows in such logs is in the detail-pane
text and the search values (Normal mode) and in the ed_values search column
(Juggernaut).

Run: QT_QPA_PLATFORM=offscreen python tests/test_payload_attributes.py
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import multiprocessing as mp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

RES = []
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MARKERS = [m.encode("utf-16-le") for m in ("CertificateDetails", "CertNotificationData")]


def check(name, ok, detail=""):
    RES.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))


def pane_fn():
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow
    return MainWindow._flatten_ev_val


def pane_text(ed):
    f = pane_fn()
    return "\n".join(filter(None, (f(v) for v in ed.values())))


def synthetic():
    from evtx_tool.core.filters import flatten_searchable_values
    ed = {"CertNotificationData": {
        "#attributes": {"xmlns": "urn:ns-zzq", "ProcessName": "proc-zzq.exe",
                        "AccountName": "acct-zzq", "Context": "ctx-zzq"},
        "CertificateDetails": {"#attributes": {"Thumbprint": "AB12CD34ZZQ"},
                               "EKUs": {"EKU": [{"#attributes": {"Name": "eku-name-zzq",
                                                                 "OID": "1.2.3.4.zzq"}}]}}},
          "Data": [{"#attributes": {"Name": "Label-zzq"}, "#text": "value-zzq"}],
          "ComplexData": {"#attributes": {"Name": "Complex-label-zzq"}, "#text": "complex-zzq"}}
    want = ["proc-zzq.exe", "acct-zzq", "ctx-zzq", "AB12CD34ZZQ", "eku-name-zzq", "1.2.3.4.zzq",
            "value-zzq", "complex-zzq"]
    pane = pane_text(ed)
    miss = [w for w in want if w not in pane]
    check("detail pane shows attribute values", not miss, f"missing {miss}")
    check("detail pane leaves out namespace declarations", "urn:ns-zzq" not in pane)
    sv = flatten_searchable_values(ed)
    miss = [w for w in want if w not in sv]
    check("search reaches attribute values", not miss, f"missing {miss}")
    check("search leaves out xmlns", "urn:ns-zzq" not in sv)
    check("search leaves out the Name label of Data / ComplexData",
          "Label-zzq" not in sv and "Complex-label-zzq" not in sv, repr(sv))
    check("plain fields unchanged", flatten_searchable_values({"A": "1", "B": ["2", "3"]}) == ["1", "2", "3"])


def windows_attrs(files):
    """(file, EventRecordID) -> attribute values in the payload, per Get-WinEvent."""
    ps = r"""
param([string]$List)
foreach ($p in Get-Content -LiteralPath $List -Encoding UTF8) {
  try { Get-WinEvent -Path $p -Oldest -ErrorAction Stop | ForEach-Object {
      "R`t$p`t" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_.ToXml())) } }
  catch { "E`t$p`t$($_.Exception.GetType().Name)" }
}
"""
    tmp = tempfile.mkdtemp(prefix="pattr_")
    try:
        lst, scr = os.path.join(tmp, "l.txt"), os.path.join(tmp, "s.ps1")
        with open(lst, "w", encoding="utf-8") as fh:
            fh.write("\n".join(files) + "\n")
        with open(scr, "w", encoding="utf-8") as fh:
            fh.write(ps)
        out = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", scr, "-List", lst],
                             capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900).stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    recs = {}
    for line in out.splitlines():
        p = line.split("\t")
        if p[0] != "R" or len(p) != 3:
            continue
        r = ET.fromstring(base64.b64decode(p[2]).decode("utf-8"))
        vals = []
        for part in r:
            tag = part.tag.split("}")[-1]
            if tag in ("System", "RenderingInfo"):
                continue
            for el in part.iter():
                if el is part:
                    continue        # <EventData Name=...>: the template's name
                et = el.tag.split("}")[-1]
                for a, v in el.attrib.items():
                    an = a.split("}")[-1]
                    if an.startswith("xmlns") or (an == "Name" and et in ("Data", "ComplexData")) or not v:
                        continue
                    vals.append(v)
        if vals:
            rid = int(r.find(f"{NS}System/{NS}EventRecordID").text)
            recs[(os.path.normcase(p[1]), rid)] = vals
    return recs


def corpus():
    roots = [os.environ.get(k) for k in ("EVTX_TEST_LOGS", "EVTX_TEST_LOGS_ONLINE")]
    roots = [r for r in roots if r and os.path.isdir(r)]
    if not roots or os.name != "nt":
        print("SKIP  corpus part (no EVTX_TEST_LOGS or not Windows)")
        return
    files = []
    for root in roots:
        for d, _, fs in os.walk(root):
            for f in fs:
                p = os.path.join(d, f)
                if f.lower().endswith(".evtx") and os.path.getsize(p) <= 50 << 20:
                    with open(p, "rb") as fh:
                        b = fh.read()
                    if any(m in b for m in MARKERS):
                        files.append(p)
    if not files:
        print("SKIP  corpus part (no certificate lifecycle log)")
        return
    truth = windows_attrs(files)
    n = sum(len(v) for v in truth.values())
    check(f"Windows shows attribute values ({len(files)} files)", n > 0, f"{len(truth)} records, {n} values")

    from evtx_tool.core.engine import ProcessingEngine
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.core.filters import flatten_searchable_values
    import duckdb

    evs = {(os.path.normcase(e["source_file"]), e["event_record_id"]): e.get("event_data") or {}
           for e in ProcessingEngine(max_workers=2).run(files, None)}
    miss_pane = miss_search = missing = 0
    for k, vals in truth.items():
        ed = evs.get(k)
        if ed is None:
            missing += 1
            continue
        pane = pane_text(ed)
        sv = flatten_searchable_values(ed)
        miss_pane += sum(1 for v in vals if v not in pane)
        miss_search += sum(1 for v in vals if not any(v in s for s in sv))
    check("Normal: every record found", missing == 0, f"{missing} missing")
    check("Normal: every attribute value in the detail pane", miss_pane == 0, f"{miss_pane} of {n} hidden")
    check("Normal: every attribute value searchable", miss_search == 0, f"{miss_search} of {n} unsearchable")

    tmp = tempfile.mkdtemp(prefix="pattr_jm_")
    try:
        pq = os.path.join(tmp, "pq")
        HeavyweightEngine(parquet_dir=pq).run(files)
        with open(os.path.join(pq, "parquet_manifest.json")) as fh:
            shards = json.load(fh)
        rows = duckdb.connect().execute(
            "select source_file, event_record_id, ed_values from read_parquet(?)", [shards]).fetchall()
        jm = {(os.path.normcase(s), r): v or "" for s, r, v in rows}
        miss = sum(1 for k, vals in truth.items() for v in vals if v not in jm.get(k, ""))
        check("Juggernaut: every attribute value in the search column", miss == 0, f"{miss} of {n} unsearchable")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    synthetic()
    corpus()
    print(f"\n{sum(RES)}/{len(RES)} checks passed")
    return 0 if all(RES) else 1


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
