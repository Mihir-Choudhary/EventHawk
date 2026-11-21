"""An event Windows could not render keeps its payload.

When a provider's template does not match the data, Windows stores the event
with <ProcessingErrorData> (ErrorCode, DataItemName, EventPayload) instead of
<EventData>.  EventHawk read only EventData / UserData, so such an event was
shown and exported with no data at all: the raw payload was lost (seen in
AppLocker "MSI and Script", BitLocker Management and AppModel-Runtime logs).

Synthetic part: pick_payload keeps any payload section.
Corpus part (EVTX_TEST_LOGS / EVTX_TEST_LOGS_ONLINE): every record whose XML,
read by Windows' own EventLogReader (Get-WinEvent), holds ProcessingErrorData
has the same ErrorCode, DataItemName and EventPayload in Normal mode and in
Juggernaut.

Run: QT_QPA_PLATFORM=offscreen python tests/test_processing_error_data.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import multiprocessing as mp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

RES = []
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


def check(name, ok, detail=""):
    RES.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))


def leaves(v, out):
    if isinstance(v, dict):
        for k, y in v.items():
            if k != "#attributes":
                leaves(y, out)
    elif isinstance(v, list):
        for y in v:
            leaves(y, out)
    elif v is not None:
        out.append(str(v))
    return out


def synthetic():
    from evtx_tool.core.record_json import pick_payload
    ped = {"ErrorCode": 15005, "DataItemName": "Item", "EventPayload": "41004200"}
    got = pick_payload({"System": {}, "ProcessingErrorData": ped})
    check("ProcessingErrorData is kept", sorted(leaves(got, [])) == sorted(["15005", "Item", "41004200"]), repr(got))
    check("it stays under its own name (the data did not render)", "ProcessingErrorData" in got, repr(got))
    check("EventData still wins when present",
          pick_payload({"EventData": {"A": "1"}, "ProcessingErrorData": ped}) == {"A": "1"})
    check("UserData still read", pick_payload({"UserData": {"X": {"B": "2"}}}) == {"X": {"B": "2"}})
    check("no payload is still {}", pick_payload({"System": {}}) == {})
    check("System / RenderingInfo / attributes are not payload",
          pick_payload({"System": {"a": 1}, "RenderingInfo": {"Message": "m"},
                        "#attributes": {"xmlns": "x"}}) == {})


def windows_records(files):
    """(file, EventRecordID) -> [ErrorCode, DataItemName, EventPayload] from Windows' EventLogReader."""
    ps = r"""
param([string]$List)
foreach ($p in Get-Content -LiteralPath $List -Encoding UTF8) {
  try { Get-WinEvent -Path $p -Oldest -ErrorAction Stop | ForEach-Object {
      $x = $_.ToXml()
      if ($x.Contains('<ProcessingErrorData>')) { "R`t$p`t" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($x)) } } }
  catch { "E`t$p`t$($_.Exception.GetType().Name)" }
}
"""
    tmp = tempfile.mkdtemp(prefix="ped_")
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
    import base64
    recs = {}
    for line in out.splitlines():
        p = line.split("\t")
        if p[0] != "R" or len(p) != 3:
            continue
        r = ET.fromstring(base64.b64decode(p[2]).decode("utf-8"))
        rid = int(r.find(f"{NS}System/{NS}EventRecordID").text)
        ped = r.find(f"{NS}ProcessingErrorData")
        recs[(os.path.normcase(p[1]), rid)] = [(c.text or "") for c in ped]
    return recs


def corpus():
    roots = [os.environ.get(k) for k in ("EVTX_TEST_LOGS", "EVTX_TEST_LOGS_ONLINE")]
    roots = [r for r in roots if r and os.path.isdir(r)]
    if not roots or os.name != "nt":
        print("SKIP  corpus part (no EVTX_TEST_LOGS or not Windows)")
        return
    pat = "ProcessingErrorData".encode("utf-16-le")
    files = []
    for root in roots:
        for d, _, fs in os.walk(root):
            for f in fs:
                p = os.path.join(d, f)
                if f.lower().endswith(".evtx") and os.path.getsize(p) <= 50 << 20:
                    with open(p, "rb") as fh:
                        if pat in fh.read():
                            files.append(p)
    if not files:
        print("SKIP  corpus part (no log with ProcessingErrorData)")
        return
    truth = windows_records(files)
    check(f"Windows reports ProcessingErrorData records ({len(files)} files)", len(truth) > 0, f"{len(truth)} records")

    from evtx_tool.core.engine import ProcessingEngine
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    import duckdb
    import json

    def compare(mode, got):
        bad = []
        for k, vals in truth.items():
            ed = got.get(k)
            if ed is None:
                bad.append((k[1], "record missing"))
                continue
            have = leaves(ed, [])
            if sorted(have) != sorted(vals):
                bad.append((k[1], f"windows {len(vals)} values, eventhawk {len(have)}"))
        check(f"{mode}: every ProcessingErrorData record keeps all its values", not bad,
              f"{len(bad)} of {len(truth)} wrong; first {bad[:3]}")

    evs = ProcessingEngine(max_workers=2).run(files, None)
    compare("Normal", {(os.path.normcase(e["source_file"]), e["event_record_id"]): e.get("event_data")
                       for e in evs})
    tmp = tempfile.mkdtemp(prefix="ped_jm_")
    try:
        pq = os.path.join(tmp, "pq")
        HeavyweightEngine(parquet_dir=pq).run(files)
        with open(os.path.join(pq, "parquet_manifest.json")) as fh:
            shards = json.load(fh)
        rows = duckdb.connect().execute(
            "select source_file, event_record_id, event_data_json from read_parquet(?)", [shards]).fetchall()
        compare("Juggernaut", {(os.path.normcase(s), r): json.loads(j) if j else {} for s, r, j in rows})
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
