"""Juggernaut correlation sees the same time windows as Normal Mode (Codex CK91-5).

Juggernaut stores timestamps as "YYYY-MM-DD HH:MM:SS.ffffff" (no "T", no "Z").
The analysis materialiser handed that form to the correlator, whose _ts() only
read "YYYY-MM-DDTHH:MM:SS": every time-window rule saw no time at all.  On a
real 3-source / 1,591-record set Normal Mode built 13 audit-policy chains and
Juggernaut 0 - missed evidence, with no warning.

Expected:
  * the materialised events carry the same timestamp text Normal Mode has
    ("YYYY-MM-DDTHH:MM:SS.ffffffZ");
  * _ts() reads both forms to the same instant (defence in depth);
  * correlate() builds the same chains from either form.
Synthetic data only.
"""
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events(ts_form):
    """Three Security logons then an audit-policy change (4719), same host, minutes apart."""
    out = []
    for i, (eid, minute) in enumerate(((4624, 0), (4624, 5), (4672, 10), (4719, 20)), 1):
        t = f"2024-01-02T03:{minute:02d}:05.123456Z"
        if ts_form == "jm":
            t = t.replace("T", " ").replace("Z", "")
        out.append({"record_id": i, "event_id": eid, "timestamp": t, "channel": "Security",
                    "provider": "Microsoft-Windows-Security-Auditing", "computer": "HOST-A",
                    "level_name": "Information", "event_data": {"SubjectUserName": "u1"},
                    "source_file": "C:\\x\\Security.evtx"})
    return out


def materialise(tmp):
    import pyarrow as pa
    import pyarrow.parquet as pq
    from PySide6.QtCore import QEventLoop, QTimer
    from evtx_tool.gui.main_window import _JMAnalysisMaterializeWorker
    evs = events("jm")
    cols = {
        "record_id": [e["record_id"] for e in evs], "event_id": [e["event_id"] for e in evs],
        "level_name": [e["level_name"] for e in evs], "timestamp_utc": [e["timestamp"] for e in evs],
        "channel": [e["channel"] for e in evs], "provider": [e["provider"] for e in evs],
        "event_source_name": [""] * 4, "computer": [e["computer"] for e in evs],
        "user_id": [""] * 4, "keywords": [""] * 4, "source_file": [e["source_file"] for e in evs],
        "event_data_json": [json.dumps(e["event_data"]) for e in evs],
        "event_record_id": [e["record_id"] for e in evs],
    }
    shard = os.path.join(tmp, "s0.parquet")
    pq.write_table(pa.table(cols), shard)
    with open(os.path.join(tmp, "parquet_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump([shard.replace("\\", "/")], fh)
    w = _JMAnalysisMaterializeWorker(tmp)
    got = {}
    loop = QEventLoop()
    w.finished_ok.connect(lambda e: (got.update(e=e), loop.quit()))
    w.failed.connect(lambda m: (got.update(err=m), loop.quit()))
    QTimer.singleShot(60000, loop.quit)
    w.start(); loop.exec(); w.wait(10000)
    return got


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])           # noqa: F841
    from evtx_tool.analysis import correlator as C

    a = C._ts("2024-01-02T03:04:05.123456Z")
    b = C._ts("2024-01-02 03:04:05.123456")
    check("_ts reads the Juggernaut storage form", b is not None and a == b, f"{a!r} vs {b!r}")

    normal = C.correlate(events("normal"))
    jm_raw = C.correlate(events("jm"))
    check("correlation finds the audit-policy chain (test is not vacuous)", len(normal) >= 1, str(len(normal)))
    check("correlation builds the same chains from the Juggernaut timestamp form",
          len(jm_raw) == len(normal), f"normal={len(normal)} jm={len(jm_raw)}")

    tmp = tempfile.mkdtemp(prefix="jmcorrts_")
    try:
        got = materialise(tmp)
        jm = got.get("e") or []
        check("materialiser returns every row", len(jm) == 4, got.get("err", str(len(jm))))
        want = [e["timestamp"] for e in events("normal")]
        have = [e.get("timestamp") for e in jm]
        check("materialised timestamps equal Normal Mode's text", have == want, f"{have[:1]} vs {want[:1]}")
        chains = C.correlate(jm)
        check("correlation on materialised Juggernaut events matches Normal",
              len(chains) == len(normal), f"normal={len(normal)} jm={len(chains)}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
