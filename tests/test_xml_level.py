"""XML export keeps every numeric level, 0 included, in both modes.

Codex release audit C3: the lxml path wrote `ev.get(key) or ""`, so a level of
0 (LogAlways -- the level of most classic events) became an empty <Level/>;
on a 46,748-record selection Normal XML blanked 35,681 levels.  Juggernaut's
export rebuilt its rows without a "level" key at all and blanked every one.
A level the log does not carry stays empty; a 0 the log carries stays 0.
Synthetic data only.
"""
import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtCore import QEventLoop, QTimer                       # noqa: E402
from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def levels(path):
    root = ET.parse(path).getroot()
    out = {}
    for e in root.iter("Event"):
        s = e.find("System")
        out[s.findtext("RecordNumber")] = s.findtext("Level") or ""
    return out


def ev(rid, level):
    return {"record_id": rid, "event_id": 1, "timestamp": "2024-01-01T00:00:00.000000Z", "channel": "System",
            "provider": "P", "computer": "C", "level": level, "level_name": "x", "source_file": r"C:\s\System.evtx",
            "event_data": {}}


def main() -> int:
    from evtx_tool.output.exporters import export
    tmp = tempfile.mkdtemp(prefix="xml_level_")
    p = os.path.join(tmp, "normal.xml")
    export([ev(1, 0), ev(2, 4), ev(3, None)], p, None)
    got = levels(p)
    check("Normal XML: level 0 stays 0", got.get("1") == "0", str(got))
    check("Normal XML: level 4 stays 4", got.get("2") == "4", str(got))
    check("Normal XML: a missing level stays empty", got.get("3") == "", str(got))

    # Juggernaut: one shard holding levels 0 and 4, exported by the real worker.
    import pyarrow as pa
    import pyarrow.parquet as pq
    from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME, _make_schema, load_arrow_table
    from evtx_tool.gui.main_window import _JMExportWorker
    rows = [{"record_id": rid, "event_id": 1, "level": lvl, "level_name": "x",
             "timestamp_utc": "2024-01-01 00:00:00.000000", "channel": "System", "provider": "P",
             "computer": "C", "source_file": r"C:\s\System.evtx", "event_data_json": "{}"}
            for rid, lvl in ((1, 0), (2, 4))]
    shard = os.path.join(tmp, "s0.parquet")
    pq.write_table(pa.Table.from_pylist(rows, schema=_make_schema()), shard)
    with open(os.path.join(tmp, _MANIFEST_FILENAME), "w", encoding="utf-8") as fh:
        json.dump([shard], fh)
    table = load_arrow_table(tmp)
    out = os.path.join(tmp, "jm.xml")
    w = _JMExportWorker(table, [shard], "1=1", [], "record_id ASC", out, "xml", len(table))
    loop, res = QEventLoop(), {}
    w.finished_ok.connect(lambda n, path: (res.update(ok=True), loop.quit()))
    w.failed.connect(lambda m: (res.update(ok=False, msg=m), loop.quit()))
    QTimer.singleShot(60_000, loop.quit)
    w.start()
    loop.exec()
    w.wait(10_000)
    check("Juggernaut XML export completes", res.get("ok"), str(res.get("msg"))[:200])
    if res.get("ok"):
        got = levels(out)
        check("Juggernaut XML: level 0 stays 0", got.get("1") == "0", str(got))
        check("Juggernaut XML: level 4 stays 4", got.get("2") == "4", str(got))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
