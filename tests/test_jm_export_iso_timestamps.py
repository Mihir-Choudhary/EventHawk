"""Juggernaut HTML and XML exports write ISO-8601 UTC timestamps, as Normal mode does.

Gemini audit 4-01 / 6-01 (High): Juggernaut's HTML/XML export path took the
stored "YYYY-MM-DD HH:MM:SS.ffffff" as the event timestamp (the CSV/JSON
path converts it).  In the HTML report the From/To filter compares
data-ts text with "YYYY-MM-DDTHH:MM", and " " sorts before "T", so an event
at 23:30 counted as earlier than 00:00 of its own day and was hidden; the
XML <Timestamp> was not ISO either.

Expected: every data-ts in the HTML and every <Timestamp> in the XML has the
"T" form; the XML matches the JSON export's timestamps (independent path).
Synthetic events.
"""
import json
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def run_export(table, shards, path, ext):
    import evtx_tool.gui.main_window as mw
    w = mw._JMExportWorker(table, shards, "1=1", [], "timestamp_utc ASC, source_file ASC, record_id ASC",
                           path, ext, 10 ** 9)
    errs = []
    w.failed.connect(errs.append)
    w.run()
    return errs


def main() -> int:
    import test_around_pivot as T
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    tmp = tempfile.mkdtemp(prefix="jm_iso_")
    try:
        evs = T.dataset()
        table = T.write_jm(evs, tmp)
        model = ArrowTableModel(table, parquet_dir=tmp)
        shards = list(model._get_shard_paths())
        model.close()
        paths = {ext: os.path.join(tmp, f"out.{ext}") for ext in ("html", "xml", "json")}
        for ext, p in paths.items():
            errs = run_export(table, shards, p, ext)
            check(f"{ext} export runs", not errs, str(errs[:1]))
        html = open(paths["html"], encoding="utf-8").read()
        dts = re.findall(r"data-ts=['\"]([^'\"]*)['\"]", html)
        bad = [d for d in dts if d and "T" not in d]
        check("every HTML data-ts has the ISO 'T' form", dts and not bad, f"{len(dts)} values, bad {bad[:2]}")
        xml = open(paths["xml"], encoding="utf-8").read()
        xts = re.findall(r"<Timestamp>([^<]*)</Timestamp>", xml)
        js = [e.get("timestamp") for e in json.load(open(paths["json"], encoding="utf-8"))]
        dated = [x for x in xts if x]          # the dataset has an undated event
        check("every dated XML <Timestamp> is ISO 'T...Z'", dated and all("T" in x and x.endswith("Z") for x in dated),
              f"{len(dated)} of {len(xts)}; {[x for x in dated if not x.endswith('Z')][:2]}")
        check("XML timestamps equal the JSON export's", sorted(xts) == sorted(js), f"{xts[:1]} vs {js[:1]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
