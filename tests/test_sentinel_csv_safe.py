"""The Sentinel CSV report is formula-safe like every other EventHawk CSV (Codex CK91-1).

User rule (2026-11-06): a cell starting with = + - @ TAB CR gets one leading
apostrophe; plain numbers and the lone "-" are untouched; nothing spills into
another cell.  sentinel/report/generator.generate_csv_report still used a bare
csv.DictWriter: a command line "=1+1" was written as a live formula.
Expected protection is derived from the rule here, not from csv_cell.
Synthetic data only.
"""
import csv
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


DANGEROUS = ["=1+1", "+cmd|' /c calc'!A0", "-2+3", "@SUM(A1)", "\tx=1", "\rhello"]
UNTOUCHED = ["-", "-12", "+44", "1e5", "plain text", 'a "quoted", multi\nline']


def scored(cmd):
    from sentinel.models import NormalizedEvent, RawEvent, ScoredEvent
    raw = RawEvent(timestamp=datetime(2024, 6, 1, 12, 0, 0, tzinfo=timezone.utc), host="HOST1",
                   event_id=4688, process_guid="", pid=1000, ppid=4, parent_guid="",
                   process_name="cmd.exe", process_path="C:\\Windows\\cmd.exe",
                   parent_name="explorer.exe", parent_path="C:\\Windows\\explorer.exe",
                   cmdline=cmd, user="SYSTEM", integrity_level="High", image_hash="",
                   attck_tags=[], flags=set())
    n = NormalizedEvent(raw=raw, proc_norm="cmd.exe", parent_norm="explorer.exe",
                        cmdline_norm=cmd, ancestry_chain=["cmd.exe", "explorer.exe"])
    return ScoredEvent(normalized=n, surprisal_cmdline=1.0, surprisal_lineage=1.0,
                       trie_depth_score=0.5, ppid_flag=0.0, host_drift=0.1,
                       composite=80.0, tier=4, justification_text="")


def main() -> int:
    from sentinel.models import BaselineMeta
    from sentinel.report.generator import generate_csv_report
    meta = BaselineMeta(host="HOST1", start_ts="2024-01-01T00:00:00+00:00",
                        end_ts="2024-01-07T00:00:00+00:00", stability_score=0.85,
                        event_count=10, build_ts="2024-01-07T12:00:00+00:00",
                        tier_boundaries={"suppress_max": 20.0, "aggregate_max": 45.0,
                                         "highlight_max": 70.0},
                        baseline_process_dist={}, input_file_hashes={})
    values = DANGEROUS + UNTOUCHED
    tmp = tempfile.mkdtemp(prefix="sentcsv_")
    try:
        out = Path(tmp) / "r.csv"
        generate_csv_report([scored(v) for v in values], {}, meta, out)
        with open(out, encoding="utf-8", newline="") as fh:
            rows = list(csv.DictReader(fh))
        check("every row written, no cell spill", len(rows) == len(values)
              and all(None not in r for r in rows), f"{len(rows)} rows")
        got = {r["cmdline_raw"].lstrip("'") if r["cmdline_raw"][:1] == "'" else r["cmdline_raw"]: r
               for r in rows}
        for col in ("cmdline_raw", "cmdline_norm"):
            bad = [v for v in DANGEROUS if got.get(v, {}).get(col) != "'" + v]
            check(f"{col}: every = + - @ TAB CR cell gets one apostrophe", not bad,
                  f"{len(DANGEROUS) - len(bad)}/{len(DANGEROUS)}; unprotected {bad!r}")
            bad = [v for v in UNTOUCHED if got.get(v, {}).get(col) != v]
            check(f"{col}: numbers, lone '-', ordinary and quoted text unchanged", not bad, repr(bad))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
