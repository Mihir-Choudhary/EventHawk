"""Juggernaut must answer conditions and searches on provider GUID / version.

Normal mode keeps System/Provider@Guid and System/Version on every event, and
a field condition or text search on either works there.  Juggernaut had no
column for them: the condition went through json_extract on the EventData map
(always NULL) and the search blob left them out, so both matched NOTHING --
an empty result that reads as "no such events".  On the real Security +
System + PowerShell logs, through the GUI: provider GUID equals / contains,
version = 0 / 1 / 2 and a GUID text search all returned 0 in Juggernaut, and
now equal Normal mode and an independent count (30,545 / 64,650 / 6,974 /
177 ...).

This parses real logs with the real HeavyweightEngine and evaluates the real
Phase-2 SQL builders on the Parquet shards, against core.filters.passes_filter
on the same events.  Needs EVTX_TEST_LOGS (skipped without it).
"""
import glob
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    logs = os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    files = [p for p in (os.path.join(logs, n) for n in ("Security.evtx", "System.evtx"))
             if os.path.exists(p)] or sorted(glob.glob(os.path.join(logs, "*.evtx")))[:2]
    if not files:
        print(f"no logs under {logs!r} -- skipped")
        return 0

    import duckdb
    from evtx_tool.core.parser import iter_events
    from evtx_tool.core.filters import passes_filter
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.core.heavyweight.filter_sql import (
        filter_config_to_sql, text_config_to_parquet_sql)

    norm = []
    for f in files:
        norm.extend(iter_events(f))
    guids = sorted({str(e.get("provider_guid") or "") for e in norm} - {""})
    versions = sorted({int(e.get("version") or 0) for e in norm})
    print(f"{len(files)} files, {len(norm):,} events, {len(guids)} provider GUIDs, "
          f"versions {versions}")

    tmp = tempfile.mkdtemp(prefix="jm_syscols_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        shards = sorted(glob.glob(os.path.join(pq, "**", "*.parquet"), recursive=True))
        src = "parquet_scan([" + ", ".join("'" + s.replace("'", "''") + "'" for s in shards) + "])"
        con = duckdb.connect()
        cols = {r[0] for r in con.execute(f"DESCRIBE SELECT * FROM {src}").fetchall()}
        check("the shards carry provider_guid and version",
              {"provider_guid", "version"} <= cols)

        def jm(fc, text=False):
            where, params = (text_config_to_parquet_sql(fc) if text
                             else filter_config_to_sql(fc))
            return con.execute(f"SELECT count(*) FROM {src} WHERE {where}", params).fetchone()[0]

        cases = []
        for g in guids[:3]:
            cases.append((f"provider_guid equals {g[:13]}...",
                          {"conditions": [{"name": "provider_guid", "operator": "equals", "value": g}]}))
            cases.append((f"provider_guid contains {g[9:18]}",
                          {"conditions": [{"name": "provider_guid", "operator": "contains", "value": g[9:18]}]}))
        for v in versions[:3]:
            cases.append((f"version equals {v}",
                          {"conditions": [{"name": "version", "operator": "equals", "value": str(v)}]}))
        for label, fc in cases:
            want = sum(1 for e in norm if passes_filter(e, fc))
            got = jm(fc)
            check(f"{label}: Juggernaut == Normal", got == want and want > 0,
                  f"jm {got:,}, normal {want:,}")
        # Text search: the parse-time filter (``parse -F``) must search what
        # Juggernaut and the GUI view search.  Its scope used to be seven
        # metadata fields, and a STRING text_search (the dialog's format) was
        # iterated character by character.
        ts0 = str(norm[0].get("timestamp") or "")
        terms = ([guids[0][9:23]] if guids else []) + [
            "svchost", "0x8020000000000000", ts0[:16],
            ts0.replace("T", " ")[:16], '"SubjectUserName":']
        for term in terms:
            fc = {"text_search": term}
            want = sum(1 for e in norm if passes_filter(e, fc))
            got = jm(fc, text=True)
            check(f"text search {term!r}: Juggernaut == parse-time filter",
                  got == want and want > 0, f"jm {got:,}, parse-time {want:,}")
        fc_s, fc_l = {"text_search": "svchost"}, {"text_search": ["svchost"]}
        check("a string text_search is one term, as in the dialog",
              sum(passes_filter(e, fc_s) for e in norm)
              == sum(passes_filter(e, fc_l) for e in norm))
        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
