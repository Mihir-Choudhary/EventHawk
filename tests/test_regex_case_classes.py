"""A case-insensitive text regex keeps \\S, \\D, \\W and (?P<name>...) meaning what they say.

Gemini audit 3-01 (High): the CLI matcher (core.filters) and Juggernaut's SQL
lowercased a case-insensitive regex before using it, so \\S became \\s
(whitespace instead of non-whitespace), \\D became \\d, and (?P<Host>...)
became (?p<host>...), a syntax error.  The Normal GUI view did it right, so
the same filter gave different results per mode.

Expected, on a real log: a case-insensitive regex with \\S and with a named
group matches the same event count in core.filters and Juggernaut SQL
(the Normal proxy already compiled it correctly), and that count is the count Python's own re gives on the
same haystack (independent reference); the SQL parameter is not lowercased.
Real log read in place (needs EVTX_TEST_LOGS_ONLINE).
"""
import glob
import os
import re
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    from evtx_tool.core.engine import _worker_parse_file
    from evtx_tool.core.filters import empty_filter, compile_filter, adv_search_haystack
    from evtx_tool.core.heavyweight.filter_sql import filter_config_to_sql
    path = min((f for f in glob.glob(os.path.join(root, "**", "Security.evtx"), recursive=True)),
               key=os.path.getsize)
    evs = _worker_parse_file({"filepath": path, "filter_config": empty_filter()})["events"]
    print(f"{len(evs)} events")
    pats = [r"logon\S*type", r"(?P<What>Logon)\s+\S+", r"\D{3}\d{4}"]

    import duckdb
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    d = tempfile.mkdtemp(prefix="rxcase_")
    try:
        HeavyweightEngine(parquet_dir=d).run([path], None)
        shards = [f.replace("\\", "/") for f in glob.glob(os.path.join(d, "*.parquet"))]
        con = duckdb.connect()
        con.execute(f"create view events as select * from read_parquet({shards})")
        for p in pats:
            ref = sum(1 for e in evs if re.search(p, adv_search_haystack(e), re.IGNORECASE))
            fc = empty_filter()
            fc.update(text_search=p, text_regex=True, case_sensitive=False)
            got_cli = sum(1 for e in evs if compile_filter(fc)(e))
            where, params = filter_config_to_sql(fc)
            check(f"{p}: the SQL parameter is the pattern as typed", p in params, str(params))
            # The GUI's text search runs text_config_to_parquet_sql (the full
            # haystack, as core.filters); filter_config_to_sql's clause above
            # must not lower the pattern either.
            from evtx_tool.core.heavyweight.filter_sql import text_config_to_parquet_sql
            where, params = text_config_to_parquet_sql(fc)
            check(f"{p}: the Parquet search parameter is the pattern as typed", p in params, str(params))
            try:
                got_sql = con.execute(f"select count(*) from events where {where}", params).fetchone()[0]
            except Exception as e:
                got_sql = repr(e)[:80]
            check(f"{p}: core.filters matches Python re ({ref})", got_cli == ref, f"{got_cli} vs {ref}")
            check(f"{p}: Juggernaut SQL matches Python re ({ref})", got_sql == ref, f"{got_sql} vs {ref}")
        con.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
