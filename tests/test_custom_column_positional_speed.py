"""Positional custom columns ({Data[n]}) are faster and give exactly the same values.

Codex audit-5 E5-12: a positional custom column took 19.8 s on 1.84 M
Juggernaut rows (a named one 5.4 s), above the 10 s target.  The profile:
60% of the time was flatten_fields(), run on every event to list its <Data>
items, although for a plain {name: value} map it returns those same pairs.

Expected: every value and every "field found" count is identical to the old
evaluation (data_items flattening every event, restored here for comparison),
and the new code takes at most 75% of the old time on the same rows.
Real corpus: EVTX_TEST_LOGS_ONLINE (win7-x86 collection); counts only.
"""
import glob
import json
import multiprocessing
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def old_data_items(event_data, need=None):
    """data_items as it was: every event flattened."""
    from evtx_tool.core.filters import flatten_fields
    if not isinstance(event_data, dict):
        return []
    if "Data" in event_data:
        v = event_data["Data"]
        if isinstance(v, dict) and "#text" in v:
            v = v["#text"]
        if isinstance(v, list):
            out = []
            for item in v:
                if isinstance(item, dict):
                    nm = (item.get("#attributes") or {}).get("Name")
                    out.append((str(nm) if nm else None, item.get("#text", "")))
                else:
                    out.append((None, item))
            return out
        if not isinstance(v, dict):
            return [(None, v)]
    return [(k, v) for k, v in flatten_fields(event_data).items() if k != "Binary"]


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE", "")
    coll = os.path.join(root, "win7-x86")
    if not root or not os.path.isdir(coll):
        print("EVTX_TEST_LOGS_ONLINE (win7-x86) not found -- skipped")
        return 0
    import evtx_tool.core.custom_columns as CC
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    files = sorted(glob.glob(os.path.join(coll, "**", "*.evtx"), recursive=True))
    tmp = tempfile.mkdtemp(prefix="ccpos_")
    try:
        pq = HeavyweightEngine(parquet_dir=os.path.join(tmp, "pq")).run(files)
        table = load_arrow_table(pq)
        with open(os.path.join(pq, "parquet_manifest.json"), encoding="utf-8") as fh:
            shards = json.load(fh)
        print(f"{len(table):,} rows")
        new_fn = CC.data_items
        t_old = t_new = 0.0
        for tpl in ("{Data[1]}", "{Data[3]} / {Data[1]}", "{Data[2]}|{EventID}", "{Data[5]}{Data[TargetUserName]}"):
            res = {}
            for label, fn in (("old", old_data_items), ("new", new_fn)):
                CC.data_items = fn
                try:
                    c = CC.compile_spec(CC.CustomColumnSpec(col_id=1, title="x", template=tpl))
                    t0 = time.perf_counter()
                    v = CC.arrow_column_values(c, table, shards)
                    res[label] = (v, dict(c.hits), time.perf_counter() - t0)
                finally:
                    CC.data_items = new_fn
            same = res["old"][0] == res["new"][0] and res["old"][1] == res["new"][1]
            n_val = sum(1 for x in res["new"][0] if x)
            check(f"{tpl}: every value and field-found count identical", same,
                  f"{n_val:,} non-empty; old {res['old'][2]:.2f} s, new {res['new'][2]:.2f} s")
            if "TargetUserName" not in tpl:
                t_old += res["old"][2]
                t_new += res["new"][2]
        check("positional columns take at most 75% of the old time", t_new <= 0.75 * t_old,
              f"old {t_old:.2f} s, new {t_new:.2f} s ({t_new / t_old:.0%})")
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
