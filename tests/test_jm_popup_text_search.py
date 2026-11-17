"""Juggernaut column popups count only what the active text search and field conditions leave (Gemini 5-03, Codex PR19-5).

Text search and Advanced Filter field conditions are applied in a second phase
over the Parquet shards (EventData is not in the in-memory table). The column
popup's cascade only carried the in-memory filters, so with a search active
the popup counted every event: Codex measured 40,963 / 64 providers in Juggernaut
against 1,388 / 1 in Normal mode on a real System log.

Expected: with a text search (toolbar or Advanced), with field conditions, and
together with a quick filter on another column, the popup's values and counts
equal those of the rows the grid shows (minus only the popup's own column
filter); the prewarmed popups agree with the clicked ones. Synthetic data only.
"""
import os
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
SF = r"C:\synthetic\Security.evtx"
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def dataset():
    evs, rid = [], 0
    for comp, eid, needle, n in (("H1", 4688, True, 3), ("H1", 4688, False, 4), ("H2", 4688, True, 2),
                                 ("H2", 4624, False, 5), ("H3", 4624, True, 1)):
        for _ in range(n):
            rid += 1
            data = {"CommandLine": "run zebrafinch now" if needle else "plain text", "Kind": "k1" if rid % 2 else "k2"}
            evs.append(T.ev(SF, rid, comp, BASE + timedelta(seconds=rid), eid, data=data))
    return evs


def write_jm_flat(evs, tmp):
    """test_around_pivot.write_jm plus ed_flat_json, which the real engine
    writes and field conditions read (the shared helper leaves it empty)."""
    import json
    import pyarrow.parquet as pq
    table = T.write_jm(evs, tmp)
    shard = os.path.join(tmp, "s0.parquet")
    t = pq.read_table(shard)
    flat = [json.dumps(json.loads(x) if x else {}) for x in t["event_data_json"].to_pylist()]
    i = t.schema.get_field_index("ed_flat_json")
    pq.write_table(t.set_column(i, t.schema.field(i), __import__("pyarrow").array(flat, type=t.schema.field(i).type)), shard)
    return table


def popup(w, col):
    from evtx_tool.gui.jm_col_worker import ColValueWorker
    where_sql, where_params = w._build_col_cascade_where(col)
    out = []
    wk = ColValueWorker(w._jm_col_table(), col, where_sql=where_sql, where_params=where_params)
    wk.finished.connect(out.append)
    wk.run()
    return dict(out[0]) if out else {}


def shown(w, col):
    T.wait_for(lambda: not w._hw_model.filter_pending(), 30)
    T.pump(200)
    return dict(Counter(str(v) for v in w._hw_model._display_table[col].to_pylist()))


def main() -> int:
    import evtx_tool.gui.main_window as mw
    m = T.Mode(mw, True)
    w = mw.MainWindow()
    evs = dataset()
    tmp = tempfile.mkdtemp(prefix="jm_pts_")
    m.load(w, table=write_jm_flat(evs, tmp), parquet_dir=tmp)
    model = w._hw_model

    model.apply_text_filter("zebrafinch")
    exp = shown(w, "computer")
    check("setup: the text search leaves 6 events", sum(exp.values()) == 6, str(exp))
    got = popup(w, "computer")
    check("toolbar text search: Computer popup = the rows shown", got == exp, f"popup {got} shown {exp}")

    model.apply_text_filter("")
    model.apply_filter({"text_search": "zebrafinch"})
    exp = shown(w, "event_id")
    got = popup(w, "event_id")
    check("Advanced text search: Event ID popup = the rows shown", got == exp, f"popup {got} shown {exp}")

    model.set_quick_filters([{"key": "computer", "value": "H1", "include": True}])
    exp_eid = shown(w, "event_id")
    got = popup(w, "event_id")
    check("text search + quick filter on Computer: Event ID popup = the rows shown", got == exp_eid, f"popup {got} shown {exp_eid}")
    got = popup(w, "computer")
    check("...and the Computer popup leaves out only its own filter (H1, H2, H3 of the search)",
          got == {"H1": 3, "H2": 2, "H3": 1}, str(got))
    model.set_quick_filters([])
    model.clear_filter()

    model.apply_filter({"conditions": [{"name": "Kind", "operator": "equals", "value": "k1"}]})
    exp = shown(w, "computer")
    got = popup(w, "computer")
    check("setup: the field condition leaves 8 of 15 events", sum(exp.values()) == 8, str(exp))
    check("field condition: Computer popup = the rows shown", got == exp, f"popup {got} shown {exp}")

    # the prewarmed popups (served on click from a cache) must agree
    w._start_col_prewarm()
    T.wait_for(lambda: not any(w._thread_running(t) for t in w._col_prewarm_workers), 30)
    T.pump(200)
    key = w._col_cache_key("computer")
    cached = dict(w._col_value_cache.get(key, {})) if key is not None else {}
    check("prewarmed Computer popup = the rows shown", cached == exp and bool(exp), f"cache {cached} shown {exp}")
    model.clear_filter()
    shown(w, "computer")
    w._start_col_prewarm()
    T.wait_for(lambda: not any(w._thread_running(t) for t in w._col_prewarm_workers), 30)
    T.pump(200)
    key2 = w._col_cache_key("computer")
    check("after clearing the filter the popup's cache key changes", key2 != key, f"{key} -> {key2}")
    w.close()
    T.pump(200)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    tempfile.tempdir = None
    sys.exit(main())
