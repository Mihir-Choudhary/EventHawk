"""A large event-key filter (IOC pivot, bookmarks, session) is exact and fast in Juggernaut.

Codex audit-5 E5-12: pivoting on the largest IOC took 47-56 s.  The key filter
was written as one SQL membership test listing every (file, record) key as a
literal -- 1.7 M literals, over 100 MB of SQL -- which DuckDB parsed again for
every query that used it (the view, every column popup, the export).

Expected: the filtered view holds exactly the chosen events (checked against
the key set itself, from the table's own columns), a file name with a quote
works, keys of events not loaded match nothing, the column popups and the
export see the same rows, and applying a 300,000-key filter takes at most
1.5 s (it took 2.7 s, and 2.4 s per query using it).  Synthetic data only.
"""
import os
import random
import shutil
import sys
import tempfile
import time
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


FILES = [r"C:\a\Security.evtx", r"C:\b\O'Brien\Security.evtx", r"C:\c\System.evtx"]
N = 400_000


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.heavyweight_model import ArrowTableModel

    evs = [T.ev(FILES[i % 3], i // 3 + 1, "HOST", T.T0 + timedelta(milliseconds=i)) for i in range(N)]
    tmp = tempfile.mkdtemp(prefix="bigkeys_")
    try:
        table = T.write_jm(evs, tmp)
        rnd = random.Random(7)
        chosen = frozenset(rnd.sample([(e["source_file"], e["record_id"]) for e in evs], 300_000))
        keys = chosen | {(FILES[0], 10 ** 9), (r"C:\not\loaded.evtx", 1)}
        m = ArrowTableModel(table, parquet_dir=tmp)
        T.wait_for(lambda: m.rowCount() == N, 60)

        t0 = time.perf_counter()
        m.apply_bookmark_filter(keys)
        T.wait_for(lambda: m.rowCount() == len(chosen) and m._filter_thread._q.empty(), 120)
        T.pump(200)
        dt = time.perf_counter() - t0
        d = m._display_table
        got = set(zip(d.column("source_file").to_pylist(), d.column("record_id").to_pylist()))
        check("the view holds exactly the chosen events", got == set(chosen) and len(d) == len(chosen),
              f"{len(d):,} rows, {len(got ^ set(chosen)):,} differ")
        check("a file name with a quote is matched",
              any(sf == FILES[1] for sf, _r in got), "")
        check("applying a 300,000-key filter takes at most 1.5 s", dt <= 1.5, f"{dt:.1f} s")

        # The column popup and the export run the model's WHERE on their own
        # connection over the model's table: they must see the same rows.
        import duckdb
        where, params = m._combined_where()
        con = duckdb.connect()
        con.register("events", m._full_table)
        t0 = time.perf_counter()
        n = con.execute(f"SELECT count(*) FROM events WHERE {where}", params).fetchone()[0]
        q = time.perf_counter() - t0
        base, bp = m.get_cascade_base_where()
        n2 = con.execute(f"SELECT count(*) FROM events WHERE {base}", bp).fetchone()[0]
        con.close()
        check("the WHERE run elsewhere over the tab's table selects the same events",
              n == len(chosen) and n2 == len(chosen), f"{n:,} / {n2:,}")
        check("...and a query with it takes well under a second", q < 1.0, f"{q:.2f} s")

        # A session filter goes to the main tab and every per-file tab, each
        # over the same shared table, with the same key set.
        tabs = [ArrowTableModel(table, parquet_dir=tmp, fixed_where="source_file = ?",
                                fixed_params=[FILES[i % 3]]) for i in range(30)]
        t0 = time.perf_counter()
        for fm in tabs:
            fm.apply_bookmark_filter(keys)
        dt = time.perf_counter() - t0
        want = [sum(1 for sf, _r in chosen if sf == FILES[i % 3]) for i in range(30)]
        # An empty request queue does not mean the query has finished: wait for
        # each tab's own result (30 filter threads share the CPU).
        T.wait_for(lambda: all(fm.rowCount() == want[i] for i, fm in enumerate(tabs)), 180)
        T.pump(300)
        bad = [i for i, fm in enumerate(tabs) if fm.rowCount() != want[i]]
        check("30 per-file tabs each show exactly their file's chosen events", not bad,
              f"{len(bad)} wrong, e.g. {[(tabs[i].rowCount(), want[i]) for i in bad[:3]]}")
        check("...and applying the key set to all 30 takes at most 2 s", dt <= 2.0, f"{dt:.1f} s")
        for fm in tabs:
            fm.close()

        # The integer-key mask (fast path) equals the text-key mask exactly.
        import pyarrow as pa
        import pyarrow.compute as pc
        mi = ArrowTableModel._key_mask_int(table, keys)
        sf = table.column("source_file")
        sf = sf.cast(pa.string()) if pa.types.is_dictionary(sf.type) else sf
        rk = pc.binary_join_element_wise(sf, pc.cast(table.column("record_id"), pa.string()), "\x1f")
        mt = pc.fill_null(pc.is_in(rk, value_set=pa.array([f"{a}\x1f{b}" for a, b in keys], pa.string())), False)
        check("integer-key mask equals the text-key mask on every row",
              mi is not None and mi.to_pylist() == mt.to_pylist(), "fast path not taken" if mi is None else "")
        big = table.slice(0, 3).set_column(table.schema.get_field_index("record_id"), "record_id",
                                           pa.array([1, 2, 1 << 41], pa.int64()))
        check("a record number past 2**40 falls back to the text keys",
              ArrowTableModel._key_mask_int(big, keys) is None)

        m.apply_bookmark_filter(frozenset({(FILES[0], 1)}))
        T.wait_for(lambda: m.rowCount() == 1 and m._filter_thread._q.empty(), 60)
        T.pump(200)
        check("a new key set replaces the old one", m.rowCount() == 1, f"{m.rowCount()}")
        m.clear_record_id_filter()
        T.wait_for(lambda: m.rowCount() == N and m._filter_thread._q.empty(), 60)
        T.pump(200)
        check("clearing it shows every event again", m.rowCount() == N, f"{m.rowCount():,}")
        m.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
