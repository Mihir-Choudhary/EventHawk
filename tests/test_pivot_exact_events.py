"""A pivot must show exactly its own events -- in every mode, at any size.

1. IOC pivot and bookmark double-click filtered by bare record ids.  Every
   EVTX numbers its own records, so on a multi-log load the pivot also showed
   the event with the same number in every other log.  Measured through the
   GUI on six real logs: one hash pivot showed 39 events for 18 records,
   another 9 for 3, a domain 2,162 for 1,187 -- in both modes.  Pivots now
   use (source_file, record_id) keys, recorded by the IOC extractor.

2. Juggernaut's composite-key filter (apply_bookmark_filter: Remote
   Assistance sessions, Filter to Bookmarks, IOC pivot) was an OR chain of
   "(source_file = ? AND record_id = ?)".  DuckDB overflows its stack on a
   few thousand of those and kills the whole process (1,000 fine, 5,000
   crashed).  It is now one IN over a combined key with inlined literals.
"""
import os
import subprocess
import sys
import textwrap

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def events():
    """Two logs whose record ids overlap; the IOC lives only in a.evtx."""
    out = []
    for day, sf in ((1, r"C:\case\a.evtx"), (2, r"C:\case\b.evtx")):
        for rid in range(1, 41):
            ed = {"Image": r"C:\Users\Public\evil.exe"} if (sf.endswith("a.evtx") and rid % 4 == 0) \
                else {"Image": r"C:\Windows\System32\svchost.exe"}
            out.append({"event_id": 1, "record_id": rid, "source_file": sf,
                        # distinct logs: same ids, different events (another day)
                        "timestamp": f"2026-01-0{day}T00:00:{rid:02d}.000000Z", "computer": "WS01",
                        "channel": "Microsoft-Windows-Sysmon/Operational", "provider": "Sysmon",
                        "level": 4, "level_name": "Information", "event_data": ed})
    return out


JM_CHILD = textwrap.dedent(r"""
    import sys, duckdb
    sys.path.insert(0, sys.argv[1])
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    n_files, n_keys = int(sys.argv[2]), int(sys.argv[3])
    class Stub:
        _invalidate = lambda self: None
        def clear_record_id_filter(self): pass
    s = Stub()
    keys = frozenset((rf"C:\logs\it's f{i % n_files}.evtx", i) for i in range(n_keys))
    ArrowTableModel.apply_bookmark_filter(s, keys)
    con = duckdb.connect()
    con.execute(f"CREATE TABLE events AS SELECT range AS record_id, "
                f"('C:\\logs\\it''s f' || (range % {n_files})::VARCHAR || '.evtx') AS source_file "
                f"FROM range({n_keys * 3})")
    # decoys: same record ids in a file the keys do not name
    con.execute(f"INSERT INTO events SELECT range, 'C:\\logs\\other.evtx' FROM range({n_keys})")
    got = con.execute(f"SELECT count(*) FROM events WHERE {s._record_id_where_sql}",
                      s._record_id_params).fetchone()[0]
    print("ROWS", got)
""")


def main() -> int:
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

    print("=== IOC keys name the file as well as the record ===")
    evs = events()
    iocs = extract_iocs(evs)
    ent = next((e for cat in ("processes", "filepaths") for e in iocs.get(cat) or []
                if "evil.exe" in str(e.get("value", ""))), {})
    keys = {tuple(k) for k in ent.get("record_keys") or []}
    want = {(e["source_file"], e["record_id"]) for e in evs if "evil" in str(e["event_data"])}
    check("the IOC entry carries (source_file, record_id) keys", keys == want,
          f"{len(keys)} keys, expected {len(want)}")

    print("\n=== Normal-mode pivot shows exactly those events ===")
    model = EventTableModel(); model.set_events(evs)
    proxy = EventFilterProxyModel(); proxy.setSourceModel(model)
    proxy.set_record_id_filter(frozenset(want))
    shown = {(model._events[proxy.mapToSource(proxy.index(r, 0)).row()]["source_file"],
              model._events[proxy.mapToSource(proxy.index(r, 0)).row()]["record_id"])
             for r in range(proxy.rowCount())}
    check("no event from the other log, none missing", shown == want,
          f"shown {len(shown)}, expected {len(want)}")

    print("\n=== Juggernaut composite filter: exact, and survives size ===")
    for n_files, n_keys in ((3, 20), (3, 15000), (1600, 50000)):
        p = subprocess.run([sys.executable, "-c", JM_CHILD, REPO, str(n_files), str(n_keys)],
                           capture_output=True, text=True, timeout=600)
        rows = next((int(l.split()[1]) for l in p.stdout.splitlines() if l.startswith("ROWS")), None)
        check(f"{n_keys:,} keys over {n_files:,} files: exactly {n_keys:,} rows, no crash",
              p.returncode == 0 and rows == n_keys,
              f"exit {p.returncode}, rows {rows}")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
