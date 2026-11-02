"""An IOC pivot reaches every event that produced the IOC, however many.

Found by Codex in audit-5 (E5-14): IOC entries kept at most 50,000
(source file, record ID) keys, silently.  A computer seen in more events
pivoted to the first 50,000 only (88,945 producer keys missing on the
Normal corpus) and nothing said the pivot was partial.  Expected: the pivot
holds every producer key.  Synthetic events (60,001 events of one computer).
"""
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []
N = 60_001


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    import evtx_tool.gui.main_window as mw
    # Two logs, each numbering its own records from 1: the keys must stay
    # (file, record).  Distinct times, so they are not copies of one log.
    evs = [{"event_id": 4624, "record_id": i // 2 + 1, "source_file": rf"C:\c\log{i % 2}.evtx",
            "computer": "WS99", "timestamp": f"2026-01-01T00:00:00.{i:06d}Z", "event_data": {}}
           for i in range(N)]
    want = {(e["source_file"], e["record_id"]) for e in evs}
    iocs = extract_iocs(evs)
    ent = next((c for c in iocs.get("computers", []) if c["value"] == "WS99"), None)
    check("the computer IOC is found", ent is not None)
    keys = {(sf, rid) for sf, rid in (ent or {}).get("record_keys", [])}
    check("the IOC entry holds every producer key", keys == want, f"{len(keys):,} of {len(want):,}")
    check("its count agrees", (ent or {}).get("count") == N, str((ent or {}).get("count")))

    w = mw.MainWindow()
    w._parse_start_ts = time.monotonic()
    w._on_analysis_finished(iocs, [], {})
    app.processEvents()
    piv = w._ioc_pivot_map.get(("computers", "WS99"), frozenset())
    check("the pivot reaches every producer event", set(piv) == want, f"{len(piv):,} of {len(want):,}")
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
