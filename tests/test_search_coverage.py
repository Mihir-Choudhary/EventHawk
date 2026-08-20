"""Advanced text search must find EVERYTHING, identically in both modes.

The haystack used to cover seven System fields and EventData VALUES only. So a
term the analyst could plainly see in the detail panel -- a record ID, a PID, a
keyword mask, an EventData FIELD NAME, or Provider@EventSourceName -- returned
nothing, with no indication the search scope was narrower than the data.

Every check compares Juggernaut against normal mode, because a search that
answers differently depending on mode is its own defect.

Run: QT_QPA_PLATFORM=offscreen python tests/test_search_coverage.py
"""
import os, sys, glob, json, itertools, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.core.parser import iter_events
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel

    LOGS = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"
    src = os.path.join(LOGS, "Application.evtx")
    if not os.path.exists(src):
        cands = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))
        if not cands:
            print("no logs — skipping"); return 0
        src = cands[0]

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    evs = list(itertools.islice(iter_events(src), 40000))
    print(f"{len(evs):,} events from {os.path.basename(src)}")

    check("parser now captures EventSourceName",
          any(e.get("event_source_name") for e in evs),
          str(sorted({e.get("event_source_name","") for e in evs} - {""})[:3]))

    nm = EventTableModel(); nm.set_events(evs)
    npx = EventFilterProxyModel(); npx.setSourceModel(nm)
    def norm(term):
        npx.set_advanced_filter({"text_search": term}); n = npx.rowCount()
        npx.set_advanced_filter(None); return n

    tmp = tempfile.mkdtemp(prefix="search_cov_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run([src])
        table = load_arrow_table(pq)
        check("JM Arrow table carries event_source_name",
              "event_source_name" in table.column_names, str(table.column_names[:9]))
        jm_model = ArrowTableModel(table, parquet_dir=pq)
        def settle():
            loop = QEventLoop(); d = {"h": False}
            def fin(): d["h"] = True; loop.quit()
            jm_model.busy_finished.connect(fin); QTimer.singleShot(120000, loop.quit)
            if not d["h"]: loop.exec()
            try: jm_model.busy_finished.disconnect(fin)
            except Exception: pass
        settle()
        def jm(term):
            jm_model.apply_filter({"text_search": term}); settle(); n = jm_model.rowCount()
            jm_model.clear_filter(); settle(); return n

        # pick real values straight out of the data so nothing is hypothetical
        e0 = next(e for e in evs if e.get("event_source_name"))
        with_pid = next((e for e in evs if str(e.get("process_id") or "").strip()
                         not in ("", "0", "None")), None)
        ed_named = next((e for e in evs if isinstance(e.get("event_data"), dict)
                         and any(k for k in e["event_data"] if not k.startswith("#")
                                 and k not in ("Data", "Binary"))), None)
        field_name = None
        if ed_named:
            field_name = next(k for k in ed_named["event_data"]
                              if not k.startswith("#") and k not in ("Data", "Binary"))

        cases = [
            ("EventSourceName", e0["event_source_name"]),
            ("record_id",       str(evs[5]["record_id"])),
            ("keywords",        str(evs[0].get("keywords") or "")),
            ("provider Name",   e0.get("provider") or ""),
            ("channel",         evs[0].get("channel") or ""),
        ]
        if with_pid:
            cases.append(("process_id", str(with_pid["process_id"])))
        if field_name:
            cases.append(("EventData FIELD NAME", field_name))

        print(f"\n  {'field':<22} {'term':<34} {'JM':>7} {'NORMAL':>7}")
        for label, term in cases:
            if not term:
                continue
            a, b = jm(term), norm(term)
            print(f"  {label:<22} {term[:32]!r:<34} {a:>7} {b:>7}")
            check(f"{label} is findable", a > 0 and b > 0, f"jm={a} normal={b}")
            check(f"{label} agrees across modes", a == b, f"jm={a} normal={b}")

        # a term that is genuinely absent must still return nothing
        a, b = jm("zz-not-present-zz"), norm("zz-not-present-zz")
        check("absent term returns nothing in both modes", a == 0 and b == 0, f"{a}/{b}")
        jm_model._filter_thread.stop()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
