"""Full functional sweep of Juggernaut Mode.

Every user-facing capability the Arrow/Parquet path exposes, exercised against
a real parsed corpus: display, detail panel, all filter layers and how they
compose, quick filters, record-id and bookmark pivots, per-file tabs, column
value popups, all four export formats, the session browsers, and analysis
materialisation.

Correctness is checked against independently computed counts from the Arrow
table itself, never against the model's own answer.

Run: QT_QPA_PLATFORM=offscreen python tests/test_jm_functional.py [logs_dir]
"""
import os, sys, csv, glob, json, shutil, tempfile, collections

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt, QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.gui.main_window import (
        _JMExportWorker, _JMAnalysisMaterializeWorker,
        _RemoteAssistanceDialog as RA,
    )
    from evtx_tool.gui.models import COL_TS, COL_EID, COL_CHANNEL, COL_COMPUTER

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"
    wanted = ["Application.evtx", "Security.evtx",
              "Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
              "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx"]
    files = [os.path.join(LOGS, f) for f in wanted
             if os.path.exists(os.path.join(LOGS, f))]
    if not files:
        files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:20]
    if not files:
        print("no logs — skipping"); return 0

    tmp = tempfile.mkdtemp(prefix="jm_func_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        table = load_arrow_table(pq)
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        total = len(table)
        print(f"{len(files)} files -> {total:,} rows\n")

        # independent truth straight from the Arrow columns
        eids   = table["event_id"].to_pylist()
        chans  = table["channel"].to_pylist()
        srcs   = table["source_file"].to_pylist()
        lvls   = table["level_name"].to_pylist()
        rids   = table["record_id"].to_pylist()
        n_by_eid = collections.Counter(eids)
        top_eid  = n_by_eid.most_common(1)[0][0]
        top_chan = collections.Counter(chans).most_common(1)[0][0]

        m = ArrowTableModel(table, parquet_dir=pq)
        def settle(mo=None, ms=300000):
            mo = mo or m
            loop = QEventLoop(); d = {"h": False}
            def fin(): d["h"] = True; loop.quit()
            mo.busy_finished.connect(fin); QTimer.singleShot(ms, loop.quit)
            if not d["h"]: loop.exec()
            try: mo.busy_finished.disconnect(fin)
            except Exception: pass
        settle()

        # ── 1. display ───────────────────────────────────────────────────
        check("1 rowCount matches the dataset", m.rowCount() == total, f"{m.rowCount():,}")
        check("1 columnCount is the display column count", m.columnCount() > 0)
        hdrs = [m.headerData(c, Qt.Orientation.Horizontal) for c in range(m.columnCount())]
        check("1 headers are all populated", all(h for h in hdrs), str(hdrs[:5]))
        cell = m.data(m.index(0, COL_EID), Qt.ItemDataRole.DisplayRole)
        check("1 cell data renders", cell not in (None, ""), repr(cell))

        # ── 2. detail panel ──────────────────────────────────────────────
        ev = m.get_event(0)
        check("2 get_event returns a full event", isinstance(ev, dict)
              and ev.get("event_id") is not None and "event_data" in ev,
              str(sorted(ev)[:8]) if ev else "None")
        check("2 out-of-range row yields None", m.get_event(total + 5) is None)

        # ── 3. metadata filters, each checked against Arrow truth ───────
        m.apply_filter({"event_ids": [top_eid]}); settle()
        check("3 event_id filter exact", m.rowCount() == n_by_eid[top_eid],
              f"{m.rowCount()} vs {n_by_eid[top_eid]}")
        # NOTE the real FilterConfig contract: channel filtering is
        # "categories", and "sources" matches PROVIDER-or-CHANNEL (substring),
        # not source_file. Per-file scoping is fixed_where (section 10).
        m.apply_filter({"categories": [top_chan]}); settle()
        exp_cat = sum(1 for c in chans if top_chan.lower() in (c or "").lower())
        check("3 category (channel) filter exact", m.rowCount() == exp_cat,
              f"{m.rowCount()} vs {exp_cat}")
        one_src = srcs[0]
        provs = table["provider"].to_pylist()
        top_prov = collections.Counter(p for p in provs if p).most_common(1)[0][0]
        m.apply_filter({"sources": [top_prov]}); settle()
        exp_src = sum(1 for pr, c in zip(provs, chans)
                      if top_prov.lower() in (pr or "").lower()
                      or top_prov.lower() in (c or "").lower())
        check("3 source (provider/channel) filter exact", m.rowCount() == exp_src,
              f"{m.rowCount()} vs {exp_src}")
        lvl = next((l for l in lvls if l), None)
        if lvl:
            m.apply_filter({"levels": [lvl]}); settle()
            check("3 level filter exact", m.rowCount() == lvls.count(lvl),
                  f"{m.rowCount()} vs {lvls.count(lvl)}")
        m.apply_filter({"event_ids": [top_eid], "exclude_event_ids": [top_eid]}); settle()
        check("3 event_id EXCLUDE removes that id",
              m.rowCount() == 0, f"{m.rowCount()} (include+exclude of the same id)")
        m.apply_filter({"exclude_event_ids": [top_eid]}); settle()
        check("3 exclude_event_ids alone is the complement",
              m.rowCount() == total - n_by_eid[top_eid],
              f"{m.rowCount()} vs {total - n_by_eid[top_eid]}")
        m.clear_filter(); settle()
        check("3 clear_filter restores everything", m.rowCount() == total)

        # ── 4. filter layers compose (AND) ──────────────────────────────
        # pick a channel the top event id actually occurs in, so the AND is
        # a real intersection rather than a trivially empty one
        chan_for_eid = collections.Counter(
            c for e, c in zip(eids, chans) if e == top_eid).most_common(1)[0][0]
        both = sum(1 for e, c in zip(eids, chans)
                   if e == top_eid and chan_for_eid.lower() in (c or "").lower())
        m.apply_filter({"event_ids": [top_eid], "categories": [chan_for_eid]}); settle()
        check("4 two metadata layers AND together (non-empty intersection)",
              m.rowCount() == both and both > 0,
              f"{m.rowCount()} vs {both}")
        m.clear_filter(); settle()

        # ── 5. quick filters ─────────────────────────────────────────────
        m.add_quick_filter("channel", top_chan, True); settle()
        check("5 quick include filter exact", m.rowCount() == chans.count(top_chan),
              f"{m.rowCount()} vs {chans.count(top_chan)}")
        check("5 has_quick_filters reports true", m.has_quick_filters())
        m.clear_quick_filters(); settle()
        check("5 clearing quick filters restores everything", m.rowCount() == total)
        m.add_quick_filter("channel", top_chan, False); settle()
        check("5 quick EXCLUDE is the complement",
              m.rowCount() == total - chans.count(top_chan),
              f"{m.rowCount()} vs {total - chans.count(top_chan)}")
        m.clear_all_filters(); settle()
        check("5 clear_all_filters resets", m.rowCount() == total)

        # ── 6. record-id pivot ───────────────────────────────────────────
        pick = frozenset(int(r) for r in rids[:25] if r is not None)
        m.apply_record_id_filter(pick); settle()
        expect = sum(1 for r in rids if r is not None and int(r) in pick)
        check("6 record-id pivot exact", m.rowCount() == expect,
              f"{m.rowCount()} vs {expect}")
        m.clear_record_id_filter(); settle()
        check("6 clearing the pivot restores everything", m.rowCount() == total)

        # ── 7. bookmark pivot ────────────────────────────────────────────
        bm = frozenset((srcs[i], int(rids[i])) for i in range(12) if rids[i] is not None)
        m.apply_bookmark_filter(bm); settle()
        check("7 bookmark pivot returns exactly the bookmarked rows",
              m.rowCount() == len(bm), f"{m.rowCount()} vs {len(bm)}")
        m.apply_bookmark_filter(frozenset()); settle()
        check("7 clearing bookmarks restores everything", m.rowCount() == total)

        # ── 8. sorting on every sortable column ─────────────────────────
        for col, name in ((COL_TS, "timestamp_utc"), (COL_EID, "event_id"),
                          (COL_CHANNEL, "channel"), (COL_COMPUTER, "computer")):
            m.sort(col, Qt.SortOrder.AscendingOrder); settle()
            v = [x for x in m._display_table[name].slice(0, 30000).to_pylist() if x is not None]
            ok_a = v == sorted(v)
            m.sort(col, Qt.SortOrder.DescendingOrder); settle()
            v2 = [x for x in m._display_table[name].slice(0, 30000).to_pylist() if x is not None]
            check(f"8 sort {name} both directions",
                  ok_a and v2 == sorted(v2, reverse=True), f"asc_ok={ok_a}")
            check(f"8 sort {name} preserves the row count", m.rowCount() == total)

        # ── 9. sort + filter together ────────────────────────────────────
        m.apply_filter({"event_ids": [top_eid]}); settle()
        m.sort(COL_TS, Qt.SortOrder.DescendingOrder); settle()
        check("9 sorting keeps the active filter", m.rowCount() == n_by_eid[top_eid],
              f"{m.rowCount()} vs {n_by_eid[top_eid]}")
        m.clear_filter(); settle()

        # ── 10. per-file tab ─────────────────────────────────────────────
        fm = ArrowTableModel(table, parquet_dir=pq,
                             fixed_where="source_file = ?", fixed_params=[one_src])
        settle(fm)
        check("10 per-file tab shows only that file", fm.rowCount() == srcs.count(one_src),
              f"{fm.rowCount()} vs {srcs.count(one_src)}")
        fm.apply_filter({"event_ids": [top_eid]}); settle(fm)
        exp = sum(1 for e, s in zip(eids, srcs) if e == top_eid and s == one_src)
        check("10 per-file tab respects its fixed scope under a filter",
              fm.rowCount() == exp, f"{fm.rowCount()} vs {exp}")
        fm._filter_thread.stop()

        # ── 11. column value popup source ────────────────────────────────
        import duckdb
        lst = "[" + ", ".join(f"'{p}'" for p in shards) + "]"
        con = duckdb.connect()
        vals = con.execute(
            f"SELECT channel, COUNT(*) FROM parquet_scan({lst}) "
            f"GROUP BY 1 ORDER BY 2 DESC").fetchall()
        con.close()
        check("11 column value counts match the table",
              sum(v[1] for v in vals) == total, f"{sum(v[1] for v in vals)} vs {total}")

        # ── 12. exports, all four formats ────────────────────────────────
        for ext in ("csv", "json", "html", "xml"):
            out = os.path.join(tmp, f"e.{ext}")
            lim = total if ext in ("csv", "json") else min(total, 5000)
            w = _JMExportWorker(table, shards, "1=1", [],
                                "timestamp_utc ASC, source_file ASC, record_id ASC",
                                out, ext, lim)
            loop = QEventLoop(); got = {}
            w.finished_ok.connect(lambda n, p: (got.update(n=n), loop.quit()))
            w.failed.connect(lambda e: (got.update(err=e), loop.quit()))
            QTimer.singleShot(600000, loop.quit)
            w.start(); loop.exec(); w.wait(10000)
            ok = "err" not in got and os.path.exists(out) and os.path.getsize(out) > 0
            check(f"12 {ext.upper()} export produces a non-empty file", ok,
                  str(got.get("err"))[:120])
            if ok and ext == "csv":
                with open(out, newline="", encoding="utf-8") as fh:
                    rd = csv.reader(fh); next(rd)
                    check("12 CSV row count exact", sum(1 for _ in rd) == total)
            if ok and ext == "json":
                check("12 JSON parses", isinstance(json.load(open(out)), list))

        # ── 13. session browsers over JM-shaped events ──────────────────
        con = duckdb.connect()
        rows = con.execute(
            f"SELECT event_id, timestamp_utc, event_data_json, channel, computer, "
            f"record_id, source_file FROM parquet_scan({lst}) "
            f"WHERE channel LIKE '%RDPClient%' OR channel LIKE '%LocalSessionManager%'"
        ).fetchall()
        con.close()
        evs = [{"event_id": r[0], "timestamp": r[1],
                "event_data": json.loads(r[2]) if r[2] else {},
                "channel": r[3], "computer": r[4], "record_id": r[5],
                "source_file": r[6]} for r in rows]
        sess = RA._build_sessions(evs)
        check("13 RDP/RA session browser builds sessions from JM data",
              len(sess) > 0, f"{len(sess)} sessions")
        outb = [s for s in sess if s["type"] == "RDP (Outbound)"]
        if outb:
            check("13 outbound sessions have evidence + source provenance",
                  all(s.get("evidence") and s.get("source_log") for s in outb))

        # ── 14. analysis materialisation ────────────────────────────────
        mw = _JMAnalysisMaterializeWorker(pq)
        loop = QEventLoop(); got = {}
        mw.finished_ok.connect(lambda e: (got.update(evs=e), loop.quit()))
        mw.failed.connect(lambda e: (got.update(err=e), loop.quit()))
        QTimer.singleShot(600000, loop.quit)
        mw.start(); loop.exec(); mw.wait(10000)
        got_evs = got.get("evs") or []
        check("14 analysis materialisation returns every row",
              len(got_evs) == total, f"{len(got_evs):,} vs {total:,}")

        m._filter_thread.stop()
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
