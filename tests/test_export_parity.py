"""CSV and JSON exports have the same layout in Normal and Juggernaut mode.

Found by driving the real GUI: the same events exported from the two modes
gave different files.  Normal wrote RecordID, EventID, Timestamp ... plus one
ED_<name> column per EventData field; Juggernaut streamed its storage
columns (record_id, ..., timestamp_utc without T/Z, an internal row_id, and
all EventData as one JSON string).  A report or script built on one export
broke on the other.

Same files, both real pipelines (ProcessingEngine + exporters for Normal,
HeavyweightEngine + _JMExportWorker for Juggernaut), compared field by field.
A synthetic block always runs; the real block needs EVTX_TEST_LOGS_ONLINE.
"""
import csv
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication                          # noqa: E402

app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def jm_export(table, parquet_dir, path, ext):
    """Export a whole JM table through the GUI's own export worker."""
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    model = ArrowTableModel(table, parquet_dir=parquet_dir)
    shards = model._get_shard_paths()
    model.close()
    w = mw._JMExportWorker(table, shards, "1=1", [],
                           "timestamp_utc ASC, source_file ASC, record_id ASC",
                           path, ext, 10 ** 9)
    errs = []
    w.failed.connect(errs.append)
    w.run()
    return errs


def read_csv(path):
    with open(path, "rb") as fh:
        bom = fh.read(3) == b"\xef\xbb\xbf"
    with open(path, encoding="utf-8-sig", newline="") as fh:
        r = csv.DictReader(fh)
        return bom, r.fieldnames, list(r)


def compare(tag, n_csv, j_csv, n_json, j_json):
    nb, nh, nrows = n_csv
    jb, jh, jrows = j_csv
    check(f"{tag}: CSV header identical", nh == jh,
          f"normal {nh[:6]}… ({len(nh)}), jm {jh[:6]}… ({len(jh)}); "
          f"only normal {sorted(set(nh) - set(jh))[:5]} only jm {sorted(set(jh) - set(nh))[:5]}")
    check(f"{tag}: both CSVs start with a UTF-8 BOM", nb and jb, f"normal {nb}, jm {jb}")
    key = lambda r: (r["SourceFile"], r["RecordID"])           # noqa: E731
    nd = {key(r): r for r in nrows}
    jd = {key(r): r for r in jrows}
    check(f"{tag}: CSV holds the same records", set(nd) == set(jd), f"{len(nd)} vs {len(jd)}")
    # ATT&CK is not run in Juggernaut mode, so that one column may differ.
    diff = [(k, c, nd[k][c], jd[k].get(c)) for k in nd if k in jd
            for c in nh if c != "ATT&CK" and nd[k][c] != jd[k].get(c)]
    check(f"{tag}: every CSV field equal (except ATT&CK)", not diff, str(diff[:3]))
    # JSON: same fields in the same order and values, event_source_name
    # included (Normal mode captures it since Codex release audit C4).
    nj = {(e["source_file"], e["record_id"]): e for e in n_json}
    jj = {(e["source_file"], e["record_id"]): e for e in j_json}
    check(f"{tag}: JSON holds the same records", set(nj) == set(jj), f"{len(nj)} vs {len(jj)}")
    bad = []
    for k, ne in nj.items():
        je = jj.get(k)
        if je is None:
            continue
        nkeys = [x for x in ne if x != "attack_tags"]
        jkeys = list(je)
        if nkeys != jkeys:
            bad.append((k, "keys", nkeys, jkeys))
        else:
            for x in nkeys:
                if ne[x] != je[x]:
                    bad.append((k, x, ne[x], je[x]))
        if len(bad) > 3:
            break
    check(f"{tag}: every JSON field equal, in the same order", not bad, str(bad[:2]))


def synthetic():
    print("=== synthetic ===", flush=True)
    import test_around_pivot as T
    from evtx_tool.output.exporters import export_csv
    tmp = tempfile.mkdtemp(prefix="exp_par_")
    try:
        evs = T.dataset()
        table = T.write_jm(evs, tmp)
        out = os.path.join(tmp, "jm.csv")
        errs = jm_export(table, tmp, out, "csv")
        check("synthetic: JM CSV export ran", not errs, str(errs))
        bom, hdr, rows = read_csv(out)
        check("synthetic: no internal storage columns", not ({"row_id", "event_data_json", "timestamp_utc"} & set(hdr)), str(hdr[:8]))
        check("synthetic: the Normal base columns first",
              hdr[:14] == ["RecordID", "EventID", "Timestamp", "Channel", "Provider", "Computer", "Level",
                           "LevelName", "Task", "Keywords", "UserID", "ProcessID", "SourceFile", "ATT&CK"], str(hdr[:14]))
        r6011 = next((r for r in rows if r.get("EventID") == "6011"), {})
        check("synthetic: timestamp in the Normal form", r6011.get("Timestamp") == "2022-02-07T10:54:25.366021Z",
              r6011.get("Timestamp"))
        nout = os.path.join(tmp, "n.csv")
        export_csv(evs, nout)
        _nb, nhdr, _nr = read_csv(nout)
        check("synthetic: ED_ columns as Normal writes them",
              [h for h in hdr if h.startswith("ED_")] == [h for h in nhdr if h.startswith("ED_")],
              f"{[h for h in hdr if h.startswith('ED_')]} vs {[h for h in nhdr if h.startswith('ED_')]}")
        del table
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def wide():
    """When rows x distinct EventData fields exceeds MAX_ED_CELLS, EventData is
    one JSON column instead of a grid of mostly-empty ED_ columns (a mixed
    1.7M-event export went from 0.94 GB / 26 s to 5.2 GB / 138 s per-field).
    Same rule, same file, in both modes.  The limit is lowered here so a small
    dataset crosses it; both modes read it from the same place."""
    print("\n=== wide export ===", flush=True)
    import test_around_pivot as T
    import evtx_tool.output.exporters as X
    saved = X.MAX_ED_CELLS
    tmp = tempfile.mkdtemp(prefix="exp_wide_")
    try:
        X.MAX_ED_CELLS = 1_000
        evs = [T.ev(T.SEC, 5000 + i, "WS01", T.T0, data={f"F{i:03d}": i, "Common": "x\ny, \"q\""})
               for i in range(40)]                        # 41 names x 41 rows = 1,681 cells
        evs.append(T.ev(T.SEC, 9999, "WS01", T.T0, data={}))
        table = T.write_jm(evs, tmp)
        jout, nout = os.path.join(tmp, "jm.csv"), os.path.join(tmp, "n.csv")
        errs = jm_export(table, tmp, jout, "csv")
        X.export_csv(evs, nout)
        _jb, jh, jrows = read_csv(jout)
        _nb, nh, nrows = read_csv(nout)
        want = X.CSV_BASE_KEYS + ["EventData"]
        check("wide: Normal writes one EventData column", nh == want, str(nh[-3:]))
        check("wide: Juggernaut writes the same header", jh == want and not errs, f"{jh[-3:]} {errs}")
        nd = {r["RecordID"]: r for r in nrows}
        jd = {r["RecordID"]: r for r in jrows}
        check("wide: every row identical in both modes",
              set(nd) == set(jd) and all(nd[k] == jd[k] for k in nd))
        back = {k: json.loads(r["EventData"]) for k, r in nd.items()}
        orig = {str(e["record_id"]): e["event_data"] for e in evs}
        check("wide: EventData column holds exactly the event's data (\"{}\" when none)", back == orig,
              str([(k, back[k], orig[k]) for k in back if back[k] != orig[k]][:2]))
        # Under the limit: per-field columns, in both modes.
        few = evs[:20]                                    # 21 names x 20 rows = 420 cells
        os.makedirs(os.path.join(tmp, "few"))
        t2 = T.write_jm(few, os.path.join(tmp, "few"))
        jn, nn = os.path.join(tmp, "jfew.csv"), os.path.join(tmp, "nfew.csv")
        jm_export(t2, os.path.join(tmp, "few"), jn, "csv")
        X.export_csv(few, nn)
        _b, h1, _r = read_csv(nn)
        _b, h2, _r = read_csv(jn)
        check("under the limit both modes keep ED_ columns",
              h1 == h2 and "EventData" not in h1 and sum(1 for x in h1 if x.startswith("ED_")) == 21, str(len(h1)))
        del table, t2
    finally:
        X.MAX_ED_CELLS = saved
        shutil.rmtree(tmp, ignore_errors=True)


def real():
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE", "")
    if not root or not os.path.isdir(root):
        print("EVTX_TEST_LOGS_ONLINE not set -- real-data block skipped")
        return
    from evtx_tool.core.engine import ProcessingEngine
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    from evtx_tool.output.exporters import export_csv, export_json
    for coll, sub in (("win10-client", "Logs_Client"), ("win2022-ad", "Win2022-AD")):
        print(f"\n=== real: {coll} ===", flush=True)
        files = [os.path.join(root, coll, sub, f) for f in ("Security.evtx", "System.evtx")]
        tmp = tempfile.mkdtemp(prefix="exp_par_real_")
        try:
            events = ProcessingEngine(max_workers=2).run(files, None)
            # Exactly what the GUI's ParseWorker does before the events reach
            # the table (and an export): ATT&CK tags, then semantic *_desc keys.
            # Found by Codex: without this the test compared engine events, not
            # the events a Normal-mode GUI export writes.
            from evtx_tool.analysis.attack_mapping import enrich_and_summarize
            from evtx_tool.analysis.normalizer import SemanticNormalizer
            enrich_and_summarize(events)
            SemanticNormalizer.get().enrich_events(events)
            export_csv(events, os.path.join(tmp, "n.csv"))
            export_json(events, os.path.join(tmp, "n.json"))
            pq = HeavyweightEngine(parquet_dir=os.path.join(tmp, "pq")).run(files)
            table = load_arrow_table(pq)
            e1 = jm_export(table, pq, os.path.join(tmp, "j.csv"), "csv")
            e2 = jm_export(table, pq, os.path.join(tmp, "j.json"), "json")
            check(f"{coll}: JM exports ran", not e1 and not e2, f"{e1} {e2}")
            with open(os.path.join(tmp, "n.json"), encoding="utf-8") as fh:
                nj = json.load(fh)
            with open(os.path.join(tmp, "j.json"), encoding="utf-8") as fh:
                jj = json.load(fh)
            compare(coll, read_csv(os.path.join(tmp, "n.csv")), read_csv(os.path.join(tmp, "j.csv")), nj, jj)
            del table
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    synthetic()
    wide()
    real()
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
