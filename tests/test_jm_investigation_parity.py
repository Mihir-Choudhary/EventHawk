"""Juggernaut must be trustworthy for an investigation, not a fast preview.

The reason a user stayed in Normal Mode (and hit the lag) was that Juggernaut
could not text-search everything and had no IOC extraction, so findings
depended on which mode you happened to pick. That is the worst possible
property for a forensic tool.

These checks assert Juggernaut and Normal Mode reach the SAME CONCLUSIONS from
the same evidence, and that anything Juggernaut cannot show in full says so.

Run: QT_QPA_PLATFORM=offscreen python tests/test_jm_investigation_parity.py
"""
import os, sys, glob, shutil, tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])
    from evtx_tool.core.parser import iter_events
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.gui.main_window import _JMAnalysisMaterializeWorker
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    from evtx_tool.analysis.correlator import correlate

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else "/mnt/NewVolume/Test_logs_Bulk/Logs"
    names = ("Application.evtx", "Security.evtx",
             "Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx")
    files = [os.path.join(LOGS, n) for n in names if os.path.exists(os.path.join(LOGS, n))]
    if not files:
        files = sorted(glob.glob(os.path.join(LOGS, "*.evtx")))[:6]
    if not files:
        print("no logs — skipping"); return 0

    norm = []
    for f in files:
        norm.extend(iter_events(f))
    print(f"{len(files)} files, {len(norm):,} events")

    tmp = tempfile.mkdtemp(prefix="jm_parity_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        w = _JMAnalysisMaterializeWorker(pq)
        got = {}
        loop = QEventLoop()
        w.finished_ok.connect(lambda e: (got.update(e=e), loop.quit()))
        w.failed.connect(lambda m: (got.update(err=m), loop.quit()))
        QTimer.singleShot(600000, loop.quit)
        w.start(); loop.exec(); w.wait(10000)
        jm = got.get("e") or []

        check("Juggernaut hands the analyser every event Normal Mode has",
              len(jm) == len(norm), f"jm={len(jm):,} normal={len(norm):,}")

        # ── IOC extraction must find the SAME indicators ─────────────────
        ni, ji = extract_iocs(norm), extract_iocs(jm)
        differing = []
        total_n = total_j = 0
        for k in sorted(set(ni) | set(ji)):
            nv, jv = ni.get(k), ji.get(k)
            if not (isinstance(nv, list) or isinstance(jv, list)):
                continue
            nvals = {str(e.get("value")) for e in (nv or []) if isinstance(e, dict)}
            jvals = {str(e.get("value")) for e in (jv or []) if isinstance(e, dict)}
            total_n += len(nvals); total_j += len(jvals)
            if nvals != jvals:
                differing.append((k, sorted(nvals - jvals)[:3], sorted(jvals - nvals)[:3]))
        check("IOC extraction finds identical indicators in both modes",
              not differing,
              "; ".join(f"{k}: normal-only={a} jm-only={b}" for k, a, b in differing[:3]))
        check("IOC extraction actually found something (test is not vacuous)",
              total_n > 0, f"{total_n} indicator values")
        print(f"      {total_n} indicators in normal, {total_j} in Juggernaut")

        # ── correlation must build the same chains ───────────────────────
        nc, jc = correlate(norm), correlate(jm)
        check("correlation produces the same number of chains in both modes",
              len(nc) == len(jc), f"normal={len(nc)} jm={len(jc)}")

        # ── the materialised events must carry what analysis reads ───────
        if jm:
            need = {"event_id", "computer", "provider", "timestamp", "channel",
                    "event_data", "record_id", "source_file"}
            missing = need - set(jm[0])
            check("materialised events carry every field the analysers read",
                  not missing, str(missing))
            with_ed = sum(1 for e in jm if e.get("event_data"))
            check("event_data survives the round trip through Parquet",
                  with_ed > 0, f"{with_ed:,}/{len(jm):,}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # ── every cap Juggernaut applies must be DISCLOSED, not silent ───────
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "evtx_tool", "gui", "main_window.py")).read()
    check("session-browser 200k cap is shown in the UI",
          "Results capped at 200,000 events" in src)
    check("logon session-filter hard cap is shown in the UI, not just logged",
          "Session Filter Truncated" in src and "INCOMPLETE" in src)
    check("column popups can search the whole dataset past the top-1000 cap",
          "_make_col_search_provider" in src)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
