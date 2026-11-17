"""Sentinel's Metrics tab shows the baseline's stability score (Gemini 14-05).

MetricsTab.populate() can show a "Baseline Stability" row, but the window never
passed the score, and the analysis did not report it, so the row never appeared.
Expected: run_analysis reports the score of the baseline it used (also when no
event was scored), and the window shows it in the Metrics tab.
Synthetic; no EVTX parsed.
"""
import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import sentinel.analysis.engine as E
    import sentinel.analysis.parser as P
    from sentinel.models import BaselineMeta, TierBoundaries
    meta = BaselineMeta(host="H", start_ts="", end_ts="", stability_score=0.4321, event_count=10, build_ts="",
                        tier_boundaries=TierBoundaries().__dict__, baseline_process_dist={}, input_file_hashes={})
    saved = (E.load_artifacts, P.parse_evtx_files, P.hash_evtx_files)
    E.load_artifacts = lambda d: (meta, None, None, None)
    P.parse_evtx_files = lambda paths, progress_cb=None: []
    P.hash_evtx_files = lambda paths: {}
    try:
        _, metrics = E.run_analysis([Path("x.evtx")], Path("B"))
    except Exception as e:
        metrics = {"error": repr(e)}
    finally:
        E.load_artifacts, P.parse_evtx_files, P.hash_evtx_files = saved
    check("run_analysis reports the baseline's stability", metrics.get("baseline_stability") == 0.4321, str(metrics)[:200])

    from sentinel.gui.window import SentinelWindow
    w = SentinelWindow()
    w._on_analysis_complete([], {"events_scored": 0, "events_raw_total": 0, "baseline_stability": 0.4321})
    t = w._metrics_tab._suppression_table
    rows = {t.item(r, 0).text(): t.item(r, 1).text() for r in range(t.rowCount()) if t.item(r, 0)}
    check("the Metrics tab shows Baseline Stability", rows.get("Baseline Stability", "").startswith("0.43"), str(rows))
    w._on_analysis_complete([], {"events_scored": 0, "events_raw_total": 0})
    rows = {t.item(r, 0).text() for r in range(t.rowCount()) if t.item(r, 0)}
    check("no score known: no made-up stability row", "Baseline Stability" not in rows, str(rows))
    w.close()
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
