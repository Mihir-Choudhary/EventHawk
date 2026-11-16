"""Sentinel window: a 0-event run clears old results, the report names its own baseline, a bad baseline is refused.

Gemini audit 10-09 (Medium):
1. an analysis that scored 0 events returned early without telling the
   window, so the previous run's alerts stayed on screen and in exports;
2. Export Report read the baseline currently selected in the Analysis tab,
   not the one the results were computed against;
3. "Load existing baseline" accepted a folder whose four files merely
   exist, without verifying them (load_artifacts and its checksums).

Expected: each right.  Synthetic; dialogs stubbed.
"""
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication, QFileDialog, QMessageBox
    _app = QApplication.instance() or QApplication([])
    from sentinel.gui.analysis_tab import AnalysisTab
    from sentinel.gui.baseline_tab import BaselineTab
    import sentinel.baseline.persistence as BP

    at = AnalysisTab()
    got = []
    at.analysis_complete.connect(lambda s, m: got.append((s, m)))
    at._run_baseline_dir = Path("B1")
    at._on_finished([], {"events_raw_total": 5, "events_scored": 0})
    check("a 0-event run tells the window (old results are cleared)", len(got) == 1 and got[0][0] == [], str(got))
    at._on_finished(["x"], {"events_scored": 1})
    check("the results carry the baseline they were computed against",
          got and got[-1][1].get("baseline_dir") == str(Path("B1")), str(got[-1][1] if got else None))

    d = Path(tempfile.mkdtemp(prefix="sbad_"))
    for f in (BP._META_FILE, BP._FREQ_FILE, BP._TRIE_FILE, BP._FUSE_FILE):
        (d / f).write_text("x", encoding="utf-8")            # exist, but garbage / unsigned
    bt = BaselineTab()
    ready = []
    bt.baseline_ready.connect(lambda p: ready.append(p))
    real = (QFileDialog.getExistingDirectory, QMessageBox.warning)
    warned = []
    QFileDialog.getExistingDirectory = staticmethod(lambda *a, **k: str(d))
    QMessageBox.warning = staticmethod(lambda *a, **k: warned.append(a[2] if len(a) > 2 else ""))
    try:
        bt._load_existing()
    finally:
        QFileDialog.getExistingDirectory, QMessageBox.warning = real
    check("an unverifiable baseline is refused when loaded", not ready and warned, f"ready={ready} warned={warned}")
    at.close(); bt.close()
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
