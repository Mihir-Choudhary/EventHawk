"""The CLI and the GUI AnalysisWorker score IOCs as the main analysis does.

Gemini audit 7-16 (Medium), part 1: cli._run_analysis() and
gui.worker.AnalysisWorker extracted IOCs but never scored them, so every
score was 0 -- YARA (score > 50) left out an encoded PowerShell command line
and MISP set to_ids False.

Expected: the GUI AnalysisWorker's IOCs carry the same scores as
score_ioc gives for the same values (the encoded command line > 50); the
CLI path calls the same scoring.  Synthetic event.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QCoreApplication
    QCoreApplication.instance() or QCoreApplication([])
    from evtx_tool.analysis.ioc_scorer import score_ioc
    from evtx_tool.gui.worker import AnalysisWorker
    cmd = "powershell.exe -NoProfile -EncodedCommand dGVzdA=="
    evs = [{"record_id": 1, "event_id": 4688, "timestamp": "2026-01-01T00:00:00.000000Z", "computer": "H",
            "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing", "source_file": "s.evtx",
            "event_data": {"CommandLine": cmd, "NewProcessName": r"C:\x\powershell.exe", "SubjectUserName": "carol"}}]
    try:
        w = AnalysisWorker(evs, do_ioc=True, do_correlate=False)
    except TypeError:
        w = AnalysisWorker(evs, True, False)
    out = {}
    w.finished.connect(lambda iocs, chains, md: out.setdefault("iocs", iocs))
    w.run()
    iocs = out.get("iocs") or {}
    got = [e.get("score", 0) for e in iocs.get("commandlines") or [] if e.get("value") == cmd]
    want = score_ioc("commandlines", cmd)[0]
    check("the AnalysisWorker scores the command line like score_ioc", got == [want] and want > 50, f"{got} vs {want}")
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evtx_tool", "cli.py"),
               encoding="utf-8").read()
    check("the CLI calls the same scoring", "score_and_correlate_iocs(iocs)" in src)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
