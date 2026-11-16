"""sentinel analyze: every folder is read, and a failed file or empty result is an error.

Gemini audit 10-08 (High): "sentinel analyze --evtx A B" with folders read
no folder (only a single folder argument was expanded), and the command
exited 0 when files could not be opened or nothing was scored; the parser
only logged a failed file.

Expected: every folder expanded; the parser reports the files it could not
read; exit code 1 for a failed file and for 0 events scored.  Synthetic:
the engine and the baseline checks are stubbed.
"""
import argparse
import os
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from sentinel.analysis import parser as P
    import sentinel.cli as cli
    import sentinel.analysis.engine as E
    import sentinel.baseline.persistence as BP
    import sentinel.report.generator as G

    class _Bad:
        def __init__(self, p):
            raise OSError("cannot open")
    saved = sys.modules.get("evtx")
    sys.modules["evtx"] = types.SimpleNamespace(PyEvtxParser=_Bad)
    try:
        P.parse_evtx_files([Path("missing.evtx")])
    finally:
        if saved is not None:
            sys.modules["evtx"] = saved
        else:
            sys.modules.pop("evtx", None)
    lf = P.last_failed_files() if hasattr(P, "last_failed_files") else None
    check("the parser reports a file it could not open", lf and "missing.evtx" in str(lf), str(lf))

    d = Path(tempfile.mkdtemp(prefix="scli_"))
    (d / "a").mkdir(); (d / "b").mkdir(); (d / "base").mkdir()
    seen = {}
    real = (E.run_analysis, BP.artifacts_exist, BP.load_artifacts, P.find_relevant_evtx_files, G.generate_report)

    def fake_find(folder, progress_cb=None):
        return [Path(folder) / "Security.evtx"]

    def fake_run(paths, baseline, sigma, progress_cb=None):
        seen["paths"] = [str(p) for p in paths]
        return [], dict(seen.get("metrics", {}))
    try:
        E.run_analysis = fake_run
        BP.artifacts_exist = lambda d: True
        BP.load_artifacts = lambda d: (None, None, None, None)
        P.find_relevant_evtx_files = fake_find
        G.generate_report = lambda *a, **k: {"critical_alerts": []}
        ns = argparse.Namespace(evtx=[str(d / "a"), str(d / "b")], baseline=str(d / "base"), sigma=None, report=None)
        seen["metrics"] = {"events_scored": 5, "failed_files": []}
        rc = cli._cmd_analyze(ns)
        check("two folders are both read", sorted(Path(p).parent.name for p in seen.get("paths", [])) == ["a", "b"],
              str(seen.get("paths")))
        check("...and a clean run exits 0", rc == 0, str(rc))
        seen["metrics"] = {"events_scored": 5, "failed_files": [("x.evtx", "cannot open")]}
        check("a file that could not be read exits 1", cli._cmd_analyze(ns) == 1)
        seen["metrics"] = {"events_scored": 0, "failed_files": []}
        check("nothing scored exits 1", cli._cmd_analyze(ns) == 1)
    finally:
        E.run_analysis, BP.artifacts_exist, BP.load_artifacts, P.find_relevant_evtx_files, G.generate_report = real
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
