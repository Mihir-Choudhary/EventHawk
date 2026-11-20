"""Sentinel's window says what its Sigma rules did, and says it when they could not run.

The Baseline and Analysis tabs take a Sigma rules folder.  Expected:
  - pySigma missing: the run fails with an error dialog naming pySigma (it was
    a log line only, and the run went on as if the rules had been applied);
  - pySigma present: the log shows how many rules were applied and how many
    events were tagged, also when no event was scored.
The tabs, their workers and the Sigma loader are the real ones; only the
parse / baseline / scoring engine is replaced by a stand-in that hands the
chosen folder to the real SigmaTagger (the engine is covered by the CLI run).
Synthetic rule, no logs.
"""
import builtins
import os
import sys
import tempfile
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
RULE = ("title: Gui Demo\nid: 00000000-0000-4000-8000-0000000000e1\ntags: [attack.t1059]\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n  sel:\n    CommandLine|contains: 'zzguidemo'\n  condition: sel\n")


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def wait(app, cond, sec=20):
    end = time.time() + sec
    while time.time() < end and not cond():
        app.processEvents()
        time.sleep(0.02)
    return cond()


class NoSigma:
    """Make 'import sigma...' fail, as in an install without pySigma."""

    def __enter__(self):
        self.real = builtins.__import__
        saved = {k: v for k, v in sys.modules.items() if k == "sigma" or k.startswith("sigma.")}
        for k in saved:
            del sys.modules[k]
        self.saved = saved

        def imp(name, *a, **k):
            if name == "sigma" or name.startswith("sigma."):
                raise ImportError("No module named 'sigma'")
            return self.real(name, *a, **k)
        builtins.__import__ = imp
        return self

    def __exit__(self, *exc):
        builtins.__import__ = self.real
        sys.modules.update(self.saved)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import sentinel.gui.analysis_tab as AT
    import sentinel.gui.baseline_tab as BT
    import sentinel.analysis.engine as E
    import sentinel.baseline.builder as B
    import sentinel.analysis.parser as P
    import sentinel.baseline.persistence as PS
    from sentinel.analysis.sigma_tagger import SigmaTagger

    try:
        import sigma.collection  # noqa: F401
        have = True
    except ImportError:
        have = False

    rules = Path(tempfile.mkdtemp(prefix="siggui_"))
    (rules / "r.yml").write_text(RULE, encoding="utf-8")
    dialogs = []
    for mod in (AT, BT):
        mod.show_blocking = lambda parent, icon, title, text: dialogs.append((title, text))

    def fake_analysis(paths, baseline, sigma_dir, progress_cb=None, **kw):
        t = SigmaTagger(sigma_dir)                 # the real loader
        return [], {"events_raw_total": 0, "sigma": dict(t.status, summary=t.summary())}

    def fake_build(paths, out, sigma_dir, progress_cb=None, **kw):
        t = SigmaTagger(sigma_dir)
        if progress_cb:
            progress_cb(t.summary(), 0.12)
        return None

    # The rules load before any parsing (a missing pySigma is said at once,
    # also for a target with no events): the real build_baseline, parse spied.
    calls = []
    real_hash, real_parse = P.hash_evtx_files, P.parse_evtx_files
    P.hash_evtx_files = lambda paths, *a, **k: calls.append("hash") or {}
    P.parse_evtx_files = lambda paths, *a, **k: calls.append("parse") or []
    with NoSigma():
        try:
            B.build_baseline([Path("x.evtx")], Path(tempfile.mkdtemp(prefix="siggui_out_")), rules)
            got = "no error"
        except Exception as exc:                       # noqa: BLE001
            got = type(exc).__name__
    check("build_baseline: SigmaUnavailable before any hashing or parsing",
          got == "SigmaUnavailable" and not calls, f"{got}, calls {calls}")
    try:
        B.build_baseline([Path("x.evtx")], Path(tempfile.mkdtemp(prefix="siggui_out_")), rules / "nope")
        got = "no error"
    except Exception as exc:                           # noqa: BLE001
        got = type(exc).__name__
    check("build_baseline: a missing rules folder is an error before parsing",
          got == "FileNotFoundError" and not calls, f"{got}, calls {calls}")
    P.hash_evtx_files, P.parse_evtx_files = real_hash, real_parse
    import inspect
    src = inspect.getsource(E.run_analysis)
    check("run_analysis loads the rules before hashing and parsing the targets",
          0 < src.find("SigmaTagger(sigma_rules_dir)") < src.find('_cb("Hashing input EVTX files"'))

    E.run_analysis = fake_analysis
    B.build_baseline = fake_build
    P.find_relevant_evtx_files = lambda folder, progress_cb=None: [Path(folder) / "x.evtx"]
    PS.artifacts_exist = lambda d: True
    src = Path(tempfile.mkdtemp(prefix="siggui_src_"))
    (src / "x.evtx").write_bytes(b"")

    def run_analysis_tab():
        tab = AT.AnalysisTab()
        tab._target_source = [src / "x.evtx"]
        tab._baseline_dir = src
        tab._sigma_edit.setText(str(rules))
        tab._start_analysis()
        wait(app, lambda: tab._worker is not None and not tab._worker.isRunning() and tab._run_btn.isEnabled())
        app.processEvents()
        return tab, tab._log_edit.toPlainText()

    def run_baseline_tab():
        tab = BT.BaselineTab()
        tab._evtx_edit.setText(str(src))
        tab._output_edit.setText(str(src / "out"))
        tab._sigma_edit.setText(str(rules))
        tab._start_build()
        wait(app, lambda: tab._worker is not None and not tab._worker.isRunning() and tab._build_btn.isEnabled())
        app.processEvents()
        return tab, tab._log_edit.toPlainText()

    with NoSigma():
        dialogs.clear()
        _t, log = run_analysis_tab()
        check("Analysis, no pySigma: an error dialog naming pySigma",
              any(title == "Analysis Failed" and "pySigma" in text for title, text in dialogs), str(dialogs))
        dialogs.clear()
        _t, log = run_baseline_tab()
        check("Baseline, no pySigma: an error dialog naming pySigma",
              any(title == "Build Failed" and "pySigma" in text for title, text in dialogs), str(dialogs))

    if have:
        dialogs.clear()
        _t, log = run_analysis_tab()
        check("Analysis, pySigma: no error dialog", not dialogs, str(dialogs))
        check("Analysis, pySigma: the log says 1 of 1 rules applied (0 events scored)",
              "Sigma: 1 of 1 rules applied" in log, log[-400:])
        dialogs.clear()
        _t, log = run_baseline_tab()
        check("Baseline, pySigma: the log says 1 of 1 rules applied",
              "Sigma: 1 of 1 rules applied" in log, log[-400:])
    elif os.environ.get("GITHUB_ACTIONS"):
        check("pySigma is installed in CI (requirements-lock.txt)", False)
    else:
        print("  NOTE  pySigma not installed here: the with-pySigma checks not run")

    app.processEvents()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
