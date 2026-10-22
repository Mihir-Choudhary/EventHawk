"""Threat Intel must never report failed lookups as an all-clear.

enrich_iocs() marked every failed lookup verdict="error" and returned
nothing; the dialog then counted ALL entries as checked and reported
"Done -- N IOCs checked, 0 malicious/suspicious found" even when every
request had failed (offline, rate limit) or the run was cancelled.  A
rejected API key also failed every request one by one, each waiting its turn
in the 4-per-minute rate limiter.

Now enrich_iocs returns what happened, a rejected key stops the run with an
error, and the dialog says INCOMPLETE and warns when anything was not checked.
"""
import os
import sys
import urllib.error

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QTimer, Qt                            # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox          # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def iocs():
    return {"ipv4": [{"value": f"203.0.113.{i}", "count": 1} for i in range(1, 6)],
            "sha256": [{"value": "a" * 64, "count": 1}]}


def checker_failing(exc):
    import evtx_tool.analysis.threat_intel as ti
    c = ti.ThreatIntelChecker(api_key="k")
    c._limiter.acquire = lambda: None
    calls = []

    def boom(req, timeout=None):
        calls.append(req.full_url)
        raise exc
    ti.urllib.request.urlopen = boom
    return c, calls


def main() -> int:
    import urllib.request
    real = urllib.request.urlopen
    try:
        print("=== offline: every lookup fails ===")
        c, calls = checker_failing(urllib.error.URLError("network unreachable"))
        data = iocs()
        stats = c.enrich_iocs(data, mode="virustotal", ioc_types=["ipv4", "sha256"])
        check("enrich_iocs reports its outcome", isinstance(stats, dict), repr(stats)[:80])
        stats = stats or {}
        check("no IOC is counted as checked", stats.get("checked") == 0, str(stats))
        check("all six count as failed", stats.get("errors") == 6, str(stats))
        check("the first failure is kept for the analyst",
              "network unreachable" in (stats.get("first_error") or ""))

        print("\n=== a rejected API key stops at once ===")
        c, calls = checker_failing(urllib.error.HTTPError("u", 401, "Unauthorized", {}, None))
        try:
            c.enrich_iocs(iocs(), mode="virustotal", ioc_types=["ipv4", "sha256"])
            raised = ""
        except Exception as exc:
            raised = str(exc)
        check("it raises, naming the cause", "rejected the API key" in raised, raised[:80])
        check("after a single request, not six", len(calls) == 1, str(len(calls)))
    finally:
        urllib.request.urlopen = real

    print("\n=== the dialog never shows a failed run as clean ===")
    from evtx_tool.gui.threat_intel_dialog import ThreatIntelDialog
    dlg = ThreatIntelDialog(parent=None)
    seen = []

    def sweep():
        m = _app.activeModalWidget()
        if isinstance(m, QMessageBox):
            seen.append((m.windowTitle(), m.text())); m.done(0)
    t = QTimer(); t.timeout.connect(sweep); t.start(30)
    dlg._on_finished({"total": 6, "checked": 0, "malicious": 0, "errors": 6,
                      "first_error": "x: down", "not_checked": 0})
    status = dlg._lbl_status.text()
    check("the status says INCOMPLETE, not Done", status.startswith("INCOMPLETE"), status[:70])
    check("...and how many failed", "6 lookup(s) FAILED" in status)
    check("a warning is shown", any("Incomplete" in ti for ti, _ in seen), str(seen)[:80])
    seen.clear()
    dlg._on_finished({"total": 6, "checked": 6, "malicious": 1, "errors": 0,
                      "first_error": "", "not_checked": 0})
    check("a complete run still reads Done, without a warning",
          dlg._lbl_status.text().startswith("Done") and not seen)
    t.stop(); dlg.close()

    ok = sum(1 for _n, c_, _d in CHECKS if c_)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c_, d in CHECKS:
        if not c_:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
