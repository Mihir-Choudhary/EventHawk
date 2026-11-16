"""Sentinel: unparseable times skip drift, one host is one host, Sigma tags read as written.

Gemini audit 10-11 (Medium):
1. HostDriftMonitor skipped a naive datetime.min, but the parser returns a
   UTC-aware one, so such events entered the drift window;
2. per-host lineage (and drift) was keyed by the raw host, so "HOST" and
   "host" were two hosts;
3. the Sigma keyword fallback read only "attack.t..." tags in lower case,
   kept punctuation in title keywords, loaded only *.yml (not *.yaml) and
   validated only a file's first YAML document.

Expected: each right.  The Sigma part uses a stand-in rule collection
(pySigma is not installed here).  Synthetic.
"""
import os
import sys
import types
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from sentinel.analysis.drift_monitor import HostDriftMonitor
    m = HostDriftMonitor({"a.exe": 1.0})
    try:
        m.update(datetime.min.replace(tzinfo=timezone.utc), "a.exe")
        ok = len(m._window) == 0
    except Exception as exc:
        ok = False
        print("   ", type(exc).__name__, exc)
    check("an unparseable (aware datetime.min) time skips the drift window", ok)

    from sentinel.analysis.lineage import PerHostLineageTracker
    from sentinel.models import RawEvent
    t = PerHostLineageTracker()
    for h in ("HOST-A", "host-a", "Host-A "):
        t.process_event(RawEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), host=h, event_id=4688,
                                 process_guid="", pid=10, ppid=4, parent_guid="", process_name="a.exe",
                                 process_path="", parent_name="", parent_path="", cmdline="", user="",
                                 integrity_level="", image_hash=""))
    check("one host across letter case and spaces is one lineage tracker", len(t._trackers) == 1, str(list(t._trackers)))

    import sentinel.analysis.engine as E
    import inspect
    src = inspect.getsource(E.run_analysis)
    check("the engine keys drift by the same host key", "host_key(ev.host)" in src or "_host_key(ev.host)" in src)

    from sentinel.analysis.sigma_tagger import SigmaTagger
    tg = SigmaTagger.__new__(SigmaTagger)
    tg._rules = []
    rule = types.SimpleNamespace(tags=["ATTACK.T1059.001", "attack.execution"], title="Mimikatz, PowerShell!")
    tg._build_keyword_fallback(types.SimpleNamespace(rules=[rule]))
    got = [(sorted(p.keywords) if hasattr(p, "keywords") else None, ids) for p, ids in tg._rules]
    check("upper-case tags read, punctuation stripped from keywords",
          got == [(["mimikatz", "powershell"], ["T1059.001"])], str(got))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
