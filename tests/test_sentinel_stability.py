"""Sentinel baseline stability follows its own definition.

Gemini audit 10-04 (High), sentinel/baseline/stability.py and builder:
1. processes were grouped by raw name, so "SVCHOST.EXE" and "svchost.exe"
   were two processes;
2. volatility was U/N, so every process launched once scored 1.0 (fully
   volatile) and a process with one template never scored 0, contrary to
   the docstring ("0 if only one unique cmdline, 1 if every event is
   unique");
3. the dominant host came from all events, not the creations, and a
   baseline mixing hosts was not reported.

Expected: one process across letter case; volatility (U-1)/(N-1), a single
launch 0; the creations' host; a warning for a mixed baseline.  Synthetic.
"""
import logging
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(name, cmd, eid=4688, host="H1"):
    from sentinel.models import RawEvent
    return RawEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), host=host, event_id=eid, process_guid="",
                    pid=1, ppid=0, parent_guid="", process_name=name, process_path="", parent_name="",
                    parent_path="", cmdline=cmd, user="", integrity_level="", image_hash="")


def main() -> int:
    from sentinel.baseline.stability import baseline_stability
    evs = [ev("SVCHOST.EXE", "svchost -k a"), ev("svchost.exe", "svchost -k a"),
           ev("svchost.exe", "svchost -k a"), ev("svchost.exe", "svchost -k a")]
    s = baseline_stability(evs)
    check("one process across letter case, one template: stability 1.0", s == 1.0, str(s))
    s = baseline_stability([ev("a.exe", "a"), ev("b.exe", "b"), ev("c.exe", "c")])
    check("processes launched once are not volatile", s == 1.0, str(s))
    s = baseline_stability([ev("x.exe", "x 1"), ev("x.exe", "x 2"), ev("x.exe", "x 3")])
    check("every launch different: stability 0.0", s == 0.0, str(s))

    from sentinel.baseline import builder as B
    h = B._dominant_host([ev("a.exe", "a", host="H1")] + [ev("t", "", eid=4689, host="H2")] * 5)
    check("the dominant host is the creations' host", h == "H1", h)
    rec = []

    class _H(logging.Handler):
        def emit(self, r):
            rec.append(r.getMessage())
    lg = logging.getLogger(B.__name__)
    hd = _H()
    lg.addHandler(hd)
    try:
        B._dominant_host([ev("a.exe", "a", host="H1"), ev("b.exe", "b", host="H2")])
    finally:
        lg.removeHandler(hd)
    check("a baseline mixing hosts is reported", any("host" in m.lower() for m in rec), str(rec))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
