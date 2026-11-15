"""A correlation rule that fails is reported, not only logged.

Found while fixing Gemini 7-01 (a missing import made one rule raise): the
correlator caught the exception, logged a warning and went on, so the
analysis came back with that rule's chains missing and nothing on screen
or in the CLI said so.

Expected: correlate(..., rule_errors=list) puts the failed rule in the list
(the GUI analysis process passes it on under "Correlation rules" in the
errors it already reports; the CLI prints it -- not exercised here).
Synthetic events; one rule is made to raise.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.analysis.correlator as C

    def boom(*a, **k):
        raise RuntimeError("synthetic rule failure")
    boom.__name__ = "_rule_synthetic"
    C._RULES.insert(0, boom)
    try:
        evs = [{"record_id": 1, "event_id": 4624, "timestamp": "2026-01-01T00:00:00.000000Z", "computer": "H",
                "channel": "Security", "provider": "P", "source_file": "s.evtx", "event_data": {}}]
        errs = []
        try:
            C.correlate(evs, rule_errors=errs)
            e = ""
        except TypeError as x:
            e = repr(x)
        check("correlate reports the failed rule", any("_rule_synthetic" in m for m in errs), e or str(errs))
    finally:
        C._RULES.remove(boom)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
