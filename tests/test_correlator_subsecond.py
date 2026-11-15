"""Correlation compares times to the microsecond and converts UTC offsets.

Gemini audit 7-04 (High): correlator._ts() cut the fraction and any offset
off a timestamp, so 10:00:00.900 counted as "not after" 10:00:00.100 (and
the reverse as after) and "+05:30" was read as UTC.

Expected: _ts_ge(.100Z, .900Z) is False and the reverse True; a +05:30 time
equals the matching UTC time; Juggernaut's space form still parses.
Synthetic values.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.correlator import _ts, _ts_ge, _ts_delta
    a, b = "2026-01-01T10:00:00.100000Z", "2026-01-01T10:00:00.900000Z"
    check("10:00:00.100 is not at/after 10:00:00.900", _ts_ge(a, b) is False)
    check("10:00:00.900 is after 10:00:00.100", _ts_ge(b, a) is True)
    check("the delta keeps the fraction (0.8 s)", abs(_ts_delta(a, b) - 0.8) < 1e-6, str(_ts_delta(a, b)))
    check("+05:30 is converted", _ts("2026-01-01T15:30:00+05:30") == _ts("2026-01-01T10:00:00Z"))
    check("Juggernaut's 'YYYY-MM-DD HH:MM:SS.ffffff' parses", _ts("2026-01-01 10:00:00.100000") == _ts(a))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
