"""Events sort by instant, not by timestamp text.

Gemini audit 4-10 / 8-05 (Medium / High): the Normal parse, the Around tab and
the chain tab sorted on the timestamp TEXT.  "...:00Z" sorts after
"...:00.500000Z" ('.' < 'Z') and "+05:30" times are not UTC, so a record
without a fraction or with an offset landed out of order.  Every corpus
record has the one fixed shape, so real order is unchanged.

Expected: ts_sort_key orders 00.000Z < 00.5Z < 01Z and puts 12:00+05:30
(06:30Z) before 07:00Z; the corpus shape is returned unchanged; and on a
real parse the order by ts_sort_key equals the order by text.
"""
import glob
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.time_window import ts_sort_key
    ts = ["2026-01-01T00:00:01Z", "2026-01-01T00:00:00.500000Z", "2026-01-01T00:00:00.000000Z"]
    got = sorted(ts, key=ts_sort_key)
    check("00.000Z < 00.5Z < 01Z", got == [ts[2], ts[1], ts[0]], str(got))
    off = ["2026-01-01T07:00:00.000000Z", "2026-01-01T12:00:00+05:30"]
    got = sorted(off, key=ts_sort_key)
    check("12:00+05:30 (06:30Z) sorts before 07:00Z", got == [off[1], off[0]], str(got))
    s = "2026-01-01T07:00:00.123456Z"
    check("the corpus shape is returned unchanged", ts_sort_key(s) == s)
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if root and os.path.isdir(root):
        from evtx_tool.core.engine import _worker_parse_file
        from evtx_tool.core.filters import empty_filter
        f = min(glob.glob(os.path.join(root, "**", "Security.evtx"), recursive=True), key=os.path.getsize)
        evs = _worker_parse_file({"filepath": f, "filter_config": empty_filter()})["events"]
        a = [e["timestamp"] for e in sorted(evs, key=lambda e: e["timestamp"])]
        b = [e["timestamp"] for e in sorted(evs, key=lambda e: ts_sort_key(e["timestamp"]))]
        check("on a real log the order is unchanged", a == b and len(a) > 0, f"{len(a)} events")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
