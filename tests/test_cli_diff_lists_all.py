"""The command-line `diff` lists every new, missing, spiking and dropping event ID.

User (2026-11-06): "Print all".  The console tables stopped at 30 new, 20
missing, 20 spike and 10 drop event IDs, with no mention of the rest.
Expected: every one is printed.  Synthetic events; the two parses are replaced
by a stand-in that returns them (the comparison and printing are the real code).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def evs(counts):
    return [{"event_id": e, "timestamp": "2026-01-01T00:00:00Z"} for e, n in counts.items() for _ in range(n)]


def main() -> int:
    from click.testing import CliRunner
    import evtx_tool.cli as C
    base = {**{1000 + i: 1 for i in range(25)},          # 25 missing from the incident
            **{3000 + i: 1 for i in range(25)},          # 25 that spike (1 -> 10)
            **{4000 + i: 10 for i in range(15)}}         # 15 that drop (10 -> 1)
    inc = {**{2000 + i: 1 for i in range(40)},           # 40 new
           **{3000 + i: 10 for i in range(25)},
           **{4000 + i: 1 for i in range(15)}}
    runs = iter([evs(base), evs(inc)])

    class Engine:
        def __init__(self, *a, **k):
            pass

        def run(self, files, fc):
            return next(runs)

    real = (C.ProcessingEngine, C._collect_evtx_files)
    C.ProcessingEngine = Engine
    C._collect_evtx_files = lambda paths: ["x.evtx"]
    try:
        r = CliRunner().invoke(C.cli, ["diff", "base", "inc"], terminal_width=200)
    finally:
        C.ProcessingEngine, C._collect_evtx_files = real
    out = r.output
    check("diff ran", r.exit_code == 0, str(r.exception)[:200])
    for label, ids in (("new", [2000 + i for i in range(40)]), ("missing", [1000 + i for i in range(25)]),
                       ("spiking", [3000 + i for i in range(25)]), ("dropping", [4000 + i for i in range(15)])):
        missing = [i for i in ids if str(i) not in out]
        check(f"every {label} event ID is printed ({len(ids)})", not missing, f"not printed: {missing[:5]}")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
