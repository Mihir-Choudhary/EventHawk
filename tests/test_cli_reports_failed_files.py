"""The command line reports a log it could not read, and says so in its exit code.

Gemini audit 11-02 (Critical): `parse --no-tui` printed "Done: 0 events
matched" and exited 0 when every file failed to open; `diff` treated an
unreadable incident log as an empty one and reported its event IDs as
"MISSING ... (possible log clearing?)" -- an anti-forensics indicator made up
from a read error -- and exited 0.

Expected:
- parse: the engine's error is printed, and the exit code is not 0;
- diff: an unreadable baseline or incident log stops the comparison (no
  MISSING / NEW tables from it), the error is printed, exit code not 0;
- a clean diff still works and exits 0.
The read failure is real: the actual engine opens a corrupt .evtx file.  The
readable side of the diff is a stand-in returning synthetic events.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from click.testing import CliRunner
    import evtx_tool.cli as C
    d = tempfile.mkdtemp(prefix="eh_cli_")
    bad = os.path.join(d, "broken.evtx")
    open(bad, "wb").write(b"this is not an event log" * 50)
    good = os.path.join(d, "fine.evtx")
    open(good, "wb").write(b"placeholder")
    runner = CliRunner()

    # parse, real engine
    r = runner.invoke(C.cli, ["parse", bad, "--no-tui"])
    out = r.output
    check("parse: a file that cannot be read gives a non-zero exit code", r.exit_code != 0, f"exit {r.exit_code}")
    check("parse: the failure is printed, naming the file", "broken.evtx" in out and ("error" in out.lower()
          or "failed" in out.lower() or "could not" in out.lower()), out[-400:])

    RealEngine = C.ProcessingEngine
    synth = [{"event_id": 4624, "timestamp": "2026-01-01T00:00:00Z"}, {"event_id": 4625, "timestamp": "2026-01-01T00:00:01Z"}]

    def stand_in(fail_side):
        calls = iter(["baseline", "incident"])

        class Engine:
            def __init__(self, *a, **k):
                self.side = next(calls)
                self.real = RealEngine(*a, **k)
                self.state = self.real.state

            def run(self, files, fc):
                if self.side == fail_side:
                    out = self.real.run([bad], fc)
                    self.state = self.real.state
                    return out
                return list(synth)
        return Engine

    for side in ("incident", "baseline"):
        C.ProcessingEngine = stand_in(side)
        try:
            r = runner.invoke(C.cli, ["diff", good, good])
        finally:
            C.ProcessingEngine = RealEngine
        out = r.output
        check(f"diff: an unreadable {side} log gives a non-zero exit code", r.exit_code != 0, f"exit {r.exit_code}")
        check(f"diff: an unreadable {side} log is not reported as missing / new event IDs",
              "possible log clearing" not in out and "MISSING" not in out and "NEW Event IDs" not in out, out[-500:])
        check(f"diff: the {side} read failure is printed", "broken.evtx" in out, out[-300:])

    # clean diff still works
    class Clean:
        def __init__(self, *a, **k):
            self.real = RealEngine(*a, **k)
            self.state = self.real.state

        def run(self, files, fc):
            return list(synth)
    C.ProcessingEngine = Clean
    try:
        r = runner.invoke(C.cli, ["diff", good, good])
    finally:
        C.ProcessingEngine = RealEngine
    check("diff: two readable sets still compare and exit 0", r.exit_code == 0, f"exit {r.exit_code} {r.output[-300:]}")

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
