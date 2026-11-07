"""Run every tests/test_*.py as its own process and summarise the results.

Usage:
    set EVTX_TEST_LOGS=<folder of test .evtx logs>              (optional)
    set EVTX_TEST_LOGS_ONLINE=<second folder of test logs>      (optional)
    python tests\\run_suite.py [result_log.txt]

Each test runs in a subprocess (an in-process Qt crash would otherwise end the
whole run silently), offscreen, with a 15-minute limit.  Tests that need real
logs skip those parts when the variables are not set.  Exit code 0 only when
every test file exits 0.  The result log (default: eventhawk_suite.txt in the
temp folder) gets one line per file, plus the last 25 output lines of each
failure.
"""
import glob
import os
import re
import subprocess
import sys
import tempfile
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(tempfile.gettempdir(), "eventhawk_suite.txt")
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONIOENCODING="utf-8")
    tests = sorted(glob.glob(os.path.join(REPO, "tests", "test_*.py")))
    fails = 0
    with open(out, "w", encoding="utf-8") as log:
        for t in tests:
            t0 = time.monotonic()
            try:
                p = subprocess.run([sys.executable, t], cwd=REPO, env=env, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=900)
                rc, text = p.returncode, (p.stdout or "") + (p.stderr or "")
            except subprocess.TimeoutExpired as e:
                rc, text = "HANG", str(e.stdout or "")
            lines = [ln for ln in text.splitlines() if re.search(r"\d+/\d+ (checks )?passed|passed|skipp", ln)]
            summary = lines[-1].strip() if lines else (text.strip().splitlines()[-1:] or [""])[0]
            fails += rc != 0
            row = f"{'OK  ' if rc == 0 else f'FAIL[{rc}]'} {os.path.basename(t)} [{time.monotonic() - t0:.0f}s] {summary}"
            print(row, flush=True)
            log.write(row + "\n")
            log.flush()
            if rc != 0:
                log.write("    " + "\n    ".join(text.splitlines()[-25:]) + "\n")
        tail = f"DONE {len(tests) - fails}/{len(tests)} files passed"
        print(tail)
        log.write(tail + "\n")
    print(f"Results: {out}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
