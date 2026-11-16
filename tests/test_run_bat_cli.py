"""run.bat --cli passes the arguments exactly, keeps the caller's folder, needs no GUI packages.

Gemini audit 11-15 (High): run.bat rebuilt the CLI arguments word by word,
so cmd.exe split "--event-id 4624,4625" (4625 lost), "a=b" and "x;y"; it
changed to the EventHawk folder first (relative paths of the caller broke);
and it required the GUI packages (PySide6, duckdb, pyarrow) even for the
CLI, stopping on a "pause".

Expected: a stub evtx_tool.py beside a copy of run.bat receives exactly the
typed arguments and runs in the caller's folder.  Windows only (cmd.exe and
the py launcher); skipped elsewhere.
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    if os.name != "nt" or not shutil.which("py"):
        print("  (not Windows or no py launcher -- skipped)\n0/0 checks passed")
        return 0
    d = tempfile.mkdtemp(prefix="runbat_")
    caller = tempfile.mkdtemp(prefix="caller_")
    shutil.copy(os.path.join(HERE, "run.bat"), d)
    with open(os.path.join(d, "evtx_tool.py"), "w", encoding="utf-8") as fh:
        fh.write("import os, sys\nprint('ARGV=' + repr(sys.argv[1:]))\nprint('CWD=' + os.getcwd())\n")
    cmd = f'"{os.path.join(d, "run.bat")}" --cli parse --event-id 4624,4625 --search a=b x;y'
    r = subprocess.run(cmd, shell=True, cwd=caller, capture_output=True, text=True, timeout=60,
                       stdin=subprocess.DEVNULL)
    out = r.stdout
    ok1 = "ARGV=['parse', '--event-id', '4624,4625', '--search', 'a=b', 'x;y']" in out
    ok2 = f"CWD={caller}" in out
    print(f"  {'PASS' if ok1 else 'FAIL'}  the arguments arrive exactly as typed  -- {out.strip()[:200]!r}")
    print(f"  {'PASS' if ok2 else 'FAIL'}  the CLI runs in the caller's folder")
    n = ok1 + ok2
    print(f"{n}/2 checks passed")
    return 0 if n == 2 else 1


if __name__ == "__main__":
    sys.exit(main())
