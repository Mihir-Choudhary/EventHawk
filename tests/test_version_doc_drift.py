"""Version, licence and documented CLI behaviour agree with the code (Gemini 14-04).

The licence text, the installer, the Inno script and the exe's version resource
were aligned earlier (11-06). Left:
1. the GUI reported application version "2.0" while the package is 2.0.0;
2. docs/06b-timezone.md said CLI numeric offsets "are not converted" and
   timeline anchors "reject" them, while the CLI converts both to UTC;
3. tests/run_suite.py took "--help" as its output file name: it created a file
   called --help and started the whole suite.

Expected: one version everywhere; the guide describes what the CLI does; the
runner answers --help with usage, runs nothing and writes no file.
"""
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool
    v = evtx_tool.__version__
    app_src = open(os.path.join(ROOT, "evtx_tool", "gui", "app.py"), encoding="utf-8").read()
    m = re.search(r"setApplicationVersion\((.+?)\)", app_src)
    arg = m.group(1).strip() if m else ""
    alias = re.search(r"from evtx_tool import __version__ as (\w+)", app_src)
    check("the GUI's application version is the package version",
          arg == "__version__" or arg.strip("'\"") == v or (alias is not None and arg == alias.group(1)),
          arg or "not found")
    iss = open(os.path.join(ROOT, "EventHawk.iss"), encoding="utf-8").read()
    check("EventHawk.iss version = package version", f'"{v}"' in iss)
    vi = open(os.path.join(ROOT, "version_info.txt"), encoding="utf-8").read()
    check("version_info.txt names the Apache licence and the version", "Apache" in vi and "MIT" not in vi and v in vi)

    from evtx_tool.cli import _cli_dt
    check("CLI converts a numeric offset to UTC", _cli_dt("2026-02-21T14:30:00+02:00", "x").hour == 12)
    doc = open(os.path.join(ROOT, "docs", "06b-timezone.md"), encoding="utf-8").read()
    check("the time-zone guide does not say CLI offsets are not converted", "numeric offsets are not converted" not in doc)
    check("...nor that timeline anchors reject them", "anchors reject numeric offsets" not in doc)
    check("...and says they are converted to UTC", re.search(r"offset[^.]*converted to UTC", doc) is not None)

    tmp = tempfile.mkdtemp(prefix="rs_")
    p = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "run_suite.py"), "--help"], cwd=tmp,
                       capture_output=True, text=True, timeout=60)
    check("run_suite.py --help prints usage and exits 0", p.returncode == 0 and "usage" in (p.stdout + p.stderr).lower(),
          f"rc={p.returncode} {(p.stdout + p.stderr)[:120]!r}")
    check("...runs no test", not re.search(r"^(OK  |FAIL\[)", p.stdout, re.M))
    check("...writes no file", not os.listdir(tmp), str(os.listdir(tmp)))
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
