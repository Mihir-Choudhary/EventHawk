"""The standalone build stages Sentinel next to EventHawk.

Codex release audit C2: build_standalone.ps1 step 3 copies evtx_tool and the
entry points but not the root `sentinel` package, so the installed app's
Tools > Baseline Analysis (Sentinel) said "Sentinel Not Installed".

This runs the script's OWN step-3 lines (between the "# 3" and "# 4" markers)
in PowerShell against a temporary folder -- no download, no build -- then
checks, in an isolated Python, that both packages import from the staged copy.
"""
import os
import re
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    if os.name != "nt":
        print("Windows only -- skipped")
        return 0
    src = open(os.path.join(REPO, "build_standalone.ps1"), encoding="utf-8").read()
    m = re.search(r"^# 3 .*?$(.*?)^# 4 ", src, re.S | re.M)
    check("step 3 found in build_standalone.ps1", m is not None)
    if not m:
        return 1
    dst = tempfile.mkdtemp(prefix="eh_stage_")
    script = f'$repo = "{REPO}"\n$dst = "{dst}"\n' + m.group(1)
    ps = os.path.join(dst, "_step3.ps1")
    with open(ps, "w", encoding="utf-8-sig") as fh:
        fh.write(script)
    r = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps],
                       capture_output=True, text=True, timeout=300)
    check("step 3 runs", r.returncode == 0, (r.stderr or r.stdout)[-300:])
    probe = ("import sys; sys.path[:0] = [sys.argv[1]]; import evtx_tool, sentinel; "
             "import os; print(os.path.dirname(sentinel.__file__))")
    r = subprocess.run([sys.executable, "-I", "-c", probe, dst], capture_output=True, text=True, timeout=120, cwd=dst)
    where = r.stdout.strip()
    check("the staged folder holds the sentinel package",
          r.returncode == 0 and os.path.normcase(where).startswith(os.path.normcase(dst)),
          (r.stderr.strip()[-200:] or where))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
