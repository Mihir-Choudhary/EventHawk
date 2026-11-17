"""Build and start scripts run no unverified download; the workflow never pastes a tag into code (Gemini 13-04).

1. run.sh downloaded get-pip.py to a fixed /tmp name (curl without -f, so an
   error page could be saved) and ran it;
2. build_standalone.ps1 ran a downloaded get-pip.py without checking it;
3. build-release.yml pasted ${{ github.ref_name }} (the tag, chosen by whoever
   pushes it) straight into PowerShell code.

Expected: run.sh makes its pip with the interpreter's own ensurepip and
downloads nothing; build_standalone.ps1 fetches one pinned pip wheel and
refuses it unless its SHA-256 matches; no ${{ github.* }} expression sits inside
a run: script (they go through env:). Static checks: the builds are not run.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def read(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


def code_lines(text, comment):
    return [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith(comment)]


def main() -> int:
    sh = "\n".join(code_lines(read("run.sh"), "#"))
    check("run.sh downloads nothing", not re.search(r"\b(curl|wget)\b", sh), "")
    check("run.sh runs no get-pip.py", "get-pip" not in sh)
    check("run.sh gets pip from the interpreter (venv with ensurepip)", "-m venv" in sh and "--without-pip" not in sh)

    ps = "\n".join(code_lines(read("build_standalone.ps1"), "#"))
    check("build_standalone.ps1 runs no get-pip.py", "get-pip" not in ps)
    m = re.search(r"pip-[\d.]+-py3-none-any\.whl", ps)
    check("build_standalone.ps1 fetches one pinned pip wheel", bool(m), m.group(0) if m else "")
    h = re.search(r"['\"]([0-9a-fA-F]{64})['\"]", ps)
    check("...with a pinned SHA-256", bool(h))
    check("...checked with Get-FileHash before use, failing the build on a mismatch",
          "Get-FileHash" in ps and re.search(r"-ne\s+\$\w*[Ss]ha|-ne\s+\$\w*[Hh]ash|Hash\s+-ne", ps) is not None and "throw" in ps)

    yml = read(".github/workflows/build-release.yml")
    bad = []
    in_run, indent = False, 0
    for ln in yml.splitlines():
        s = ln.strip()
        lead = len(ln) - len(ln.lstrip())
        if re.match(r"-?\s*run:\s*[|>]", s):
            in_run, indent = True, lead
            continue
        if in_run and s and lead <= indent:
            in_run = False
        if re.match(r"-?\s*run:\s*\S", s) and "${{" in s:
            bad.append(s)
        if in_run and "${{" in ln:
            bad.append(s)
    check("no ${{ ... }} expression inside a run: script", not bad, "; ".join(bad)[:300])
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
