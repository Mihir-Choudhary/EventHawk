"""CLI: a wildcard only picks up .evtx files, and says what it left out.

Gemini audit 1-04 (High): _collect_evtx_files took every glob match, so
"logs\\*" handed notes.txt and sub-directories to the engine as event logs.

Expected: "dir\\*" yields only the .evtx files (any case of the suffix); the
text file and the directory are not passed on, and a warning names how many
matches were skipped; a wildcard that matches nothing is reported.
Synthetic files only (names, no event data is read).
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from rich.console import Console
    import evtx_tool.cli as C
    d = tempfile.mkdtemp(prefix="cliglob_")
    for n in ("a.evtx", "B.EVTX", "notes.txt"):
        open(os.path.join(d, n), "wb").close()
    os.mkdir(os.path.join(d, "sub_dir"))
    buf = io.StringIO()
    C.console = Console(file=buf, width=200)
    got = C._collect_evtx_files([os.path.join(d, "*")])
    names = sorted(os.path.basename(f) for f in got)
    check("the wildcard yields only the .evtx files", names == ["B.EVTX", "a.evtx"], str(names))
    out = buf.getvalue()
    check("a warning says matches were skipped", "2" in out and "not" in out.lower() and "evtx" in out.lower(), out.strip()[:200])
    buf.truncate(0); buf.seek(0)
    got = C._collect_evtx_files([os.path.join(d, "*.nomatch")])
    check("a wildcard that matches nothing is reported", not got and buf.getvalue().strip() != "", buf.getvalue().strip()[:200])
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
