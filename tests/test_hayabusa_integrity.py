"""Hayabusa: failures are reported and the evidence folder is left alone (audit SA-2..SA-5).

SA-2  A Hayabusa that failed returned an empty list with only a log line, so
      the analyst saw "no detections".  Reproduced: a program exiting with
      code 2 gave [] and no error.  Expected: every failure (bad exit code,
      missing program, unreadable output, unreadable lines) is reported.
SA-3  With part of a folder selected, a temporary folder was created INSIDE
      the evidence folder and the logs were hard-linked into it: the folder
      changed and each log's link count went 1 -> 2.  Expected: nothing is
      created in the evidence folder and the logs' link counts stay 1.
SA-4  Hayabusa was looked for in C:\\hayabusa and C:\\Tools\\hayabusa, folders
      any signed-in Windows user may create.  Expected: only folders that
      belong to the analyst or to administrators are searched.
SA-5  "The folder holds only the selected logs" compared counts, not names:
      two logs plus a missing path selected, three logs in the folder -> the
      whole folder was scanned, including the log not selected.
Synthetic files only; no Hayabusa needed.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def call(fn, *a, **kw):
    """Call with the 'problems' list; a signature without it reports nothing."""
    problems = []
    try:
        return fn(*a, problems=problems, **kw), problems
    except TypeError:
        return fn(*a, **kw), problems


def scanned(folder):
    return sorted(n.split("_", 1)[1] for n in os.listdir(folder))


def main() -> int:
    from evtx_tool.analysis import hayabusa_runner as H
    base = tempfile.mkdtemp(prefix="hay_test_")
    ev = os.path.join(base, "evidence")
    os.makedirs(ev)
    paths = {}
    for n in ("a.evtx", "b.evtx", "c.evtx"):
        paths[n] = os.path.join(ev, n)
        with open(paths[n], "wb") as f:
            f.write(b"x" * 16)
    try:
        # SA-2
        res, problems = call(H.run_hayabusa, sys.executable, [paths["a.evtx"]])
        check("SA-2 a failed run is reported, with its exit code", any("code 2" in p for p in problems),
              f"result {res}, problems {len(problems)}")
        res, problems = call(H.run_hayabusa, os.path.join(base, "no_such.exe"), [paths["a.evtx"]])
        check("SA-2 a missing program is reported", len(problems) == 1 and res == [])
        out = os.path.join(base, "out.jsonl")
        good = {"RuleTitle": "T", "Computer": "PC", "Level": "high", "Timestamp": "2024-01-01 00:00:00"}
        with open(out, "w", encoding="utf-8") as f:
            f.write(json.dumps(good) + "\n{broken\n\n" + json.dumps(good) + "\nalso broken\n")
        res, problems = call(H.parse_hayabusa_jsonl, out)
        check("SA-2 unreadable result lines are counted and reported",
              len(problems) == 1 and "2" in problems[0], f"problems {problems}")
        check("SA-2 the readable lines are still used", sum(c.get("event_count", 0) for c in res) == 2)
        with open(out, "w", encoding="utf-8") as f:
            f.write(json.dumps(good) + "\n")
        res, problems = call(H.parse_hayabusa_jsonl, out)
        check("SA-2 a clean result reports nothing", problems == [] and len(res) == 1)

        # SA-3
        before = sorted(os.listdir(ev))
        (flag, val, tmp), problems = call(H._resolve_input, [paths["a.evtx"], paths["b.evtx"]])
        check("SA-3 nothing is created in the evidence folder", sorted(os.listdir(ev)) == before,
              f"{sorted(os.listdir(ev))}")
        check("SA-3 the logs' link counts are unchanged",
              all(os.stat(p).st_nlink == 1 for p in paths.values()))
        check("SA-3 only the two selected logs are scanned",
              bool(tmp) and os.path.dirname(os.path.abspath(val)) != ev and scanned(val) == ["a.evtx", "b.evtx"])
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
        (flag, val, tmp), problems = call(H._resolve_input, list(paths.values()))
        check("SA-3 a fully selected folder is scanned in place", (flag, val, tmp) == ("-d", ev, None))

        # SA-5
        (flag, val, tmp), problems = call(H._resolve_input,
                                          [paths["a.evtx"], paths["b.evtx"], os.path.join(ev, "gone.evtx")])
        check("SA-5 the log that was not selected is not scanned",
              bool(tmp) and val != ev and scanned(val) == ["a.evtx", "b.evtx"])
        check("SA-5 the path that was not found is reported", len(problems) == 1 and "1" in problems[0],
              f"{problems}")
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

        # SA-4
        home = os.path.normcase(os.path.expanduser("~"))
        ok_roots = (home, os.path.normcase("C:\\Program Files"))
        bad = [p for p in H._COMMON_PATHS_WIN if not os.path.normcase(p).startswith(ok_roots)]
        check("SA-4 Hayabusa is searched only in the analyst's or administrators' folders", not bad, f"{bad}")
    finally:
        shutil.rmtree(base, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
