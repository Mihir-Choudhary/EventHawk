"""CLI --profile takes a name or a JSON file; an unknown one stops the run (Codex C6-1).

docs/12-cli.md promises a profile name or a JSON path.  The path was looked up
as a name, not found, logged to the log file only, and the run went on with no
profile: a real 16,841-event export instead of 240, exit 0, "Profiles: <path>"
printed, and no profile in a --save-filter file.
Expected: a JSON path is loaded and applied; a name or path that does not
exist ends the run with a visible error and a non-zero exit, before parsing.
Synthetic profile; the CLI run uses one test log when EVTX_TEST_LOGS is set.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.filters import empty_filter
    from evtx_tool.profiles.manager import ProfileManager
    tmp = tempfile.mkdtemp(prefix="cliprof_")
    try:
        prof = os.path.join(tmp, "only_4688.json")
        with open(prof, "w", encoding="utf-8") as fh:
            json.dump({"name": "Only 4688 (test)", "description": "test", "event_ids": [4688],
                       "sources": ["Microsoft-Windows-Security-Auditing"]}, fh)
        pm = ProfileManager()
        try:
            fc = pm.build_filter([prof], base_filter=empty_filter(), strict=True)
            groups = fc.get("profile_groups") or []
        except TypeError:                                    # pre-fix signature
            groups = (pm.build_filter([prof], base_filter=empty_filter()).get("profile_groups") or [])
        except Exception as exc:                             # noqa: BLE001
            groups = f"{type(exc).__name__}: {exc}"
        check("a profile JSON path is loaded and applied",
              isinstance(groups, list) and len(groups) == 1 and groups[0].get("event_ids") == [4688], str(groups))
        raised = None
        try:
            pm.build_filter(["No Such Profile 123"], base_filter=empty_filter(), strict=True)
        except Exception as exc:                             # noqa: BLE001
            raised = exc
        check("an unknown profile is an error, not an empty profile list",
              raised is not None and "No Such Profile 123" in str(raised), repr(raised))

        logs = os.environ.get("EVTX_TEST_LOGS", "")
        src = next(iter(sorted(glob.glob(os.path.join(logs, "*.evtx")))), None) if logs else None
        if src:
            out = os.path.join(tmp, "o.json")
            r = subprocess.run([sys.executable, "-B", os.path.join(ROOT, "evtx_tool.py"), "parse", src,
                                "--profile", "No Such Profile 123", "--no-tui", "-o", out],
                               capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
            check("CLI: an unknown --profile exits non-zero, says so, writes nothing",
                  r.returncode != 0 and "No Such Profile 123" in (r.stdout + r.stderr) and not os.path.exists(out),
                  f"exit {r.returncode}")
        else:
            print("  (EVTX_TEST_LOGS not set: CLI run skipped)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
