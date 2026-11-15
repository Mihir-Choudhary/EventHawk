"""Hayabusa staging: sub-folders are included; detections name the original log.

Gemini audit 7-14 (Medium): when several paths were selected, a selected
folder was staged with glob("*.evtx"), so logs in its sub-folders were not
scanned; detections then named the staged copy ("0000_Security.evtx" in
%TEMP%) instead of the log the analyst selected; and with Hayabusa asked for
but not found, the analysis said nothing.

Expected: a folder with logs at two depths plus a single file stage all three;
the staged-name map points back to the original paths; the analysis process
reports a missing Hayabusa.  Synthetic files (names only; nothing is run).
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.analysis.hayabusa_runner as H
    root = tempfile.mkdtemp(prefix="haya_")
    try:
        d = os.path.join(root, "case")
        os.makedirs(os.path.join(d, "sub"))
        for p in (os.path.join(d, "System.evtx"), os.path.join(d, "sub", "Security.evtx"),
                  os.path.join(root, "Single.evtx")):
            open(p, "wb").close()
        flag, val, tmp = H._resolve_input([d, os.path.join(root, "Single.evtx")])
        staged = sorted(os.listdir(val)) if tmp else []
        check("the folder's sub-folder log is staged", any(s.endswith("Security.evtx") for s in staged), str(staged))
        check("all three logs are staged", len(staged) == 3, str(staged))
        mp = getattr(H, "_STAGED_ORIGINALS", {}).get(tmp, {}) if tmp else {}
        back = sorted(mp.get(s.lower(), "") for s in staged)
        check("each staged name maps back to the selected log",
              back == sorted([os.path.join(d, "System.evtx"), os.path.join(d, "sub", "Security.evtx"),
                              os.path.join(root, "Single.evtx")]), str(back))
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    src = open(os.path.join(os.path.dirname(H.__file__), "analysis_worker_proc.py"), encoding="utf-8").read()
    check("the analysis process reports a missing Hayabusa", 'do_hayabusa and not hayabusa_path' in src
          and 'errors["Hayabusa"]' in src)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
