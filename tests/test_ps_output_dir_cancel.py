"""PowerShell History: a reused folder is not mixed, a cancelled run leaves no partial files.

Gemini audit 9-12 (Medium): extracting into a folder that already held an
extraction left the earlier run's scriptblock_*.txt files beside the new
ones (more block files than the summary counts); a run cancelled while
writing left a partial set of files; the block-file loop never checked
for cancel.

Expected: the second run goes to a new subfolder (the first run's files
untouched) with exactly its own block files; a run cancelled while writing
block files stops there and removes what it wrote.  Synthetic records.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def rec(rid, text):
    data = {"Event": {"System": {"Channel": "Microsoft-Windows-PowerShell/Operational", "EventID": 4104,
                                 "Computer": "C1", "Level": 5, "EventRecordID": rid,
                                 "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:%02d.000000Z" % rid}}},
                      "EventData": {"MessageNumber": 1, "MessageTotal": 1, "ScriptBlockText": text,
                                    "ScriptBlockId": "{%08d-1111-1111-1111-111111111111}" % rid, "Path": ""}}}
    return {"event_record_id": rid, "timestamp": "x", "data": json.dumps(data)}


def blocks(d):
    return sorted(f for f in os.listdir(d) if f.startswith("scriptblock_"))


def main() -> int:
    from evtx_tool.analysis.ps_extractor.extractor import PSExtractor
    root = tempfile.mkdtemp(prefix="ps_dir_")
    try:
        PSExtractor([rec(1, "a"), rec(2, "b")], root).run()
        first = blocks(root)
        s = PSExtractor([rec(3, "c")], root).run()
        out = s.get("output_dir") or root
        check("the second run does not mix its files with the first",
              out != root and blocks(out) == ["scriptblock_00000003-1111-1111-1111-111111111111.txt"]
              and s.get("script_blocks") == 1, f"{out} {blocks(out)}")
        check("the first run's files are untouched", blocks(root) == first, str(blocks(root)))

        d2 = tempfile.mkdtemp(prefix="ps_cancel_")
        x = PSExtractor([rec(i, f"t{i}") for i in range(1, 40)], d2)
        seen = {"n": 0}
        x.cancel_check = lambda: seen["n"] > 0

        def progress(step, pct):
            if step.startswith("Writing script block files") and "(" in step and not step.startswith(
                    "Writing script block files (0/"):
                seen["n"] += 1
        x.progress_callback = progress
        s2 = x.run()
        left = [f for f in os.listdir(d2)]
        check("a run cancelled while writing block files says so", s2.get("cancelled") is True, str(s2.get("cancelled")))
        check("...and leaves no partial files", left == [], str(left[:5]))
        shutil.rmtree(d2, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
