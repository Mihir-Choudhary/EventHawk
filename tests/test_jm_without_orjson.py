"""Juggernaut works without the optional orjson, and stores the same JSON text.

Gemini audit 2-06 (Medium): core/heavyweight/engine.py did a bare top-level
"import orjson", so without that optional package (requirements.txt says it
falls back to the stdlib) Juggernaut mode could not even be imported.

Expected: with orjson made unimportable, the engine imports, extracts a row,
and the stored event_data JSON is byte-identical to what orjson writes (the
stdlib's default separators add spaces, which would change the stored text).
Runs the no-orjson half in a subprocess; synthetic record.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


CHILD = r'''
import sys, json
sys.modules["orjson"] = None          # "import orjson" now raises ImportError
sys.path.insert(0, sys.argv[1])
from evtx_tool.core.heavyweight import engine as H
rec = {"Event": {"System": {"Provider": {"#attributes": {"Name": "P"}}, "EventID": 4688, "Level": 0,
       "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00.000000Z"}}, "EventRecordID": 9,
       "Channel": "Security", "Computer": "HOST-A"},
       "EventData": {"NewProcessName": "C:\\x\\é.exe", "Count": 3, "List": ["a", "b"]}}}
row = H._extract_and_filter(rec, "f.evtx", None)
print(json.dumps([v for v in row if isinstance(v, str) and v.startswith("{")]))
'''


def main() -> int:
    p = subprocess.run([sys.executable, "-c", CHILD, ROOT], capture_output=True, text=True, encoding="utf-8")
    check("Juggernaut's engine imports and extracts without orjson", p.returncode == 0,
          (p.stderr or "").strip().splitlines()[-1:] and (p.stderr or "").strip().splitlines()[-1])
    if p.returncode == 0:
        no_orjson = json.loads(p.stdout.strip().splitlines()[-1])
        from evtx_tool.core.heavyweight import engine as H
        rec = {"Event": {"System": {"Provider": {"#attributes": {"Name": "P"}}, "EventID": 4688, "Level": 0,
               "TimeCreated": {"#attributes": {"SystemTime": "2026-01-01T00:00:00.000000Z"}}, "EventRecordID": 9,
               "Channel": "Security", "Computer": "HOST-A"},
               "EventData": {"NewProcessName": "C:\\x\\é.exe", "Count": 3, "List": ["a", "b"]}}}
        with_orjson = [v for v in H._extract_and_filter(rec, "f.evtx", None) if isinstance(v, str) and v.startswith("{")]
        check("the stored JSON text is identical with and without orjson", no_orjson == with_orjson and with_orjson,
              f"{no_orjson} vs {with_orjson}")
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
