"""Juggernaut keeps a missing ProcessID / ThreadID missing, never 0.

Codex release audit C5: `_safe_int(None)` returns 0, so a record whose System
block has no Execution ProcessID/ThreadID was stored with PID 0 and TID 0 --
185 records of a real 46,748-record selection.  Absence is not PID 0 (and
PID 0 is a real value: the System Idle Process).  Normal mode keeps None.
Synthetic records only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def record(execution):
    system = {"EventID": 7036, "Level": 4, "EventRecordID": 9, "Channel": "System", "Computer": "C",
              "Provider": {"#attributes": {"Name": "P"}},
              "TimeCreated": {"#attributes": {"SystemTime": "2024-01-01T00:00:00.000000Z"}}}
    if execution is not None:
        system["Execution"] = execution
    return {"Event": {"System": system, "EventData": {}}}


def main() -> int:
    from evtx_tool.core.heavyweight.engine import _ARROW_COLS, _extract_and_filter
    pi, ti = _ARROW_COLS.index("process_id"), _ARROW_COLS.index("thread_id")

    def ids(rec):
        row = _extract_and_filter(rec, r"C:\s\System.evtx", None)
        return (row[pi], row[ti]) if isinstance(row, tuple) else ("not a row", row)

    check("no Execution element: PID and TID stay empty", ids(record(None)) == (None, None), str(ids(record(None))))
    check("Execution without the attributes: PID and TID stay empty",
          ids(record({"#attributes": {}})) == (None, None), str(ids(record({"#attributes": {}}))))
    check("a real PID 0 / TID 0 stays 0",
          ids(record({"#attributes": {"ProcessID": 0, "ThreadID": 0}})) == (0, 0))
    check("ordinary IDs are kept", ids(record({"#attributes": {"ProcessID": 4321, "ThreadID": 77}})) == (4321, 77))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
