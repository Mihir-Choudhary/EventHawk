"""PowerShell History matches events to sessions by PID on the SAME computer only.

Codex release audit C7: the session builder indexed sessions by PID alone,
so with logs from two machines a 4103 (or 53504) of PID 7 on machine A was
put into the session of PID 7 on machine B.  PID 7 on A says nothing about
PID 7 on B.  Expected: the event stays unsessioned (kept, not attributed).
Synthetic events only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.analysis.ps_extractor.session_builder import build_sessions

    def s400(comp, ts, hid):
        return {"event_id": 400, "timestamp": ts, "pid": "7", "computer": comp, "host_id": hid,
                "host_application": "powershell.exe"}

    b = {400: [s400("MACHINE-B", "2024-01-01T00:00:10Z", "HB")],
         4103: [{"event_id": 4103, "timestamp": "2024-01-01T00:00:20Z", "pid": "7", "computer": "MACHINE-A",
                 "host_id": "", "command_name": "Cross"}],
         53504: [{"event_id": 53504, "timestamp": "2024-01-01T00:00:09.500Z", "pid": "7",
                  "computer": "MACHINE-A", "app_domain": "D"}]}
    ss = {s.host_id: s for s in build_sessions(b)}
    in_b = [e for e in ss["HB"].session_events if e.get("computer") == "MACHINE-A"]
    loose = [e["event_id"] for e in ss.get("_unsessioned").session_events] if "_unsessioned" in ss else []
    check("machine A's events are not put in machine B's session", not in_b, f"{len(in_b)} attached")
    check("...they are kept, unsessioned", sorted(loose) == [4103, 53504], str(loose))

    b = {400: [s400("MACHINE-A", "2024-01-01T00:00:10Z", "HA")],
         4103: [{"event_id": 4103, "timestamp": "2024-01-01T00:00:20Z", "pid": "7", "computer": "machine-a",
                 "host_id": "", "command_name": "Same"}],
         53504: [{"event_id": 53504, "timestamp": "2024-01-01T00:00:09.500Z", "pid": "7",
                  "computer": "MACHINE-A", "app_domain": "D"}]}
    ss = {s.host_id: s for s in build_sessions(b)}
    got = sorted(e["event_id"] for e in ss["HA"].session_events)
    check("same computer (any case): events still join their session", got == [400, 4103, 53504], str(got))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
