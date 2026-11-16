"""PowerShell sessions: a PID match needs the session to be running, and the same engine.

Gemini audit 9-13 (Medium), session_builder / models:
1. an event matched by PID joined a session that had not started yet or
   had already stopped (PIDs are reused), or the earliest session when none
   had started;
2. a PowerShell 7 (PowerShellCore) event joined a Windows PowerShell 5.1
   session of the same PID (another engine, another process);
3. a 4103 matched by PID did not fill the session's user name (matched by
   HostId it did);
4. duration_str failed on "+00:00" timestamps.
Also: a stop logged before its start read 0:00:00, a duration the log does
not give; it reads Unavailable now.

Expected: those events unsessioned; the user filled; 0:00:15.  Synthetic.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, ts, rid, channel="Windows PowerShell", **kw):
    d = {"event_id": eid, "timestamp": ts, "pid": "4400", "computer": "C1", "event_record_id": rid,
         "channel": channel, "host_id": ""}
    d.update(kw)
    return d


def main() -> int:
    from evtx_tool.analysis.ps_extractor.session_builder import build_sessions
    from evtx_tool.analysis.ps_extractor.models import PSSession
    op, core = "Microsoft-Windows-PowerShell/Operational", "PowerShellCore/Operational"
    b = {400: [ev(400, "2026-01-01T10:00:00Z", 1, host_id="H1", host_application="powershell.exe")],
         403: [ev(403, "2026-01-01T10:00:10Z", 2, host_id="H1")],
         4104: [ev(4104, "2026-01-01T09:59:50Z", 3, op, script_block_id="{a1}", message_number=1),
                ev(4104, "2026-01-01T10:00:20Z", 4, op, script_block_id="{a2}", message_number=1),
                ev(4104, "2026-01-01T10:00:05Z", 5, op, script_block_id="{a3}", message_number=1)],
         4103: [ev(4103, "2026-01-01T10:00:05Z", 6, core, user="SYNTH\\bob", command_name="Get-Date"),
                ev(4103, "2026-01-01T10:00:06Z", 7, op, user="SYNTH\\alice", command_name="Get-Item")]}
    ss = build_sessions(b)
    h1 = next(s for s in ss if s.host_id == "H1")
    rids = sorted(e["event_record_id"] for e in h1.session_events)
    check("only events inside the session's run, of its engine, join it", rids == [1, 2, 5, 7], str(rids))
    un = next((s for s in ss if s.host_id == "_unsessioned"), None)
    urids = sorted(e["event_record_id"] for e in un.session_events) if un else []
    check("...the others are kept unsessioned", urids == [3, 4, 6], str(urids))
    check("a 4103 matched by PID fills the user name", h1.user_name == "SYNTH\\alice", repr(h1.user_name))

    s = PSSession(host_id="x", pid="1", computer="C", start_ts="2026-01-01T10:00:00+00:00",
                  stop_ts="2026-01-01T10:00:15+00:00", host_name="", host_version="", host_application="",
                  encoded_command="", runspace_id="")
    check("duration with +00:00 timestamps", s.duration_str() == "0:00:15", repr(s.duration_str()))
    s.stop_ts = "2026-01-01T09:59:00Z"
    check("a stop before the start has no duration (not 0:00:00)", s.duration_str().startswith("Unavailable"),
          repr(s.duration_str()))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
