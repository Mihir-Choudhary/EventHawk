"""PowerShell sessions: events join the right session, by host, HostId and time.

Gemini audit 9-07 (High), ps_extractor session reconstruction:
1. a classic 400/403 with no <Execution> element lost the PID its
   EventData carries (ProcessId), so its events could not join it;
2. timestamps were compared as text: "...:00Z" sorts after "...:00.5Z",
   so a 4104 half a second into a session was put before it;
3. a 403 of another computer with the same HostId stopped this session;
4. a 403 whose HostId differs only in letter case did not stop it;
5. a 4103 carrying another session's HostId was attached by PID to this
   one.

Expected: each of those right.  Synthetic parsed events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, ts, host_id="", pid="10", computer="C1", **kw):
    d = {"event_id": eid, "timestamp": ts, "host_id": host_id, "pid": pid, "computer": computer,
         "event_record_id": kw.pop("rid", 1), "channel": "Windows PowerShell"}
    d.update(kw)
    return d


def main() -> int:
    from evtx_tool.analysis.ps_extractor import event_parsers as P
    from evtx_tool.analysis.ps_extractor.session_builder import build_sessions
    rec = {"Event": {"System": {"EventID": 400, "Channel": "Windows PowerShell", "Computer": "C1",
                                "TimeCreated": {"#attributes": {"SystemTime": "2024-01-02T03:04:05.000000Z"}}},
                     "EventData": {"Data": [{"#attributes": {"Name": "ProcessId"}, "#text": "4242"},
                                            {"#attributes": {"Name": "HostId"}, "#text": "HID-1"}]}},
           "_record_id": 7}
    r = P.parse_400(rec)
    check("a classic 400 with no Execution keeps its EventData ProcessId", r.get("pid") == "4242", repr(r.get("pid")))

    s400 = ev(400, "2024-01-02T03:00:00Z", "HID-A", host_application="powershell.exe")
    sb = ev(4104, "2024-01-02T03:00:00.5Z", rid=2, script_block_id="{aa}", message_number=1)
    ss = [s for s in build_sessions({400: [s400], 4104: [sb]}) if s.host_id == "HID-A"]
    order = [e["event_id"] for e in ss[0].session_events] if ss else []
    check("a 4104 half a second into the session comes after its start", order == [400, 4104], str(order))

    other_403 = ev(403, "2024-01-02T04:00:00Z", "HID-A", computer="C2", rid=3)
    ss = [s for s in build_sessions({400: [s400], 403: [other_403]}) if s.host_id == "HID-A"]
    check("another computer's 403 does not stop this session", ss and ss[0].stop_ts == "", repr(ss[0].stop_ts if ss else None))

    up_403 = ev(403, "2024-01-02T04:00:00Z", "hid-a", rid=4)
    ss = [s for s in build_sessions({400: [s400], 403: [up_403]}) if s.host_id == "HID-A"]
    check("a 403 whose HostId differs in case stops it", ss and ss[0].stop_ts == "2024-01-02T04:00:00Z",
          repr(ss[0].stop_ts if ss else None))

    foreign = ev(4103, "2024-01-02T03:10:00Z", "HID-OTHER", rid=5, command_name="Get-Date")
    ss = build_sessions({400: [s400], 4103: [foreign]})
    a = [s for s in ss if s.host_id == "HID-A"]
    check("a 4103 with another session's HostId is not grafted in by PID",
          a and not any(e["event_id"] == 4103 for e in a[0].session_events)
          and any(e["event_id"] == 4103 for s in ss for e in s.session_events), str([s.host_id for s in ss]))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
