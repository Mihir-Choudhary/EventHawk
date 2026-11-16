"""Sentinel lineage: dead parents flagged on every path, chains walked fully and safely.

Gemini audit 10-07 (High): the Sysmon (GUID) path returned a parent with
no exit-time check, so PPID spoofing of a terminated Sysmon parent was
never flagged; a Sysmon process exit updated only the GUID entry.
10-13 (High): after PPID_MISMATCH the engine still scored the spoofed
parent name, and the ancestry walk grafted the dead parent's ancestry.
10-14 (Medium): on Security logs the walk stopped after one hop (no PPID
kept), and any repeated name (cmd -> powershell -> cmd) was taken for a
cycle.

Expected: each right.  Synthetic events.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, s, name, pid=0, ppid=0, guid="", pguid="", parent=""):
    from sentinel.models import RawEvent
    return RawEvent(timestamp=T0 + timedelta(seconds=s), host="H", event_id=eid, process_guid=guid, pid=pid,
                    ppid=ppid, parent_guid=pguid, process_name=name, process_path="C:\\x\\" + name,
                    parent_name=parent, parent_path="", cmdline=name, user="u", integrity_level="", image_hash="")


def main() -> int:
    from sentinel.analysis.lineage import LineageTracker
    from sentinel.analysis.normalizer import normalize_procname as n

    # 10-07: Sysmon parent terminated before the child; exit by EID 5 updates the PID entry too.
    t = LineageTracker()
    t.process_event(ev(1, 0, "svchost.exe", pid=400, guid="{P}", parent="services.exe"))
    t.process_event(ev(5, 10, "svchost.exe", pid=400, guid="{P}"))
    c = ev(1, 20, "cmd.exe", pid=500, ppid=400, guid="{C}", pguid="{P}", parent="svchost.exe")
    r = t.process_event(c)
    check("Sysmon: a dead parent is flagged PPID_MISMATCH", "PPID_MISMATCH" in c.flags and r is None, str((c.flags, r)))
    check("Sysmon: a process exit also marks the PID entry", t._by_pid[400].exit_time is not None)

    # A GUID-less Security 4689 of the same PID does not end a Sysmon-tracked
    # parent (on the corpus this flagged two live parents' children).
    t = LineageTracker()
    t.process_event(ev(1, 0, "svchost.exe", pid=400, guid="{P}", parent="services.exe"))
    t.process_event(ev(4689, 5, "svchost.exe", pid=400))
    c = ev(1, 6, "cmd.exe", pid=500, ppid=400, guid="{C}", pguid="{P}", parent="svchost.exe")
    t.process_event(c)
    check("a Security 4689 does not end a process Sysmon tracks", "PPID_MISMATCH" not in c.flags, str(c.flags))

    # 10-14: a Security 4688 chain of 5 with a repeated name.
    t = LineageTracker()
    names = ["wininit.exe", "services.exe", "cmd.exe", "powershell.exe", "cmd.exe"]
    evs = []
    for i, nm in enumerate(names):
        e = ev(4688, i, nm, pid=100 + i, ppid=99 + i if i else 4, parent=names[i - 1] if i else "System")
        t.process_event(e)
        evs.append(e)
    last = evs[-1]
    chain = t.get_ancestry_chain(last, n(last.process_name), n(last.parent_name))
    check("Security: the chain is walked to 5 levels through a repeated name",
          chain == [n(x) for x in reversed(names)], str(chain))

    # 10-13: the walk stops at a terminated parent.
    t = LineageTracker()
    t.process_event(ev(4688, 0, "services.exe", pid=300, ppid=4, parent="wininit.exe"))
    t.process_event(ev(4688, 1, "svchost.exe", pid=0x400, ppid=300, parent="services.exe"))
    t.process_event(ev(4689, 5, "svchost.exe", pid=0x400))
    sp = ev(4688, 10, "cmd.exe", pid=600, ppid=0x400, parent="svchost.exe")
    r = t.process_event(sp)
    chain = t.get_ancestry_chain(sp, "cmd.exe", "x")
    check("Security: the spoofed child is flagged", "PPID_MISMATCH" in sp.flags and r is None, str(sp.flags))
    check("...and no ancestry is grafted from the dead parent", "services.exe" not in chain, str(chain))

    from sentinel.analysis.engine import scored_parent
    pn = scored_parent(r, sp)
    check("the engine does not score the spoofed parent's name", pn != n("svchost.exe") and "svchost" in pn, repr(pn))
    ok_ev = ev(4688, 0, "a.exe", parent="explorer.exe")
    check("...an unflagged event still uses its parent", scored_parent(None, ok_ev) == n("explorer.exe"))
    n_ = sum(ok for _, ok, _ in CHECKS)
    print(f"{n_}/{len(CHECKS)} checks passed")
    return 0 if n_ == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
