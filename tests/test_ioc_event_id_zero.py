"""An IOC's event-ID context includes event ID 0 when an event 0 produced it.

Found by Codex in audit-5b (Minor, both modes): the IOC accumulator added an
event ID only when it was truthy, so a real EventID 0 (42 explicit raw records
on the corpus) never appeared in "Event IDs" -- Normal 6 / JM 7 computer
IOCs showed a context without one of their producers' IDs.  The producer
keys and counts were complete; only the context lied by omission.

Expected: 0 is listed like any other ID; an event with no event ID at all
adds none.  Synthetic events.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, eid, comp):
    e = {"record_id": rid, "source_file": r"C:\c\System.evtx", "computer": comp,
         "timestamp": f"2026-01-01T00:00:{rid:02d}.000000Z", "event_data": {}}
    if eid is not ...:
        e["event_id"] = eid
    return e


def main() -> int:
    from evtx_tool.analysis.ioc_extractor import extract_iocs

    def ids(evs, comp):
        ent = next((c for c in extract_iocs(evs).get("computers", []) if c["value"] == comp), None)
        return ent and ent["event_ids"]

    got = ids([ev(1, 0, "WS1"), ev(2, 7036, "WS1")], "WS1")
    check("event 0 first, then 7036: both IDs listed", got == [0, 7036], str(got))
    got = ids([ev(1, 7036, "WS2"), ev(2, 0, "WS2")], "WS2")
    check("event 7036 first, then 0: both IDs listed", got == [0, 7036], str(got))
    got = ids([ev(1, ..., "WS3"), ev(2, 7036, "WS3")], "WS3")
    check("an event without an event ID adds none", got == [7036], str(got))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
