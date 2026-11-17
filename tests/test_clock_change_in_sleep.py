"""Only Windows' own wake correction is excused inside a sleep (Codex PR19-2).

Every clock change inside a sleep, hibernation or low-power period (plus two
minutes) was ignored, whatever it was. A change by an application in the middle
of the period then left the period with a "known" length that the clock change
makes unprovable, and the report called it a correction made on waking.

Windows' wake correction is recognisable: it is not an application change
(Kernel-General 1 Reason 1), the new time lands on the wake, and the jump is no
larger than the period. On the real test logs all 65 such changes fit that and
the one application change inside a hibernation did not.

Expected: the wake correction keeps the period's length and is marked as made
on waking in the report; an application change, a change whose new time is not
the wake, and a jump larger than the period make the length Unavailable and are
not marked as made on waking. Synthetic events only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import test_system_activity as T                                    # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def hib(evs):
    from evtx_tool.analysis import system_activity as SA
    res = SA.build(evs)
    return next(r for r in res["rows"] if r["state"] == "Hibernate"), res


def wake_flag(res, evs):
    from evtx_tool.output import system_activity_report as rep
    p = rep.build_payload(res, evs)
    return [c[5] for c in p.get("clock", [])]


def main() -> int:
    base = T.scenario()
    # the hibernation runs 14:18:09.963981 -> 17:34:17.141136
    cases = [
        ("Windows' wake correction (Reason 2, new time = the wake)", True,
         T.ev("2025-11-13T17:33:30.000000Z", T.KG, 1, OldTime="2025-11-13T14:19:00.000000Z",
              NewTime="2025-11-13T17:34:17.000000Z", Reason="2")),
        ("an application change in the middle (Reason 1)", False,
         T.ev("2025-11-13T15:00:00.000000Z", T.KG, 1, OldTime="2025-11-13T15:00:00.000000Z",
              NewTime="2025-11-13T15:10:00.000000Z", Reason="1")),
        ("a hardware sync whose new time is not the wake", False,
         T.ev("2025-11-13T15:00:00.000000Z", T.KG, 1, OldTime="2025-11-13T15:00:00.000000Z",
              NewTime="2025-11-13T15:10:00.000000Z", Reason="2")),
        ("a jump larger than the period", False,
         T.ev("2025-11-13T17:34:00.000000Z", T.KG, 1, OldTime="2025-11-13T10:00:00.000000Z",
              NewTime="2025-11-13T17:34:17.000000Z", Reason="2")),
        ("Security 4616 landing on the wake", True,
         T.ev("2025-11-13T17:33:30.000000Z", T.SEC, 4616, chan="Security", PreviousTime="2025-11-13T14:19:00.000000Z",
              NewTime="2025-11-13T17:34:17.000000Z", ProcessName="C:\\Windows\\System32\\svchost.exe")),
    ]
    for label, excused, ch in cases:
        evs = base + [ch]
        r, res = hib(evs)
        if excused:
            check(f"{label}: the hibernation keeps its length", r["duration"] is not None, r["notes"])
        else:
            check(f"{label}: the hibernation's length is Unavailable", r["duration"] is None, r["notes"])
        flags = wake_flag(res, evs)
        check(f"{label}: report marks it {'made on waking' if excused else 'not made on waking'}",
              flags == [excused], str(flags))
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
