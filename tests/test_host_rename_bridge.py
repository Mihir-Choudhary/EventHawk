"""A rename to a short name bridges to that name's FQDN.

Codex review-1 F4: an EID 6011 says OLD-PC was renamed NEW-PC; later events are
stamped NEW-PC.corp.local; NEW-PC itself is on no event.  The rename linked
OLD-PC to the unseen NEW-PC, but the domain-suffix pass only looked at names
seen on events, so NEW-PC never reached NEW-PC.corp.local: two groups, and
"this host" around the FQDN left out the old name's events.

The existing rules must hold: several domains for one short name stay a
suggestion, an old name renamed to two names (a cloned image) stays a
suggestion, and a name seen on no event is never listed as a member.
Pure logic, synthetic names.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.core.host_identity import HostIdentity, NameStat, Rename   # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ns(name, f):
    return NameStat(name, f, 1, "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")


def rn(old, new, ts="2024-01-01T12:00:00Z"):
    return Rename(old, new, ts, r"C:\c\System.evtx", 1)


def main() -> int:
    h = HostIdentity.build([ns("OLD-PC", r"C:\c\a.evtx"), ns("NEW-PC.corp.local", r"C:\c\b.evtx")],
                           [rn("OLD-PC", "NEW-PC")])
    g = h.group_of("OLD-PC")
    check("rename to an unseen short name joins that name's FQDN",
          sorted(g.members) == ["NEW-PC.corp.local", "OLD-PC"], str(g.members))
    check("the unseen short name is not listed as a member", "NEW-PC" not in g.members, str(g.members))
    check("one group, not two", len(h.groups()) == 1, str([x.members for x in h.groups()]))

    h = HostIdentity.build([ns("OLD-PC", r"C:\c\a.evtx"), ns("NEW-PC.corp.local", r"C:\c\b.evtx"),
                            ns("NEW-PC.other.local", r"C:\c\d.evtx")], [rn("OLD-PC", "NEW-PC")])
    check("two domains for the new short name: only suggestions, nothing joined automatically",
          sorted(h.group_of("OLD-PC").members) == ["OLD-PC"], str(h.group_of("OLD-PC").members))

    h = HostIdentity.build([ns("TEMPLATE", r"C:\c\a.evtx"), ns("NEW1.corp.local", r"C:\c\b.evtx")],
                           [rn("TEMPLATE", "NEW1"), rn("TEMPLATE", "NEW2")])
    check("an image renamed to two names (clone) stays a suggestion",
          sorted(h.group_of("TEMPLATE").members) == ["TEMPLATE"], str(h.group_of("TEMPLATE").members))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
