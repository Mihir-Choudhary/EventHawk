"""Host identity: which Computer names belong to the same machine.

One machine records more than one Computer name: renames (EID 6011, e.g. the
setup name WIN-VR474TJ38H3 becoming DESKTOP-A8CALR3), and FQDN versus short
name.  Six of seven public single-machine collections do this.  Exact-name
matching therefore drops events when an analyst asks for "this host".

These synthetic cases pin the grouping rules of
docs/superpowers/specs/2026-10-23-time-window-pivot-and-host-identity-design.md
section 2: renames and a single domain suffix link automatically; two domains
and shared local log files are only suggestions; IP literals stay whole;
blank names are never linked; confirm/reject regroup.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def main() -> int:
    from evtx_tool.core.host_identity import (
        UNKNOWN, HostIdentity, NameStat, Rename, name_key, parse_rename,
    )

    def ns(name, f=r"C:\x\System.evtx", n=1, first="2022-01-01T00:00:00.000000Z",
           last="2022-01-01T00:00:00.000000Z"):
        return NameStat(name, f, n, first, last)

    def rn(old, new, ts="2022-01-01T00:00:01.000000Z", f=r"C:\x\System.evtx", rid=1):
        return Rename(old, new, ts, f, rid)

    print("=== renames ===")
    hi = HostIdentity.build([ns("A", r"C:\a.evtx"), ns("C", r"C:\c.evtx")],
                            [rn("A", "B"), rn("B", "C", rid=2)])
    g = hi.group_of("A")
    check("a rename chain through an unseen name joins both ends",
          g.members == ["A", "C"], str(g.members))
    check("...with two automatic rename links",
          sorted((l.kind, l.state) for l in g.links) == [("rename", "auto")] * 2,
          str(g.links))
    check("the bridge name is not a member", "B" not in g.members)

    hi = HostIdentity.build([ns("evtx-PC")], [rn("evtx-PC", "EVTX-PC")])
    check("a case-only rename leaves one group", hi.group_of("evtx-PC").members == ["evtx-PC"],
          str(hi.group_of("evtx-PC").members))

    hi = HostIdentity.build([ns("A", r"C:\a.evtx"), ns("B", r"C:\b.evtx")],
                            [rn("A", "B"), rn("B", "A", rid=2)])
    check("a rename cycle is one group", hi.group_of("A").members == ["A", "B"])

    print("\n=== domain suffix ===")
    hi = HostIdentity.build([ns("WS01", r"C:\a.evtx"), ns("WS01.corp.local", r"C:\b.evtx")], [])
    g = hi.group_of("WS01")
    check("one domain links the bare name automatically",
          g.members == ["WS01", "WS01.corp.local"], str(g.members))
    check("...as an automatic domain_suffix link",
          [(l.kind, l.state) for l in g.links] == [("domain_suffix", "auto")], str(g.links))

    hi = HostIdentity.build([ns("WS01", r"C:\a.evtx"), ns("WS01.a.local", r"C:\b.evtx"),
                             ns("WS01.b.local", r"C:\c.evtx")], [])
    check("two domains: the bare name stays alone", hi.group_of("WS01").members == ["WS01"])
    sug = hi.suggestions_for("WS01")
    check("...with two suggested domain_suffix links",
          sorted((l.kind, l.state) for l in sug) == [("domain_suffix", "suggested")] * 2,
          str(sug))
    check("two different FQDNs are never linked to each other",
          hi.group_of("WS01.a.local").members == ["WS01.a.local"]
          and all({l.a, l.b} != {"ws01.a.local", "ws01.b.local"}
                  for l in hi.suggestions_for("WS01.a.local")))

    print("\n=== shared local log file ===")
    hi = HostIdentity.build([ns("HOSTA"), ns("HOSTB")], [])
    check("two names in one local file stay separate groups",
          hi.group_of("HOSTA").members == ["HOSTA"])
    sug = hi.suggestions_for("HOSTA")
    check("...with one same_file suggestion naming the file",
          len(sug) == 1 and sug[0].kind == "same_file" and sug[0].state == "suggested"
          and r"C:\x\System.evtx" in sug[0].evidence, str(sug))

    hi = HostIdentity.build([ns("HOSTA", r"C:\x\ForwardedEvents.evtx"),
                             ns("HOSTB", r"C:\x\ForwardedEvents.evtx")], [])
    check("a forwarded file gives no suggestion", hi.suggestions_for("HOSTA") == [])

    print("\n=== IP literals and blank names ===")
    check("an IPv4 literal is never split", name_key("10.0.0.5") == ("10.0.0.5", "10.0.0.5"))
    check("an IPv6 literal stays whole", name_key("fe80::1")[0] == "fe80::1")
    hi = HostIdentity.build([ns("10.0.0.5", r"C:\a.evtx"), ns("10.0.0.6", r"C:\b.evtx")], [])
    check("two IPs in the same /8 stay two groups",
          hi.group_of("10.0.0.5").members == ["10.0.0.5"]
          and hi.group_of("10.0.0.6").members == ["10.0.0.6"])
    check("a blank name keys as (unknown)", name_key("  ") == (UNKNOWN, UNKNOWN))
    hi = HostIdentity.build([ns(""), ns("HOSTA")], [])
    check("a blank name in a shared file gets no suggestion",
          hi.suggestions_for("HOSTA") == [] and hi.suggestions_for("") == [])
    check("the blank group holds only the blank name", hi.group_of("").members == [""])

    print("\n=== unreadable 6011 ===")
    check("a one-name 6011 payload is unreadable",
          parse_rename({"Data": {"#text": ["only-one"]}}) is None)
    check("a two-name 6011 payload reads as (old, new)",
          parse_rename({"Data": {"#text": ["WIN-VR474TJ38H3", "DESKTOP-A8CALR3"]}})
          == ("WIN-VR474TJ38H3", "DESKTOP-A8CALR3"))
    check("the unreadable count is kept",
          HostIdentity.build([ns("A")], [], unreadable_renames=2).unreadable_renames == 2)

    print("\n=== confirm / reject ===")
    hi = HostIdentity.build([ns("HOSTA"), ns("HOSTB")], [])
    link = hi.suggestions_for("HOSTA")[0]
    hi.confirm(link)
    g = hi.group_of("HOSTA")
    check("confirming a suggestion merges the groups", g.members == ["HOSTA", "HOSTB"],
          str(g.members))
    check("...and the link is confirmed",
          [l.state for l in g.links if l.kind == "same_file"] == ["confirmed"], str(g.links))
    hi.reject(link)
    check("rejecting it splits them again", hi.group_of("HOSTA").members == ["HOSTA"])
    check("...and it is no longer suggested", hi.suggestions_for("HOSTA") == [])

    print("\n=== display name ===")
    hi = HostIdentity.build(
        [ns("WIN-VR474TJ38H3", r"C:\a.evtx", last="2022-02-07T10:53:59.000000Z"),
         ns("DESKTOP-A8CALR3", r"C:\b.evtx", last="2022-02-10T09:00:00.000000Z")],
        [rn("WIN-VR474TJ38H3", "DESKTOP-A8CALR3")])
    check("the display name is the latest name",
          hi.group_of("WIN-VR474TJ38H3").display_name == "DESKTOP-A8CALR3")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
