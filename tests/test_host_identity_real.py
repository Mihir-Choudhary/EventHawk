"""Host identity on seven real single-machine collections, in both modes.

NextronSystems evtx-baseline v0.8.5: complete winevt\\Logs folders from one
machine each.  Six of the seven record more than one Computer name, and the
spec (section 1.1) lists why: renames proven by EID 6011, and FQDN versus
short name.  Each collection must group into exactly the machine(s) it is.

Juggernaut builds the input from the Arrow table plus the Parquet shards;
Normal mode from the event list.  Both must produce identical input, so the
same pivot means the same thing in either mode.

Needs EVTX_TEST_LOGS_ONLINE (the "nextron" folder); skipped without it.
"""
import glob
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


EXPECTED = {
    # collection: (group that must exist, link kind joining it, display name or None)
    "win10-client": ({"DESKTOP-A8CALR3", "WIN-VR474TJ38H3"}, "rename", "DESKTOP-A8CALR3"),
    "win11-client": ({"DESKTOP-6D0DBMB", "WIN-KPO4DDU11AB"}, "rename", "DESKTOP-6D0DBMB"),
    "win11-client-2023": ({"WinDevEval", "WinDev2310Eval"}, "rename", "WinDev2310Eval"),
    "win2022-0-20348-azure": ({"Agamemnon", "WIN-06FB45IHQ35"}, "rename", "Agamemnon"),
    "win7-x86": ({"37L4247D28-05", "evtx-PC"}, "rename", "evtx-PC"),
    "win2022-ad": ({"WIN-FPV0DSIC9O6", "WIN-FPV0DSIC9O6.sigma.fr"}, "domain_suffix", None),
    "win2022-evtx": ({"WIN-TKC15D7KHUR"}, None, "WIN-TKC15D7KHUR"),
}
PARITY = ("win7-x86", "win10-client", "win2022-ad")


def jm_inputs(files):
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    from evtx_tool.core.heavyweight.host_inputs import inputs_from_jm
    tmp = tempfile.mkdtemp(prefix="hostid_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        table = load_arrow_table(pq)
        out = inputs_from_jm(table, pq)
        del table
        return out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE", "")
    if not root or not os.path.isdir(root):
        print("EVTX_TEST_LOGS_ONLINE not set -- skipped")
        return 0
    from evtx_tool.core.host_identity import HostIdentity, inputs_from_events
    from evtx_tool.core.parser import iter_events

    for coll, (want, kind, display) in EXPECTED.items():
        files = sorted(glob.glob(os.path.join(root, coll, "**", "*.evtx"), recursive=True))
        if not files:
            check(f"{coll}: collection present", False, root)
            continue
        print(f"=== {coll} ({len(files)} files) ===", flush=True)
        names, renames, bad = jm_inputs(files)
        hi = HostIdentity.build(names, renames, bad)
        anchor = sorted(want)[0]
        g = hi.group_of(anchor)
        check(f"{coll}: one machine's names form one group", set(g.members) == want,
              str(g.members))
        if kind:
            check(f"{coll}: joined by {kind}", any(l.kind == kind for l in g.links),
                  str([(l.kind, l.a, l.b) for l in g.links]))
        if display:
            check(f"{coll}: display name {display}", g.display_name == display, g.display_name)
        check(f"{coll}: no 6011 unreadable", bad == 0, str(bad))

        if coll == "win11-client-2023":
            lone = hi.group_of("WIN-OQ6R0RVA4NF")
            check(f"{coll}: WIN-OQ6R0RVA4NF stays its own group", lone.members == ["WIN-OQ6R0RVA4NF"],
                  str(lone.members))
            sug = hi.suggestions_for("WIN-OQ6R0RVA4NF")
            check(f"{coll}: ...with a same_file suggestion to the WinDev group",
                  any(l.kind == "same_file" and {l.a, l.b} & {"windeveval", "windev2310eval"}
                      for l in sug), str([(l.kind, l.a, l.b) for l in sug]))
        if coll == "win7-x86":
            check(f"{coll}: the chain bridge WIN-DQ6SQUGKQRD is not a member",
                  "WIN-DQ6SQUGKQRD" not in g.members)
            check(f"{coll}: three renames read", len(renames) == 3, str(len(renames)))
        if coll == "win2022-evtx":
            check(f"{coll}: no suggestions", hi.suggestions_for("WIN-TKC15D7KHUR") == [])

        if coll in PARITY:
            n_names, n_renames, n_bad = inputs_from_events(e for f in files for e in iter_events(f))
            check(f"{coll}: Normal and Juggernaut read the same names",
                  sorted(n_names) == sorted(names),
                  f"normal {len(n_names)}, jm {len(names)}; first diff "
                  f"{next((a, b) for a, b in zip(sorted(n_names), sorted(names)) if a != b) if sorted(n_names) != sorted(names) and len(n_names) == len(names) else '-'}")
            check(f"{coll}: ...and the same renames",
                  sorted(n_renames) == sorted(renames) and n_bad == bad,
                  f"normal {n_renames}, jm {renames}")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
