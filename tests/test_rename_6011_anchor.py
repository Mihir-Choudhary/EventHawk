"""A host rename (EID 6011) is used only from the System log and for the computer that logged it.

Gemini audit 8-15 (Medium): host identity took any EventLog 6011, also
one in the Application log, and a rename naming two other computers
(OLD -> NEW written by a third-party tool on SYNTH-SRV-ALPHA) was used to
merge OLD and NEW automatically.

Expected (both modes): such a 6011 is not used for grouping and is counted
(the dialog reports it); a genuine System 6011 of the logging host still
links its old and new names.  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def r6011(rid, comp, old, new, channel="System"):
    e = T.ev(r"C:\c\System.evtx", rid, comp, T.T0, 6011, "EventLog", {"Data": {"#text": [old, new]}})
    e["channel"] = channel
    return e


def dataset():
    return [r6011(1, "SYNTH-NEW", "SYNTH-OLD", "SYNTH-NEW"),                    # genuine
            r6011(2, "SYNTH-PROD-NEW", "SYNTH-PROD-OLD", "SYNTH-PROD-NEW", "Application"),
            r6011(3, "SYNTH-SRV-ALPHA", "SYNTH-A", "SYNTH-B"),                  # another computer's names
            T.ev(r"C:\c\Security.evtx", 4, "SYNTH-PROD-OLD", T.T0, 4624),
            T.ev(r"C:\c\Security.evtx", 5, "SYNTH-A", T.T0, 4624),
            T.ev(r"C:\c\Security.evtx", 6, "SYNTH-B", T.T0, 4624),
            T.ev(r"C:\c\Security.evtx", 7, "SYNTH-OLD", T.T0, 4624)]


def judge(tag, names, renames, bad):
    from evtx_tool.core.host_identity import HostIdentity
    pairs = sorted((r.old.casefold(), r.new.casefold()) for r in renames)
    check(f"{tag}: only the genuine System rename of the logging host is used",
          pairs == [("synth-old", "synth-new")], str(pairs))
    check(f"{tag}: the other two are counted as not used", bad == 2, str(bad))
    hi = HostIdentity.build(names, renames, unreadable_renames=bad)
    g = sorted(n.casefold() for n in hi.group_of("SYNTH-A").members)
    check(f"{tag}: SYNTH-A and SYNTH-B are not merged", "synth-a" in g and "synth-b" not in g, str(g))


def main() -> int:
    from evtx_tool.core.host_identity import inputs_from_events
    judge("Normal", *inputs_from_events(dataset()))

    import evtx_tool.gui.main_window as mw
    from evtx_tool.core.heavyweight.host_inputs import inputs_from_jm
    w = mw.MainWindow()
    m = T.Mode(mw, True)
    try:
        m.load(w, dataset())
        judge("JM", *inputs_from_jm(w._hw_model._display_table, w._hw_db_path))
    finally:
        T.teardown(w, True, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
