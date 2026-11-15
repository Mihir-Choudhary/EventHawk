"""The ATT&CK summary of an exported subset matches the parse-time summary.

Gemini audit 6-13 / 7-06 (High): "Current view" and "Specific files" exports
rebuild the ATT&CK summary with MainWindow._derive_attack_summary, which
lowercased tactic names ("execution") -- the HTML and PDF reports look tactics
up by their proper names ("Execution"), so they showed no tactic cards -- and
counted tags, not events, so one event with three tactics was "3 tagged".

Expected: on a real log, _derive_attack_summary(events) equals what
attack_mapping.enrich_and_summarize returned for the same events (the
parse-time path): same tactic names and counts, same total_tagged.
Real log read in place (needs EVTX_TEST_LOGS_ONLINE).
"""
import glob
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE")
    if not root or not os.path.isdir(root):
        print("SKIP: EVTX_TEST_LOGS_ONLINE not set")
        return 0
    from evtx_tool.core.engine import _worker_parse_file
    from evtx_tool.core.filters import empty_filter
    from evtx_tool.analysis.attack_mapping import enrich_and_summarize
    from evtx_tool.gui.main_window import MainWindow
    evs = []
    fs = [f for f in glob.glob(os.path.join(root, "**", "*.evtx"), recursive=True) if os.path.getsize(f) > 70_000]
    for f in sorted(fs, key=os.path.getsize):
        evs += _worker_parse_file({"filepath": f, "filter_config": empty_filter()})["events"]
        if len(evs) > 40_000:
            break
    # A Security log too: its events are the ones that carry real ATT&CK tags.
    sec = sorted(glob.glob(os.path.join(root, "**", "Security.evtx"), recursive=True), key=os.path.getsize)
    if sec:
        evs += _worker_parse_file({"filepath": sec[0], "filter_config": empty_filter()})["events"]
    ref = enrich_and_summarize(evs)
    got = MainWindow._derive_attack_summary(evs) or {}
    print(f"{len(evs)} events, {ref['total_tagged']} tagged, {len(ref['by_tactic'])} tactics")
    check("the sample has tagged events (not vacuous)", ref["total_tagged"] > 0)
    check("tactic names keep their case", sorted(got.get("by_tactic", {})) == sorted(ref["by_tactic"]),
          f"{sorted(got.get('by_tactic', {}))[:3]} vs {sorted(ref['by_tactic'])[:3]}")
    check("tactic counts match", got.get("by_tactic") == ref["by_tactic"])
    check("total_tagged counts events, not tags", got.get("total_tagged") == ref["total_tagged"],
          f"{got.get('total_tagged')} vs {ref['total_tagged']}")
    multi = [{"event_id": 1, "attack_tags": [
        {"tactic": "Execution", "tid": "T1059", "name": "a"},
        {"tactic": "Defense Evasion", "tid": "T1027", "name": "b"},
        {"tactic": "Initial Access", "tid": "T1566", "name": "c"}]}]
    m = MainWindow._derive_attack_summary(multi) or {}
    check("one event with three tactics is 1 tagged event", m.get("total_tagged") == 1, str(m.get("total_tagged")))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
