"""Normal mode's parse engine keeps Provider@EventSourceName, like the other parsers.

Codex release audit C4: core/engine.py has its own inline extractor (the one
the GUI and CLI actually run) and never stored EventSourceName, while
core/parser.py and Juggernaut do -- so on a real 46,748-record selection all
3,927 non-empty values were missing in Normal mode, and searching for a
classic source name found 0 events.  Synthetic record only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.core.engine import _extract_event_inline
    data = {"Event": {"System": {
        "Provider": {"#attributes": {"Name": "Microsoft-Windows-Winlogon", "EventSourceName": "Wlclntfy",
                                     "Guid": "{00000000-0000-0000-0000-000000000000}"}},
        "EventID": 7001, "Level": 4, "Channel": "System", "Computer": "C"}, "EventData": {}}}
    ev = _extract_event_inline(data, 1, "2024-01-01T00:00:00.000000Z", r"C:\s\System.evtx")
    check("EventSourceName is stored", ev.get("event_source_name") == "Wlclntfy", repr(ev.get("event_source_name")))
    check("the provider Name is unchanged", ev.get("provider") == "Microsoft-Windows-Winlogon")
    data["Event"]["System"]["Provider"]["#attributes"].pop("EventSourceName")
    ev = _extract_event_inline(data, 2, "2024-01-01T00:00:00.000000Z", r"C:\s\System.evtx")
    check("a provider without one gives an empty value", ev.get("event_source_name") == "",
          repr(ev.get("event_source_name")))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
