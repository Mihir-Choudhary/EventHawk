"""Apply Profiles must filter in Normal mode exactly as it does in Juggernaut.

A profile-built config speaks the parse-time dialect of core.filters:
event_ids / exclude_event_ids / task_categories lists, and None for every list
it does not set (empty_filter).  The Normal view proxy read only the Advanced
Filter dialog's dialect, so:

  * with no Advanced Filter active, Apply Profiles raised
    TypeError: 'NoneType' object is not iterable -- and the view kept showing
    every event (real corpus: 76,034 of 76,034 for all five profiles tried),
    silently under pythonw;
  * with one active, the profile's event IDs were ignored altogether;
  * text_search=None would have become a search for the word "None".

Real corpus after the fix: Logon/Logoff 2,391, PowerShell 1,509, RDP 2,384,
Privilege Escalation 2,130, Process Creation 126 -- identical in Normal, in
Juggernaut, and in an independent count through core.filters.passes_filter.
Here the same comparison runs on synthetic events, against passes_filter.
"""
import os
import random
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def events(n=4000, seed=3):
    rng = random.Random(seed)
    srcs = [("Microsoft-Windows-Security-Auditing", "Security"),
            ("Microsoft-Windows-PowerShell", "Microsoft-Windows-PowerShell/Operational"),
            ("Service Control Manager", "System"),
            ("Microsoft-Windows-TerminalServices-LocalSessionManager",
             "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")]
    eids = [4624, 4625, 4634, 4672, 4688, 4104, 4103, 7036, 21, 24, 1, 4800]
    out = []
    for i in range(n):
        prov, chan = rng.choice(srcs)
        out.append({"event_id": rng.choice(eids), "provider": prov, "channel": chan,
                    "computer": "WS01", "level": 4, "level_name": "Information",
                    "task": rng.choice([12544, 12545, 0, 13824]),
                    "timestamp": f"2026-02-11T13:{i // 60 % 60:02d}:{i % 60:02d}.000000Z",
                    "record_id": i + 1, "source_file": "x.evtx", "user_id": "",
                    "keywords": "0x8020000000000000",
                    "event_data": {"SubjectUserName": "bob", "TargetUserName": "alice"}})
    return out


def main() -> int:
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    from evtx_tool.core.filters import empty_filter, passes_filter
    from evtx_tool.profiles.manager import ProfileManager

    evs = events()
    model = EventTableModel(); model.set_events(evs)
    proxy = EventFilterProxyModel(); proxy.setSourceModel(model)
    pm = ProfileManager()

    print("=== profile alone (no Advanced Filter active) ===")
    for name in ("Logon/Logoff Activity", "PowerShell Execution", "RDP Activity",
                 "Privilege Escalation"):
        fc = pm.build_filter([name], base_filter=empty_filter())
        want = sum(1 for e in evs if passes_filter(e, fc))
        try:
            proxy.set_advanced_filter(fc)
            got = proxy.rowCount()
        except Exception as exc:                       # the pre-fix failure
            got = f"{type(exc).__name__}: {exc}"
        check(f"{name}: view shows exactly the profile's events",
              got == want and want < len(evs), f"view {got}, expected {want}")

    print("\n=== explicit lists in the parse-time dialect ===")
    for label, extra in (("exclude_event_ids", {"exclude_event_ids": [4624, 4688]}),
                         ("task_categories", {"task_categories": [12544]})):
        fc = empty_filter(); fc.update(extra)
        want = sum(1 for e in evs if passes_filter(e, fc))
        try:
            proxy.set_advanced_filter(fc)
            got = proxy.rowCount()
        except Exception as exc:
            got = f"{type(exc).__name__}: {exc}"
        check(f"{label} is honoured", got == want, f"view {got}, expected {want}")

    print("\n=== profile stacked on an Advanced Filter (dialog dialect) ===")
    dialog_cfg = {"event_id_expr": "", "sources": [], "users": ["bob"],
                  "computers": [], "text_search": "", "conditions": []}
    fc = pm.build_filter(["Logon/Logoff Activity"], base_filter=dict(dialog_cfg))
    want = sum(1 for e in evs if passes_filter(e, fc))
    proxy.set_advanced_filter(fc)
    check("the profile's event IDs apply on top of the dialog filter",
          proxy.rowCount() == want, f"view {proxy.rowCount()}, expected {want}")

    print("\n=== None never turns into a search for 'None' ===")
    fc = empty_filter()                                  # text_search=None
    try:
        proxy.set_advanced_filter(fc)
        got = proxy.rowCount()
    except Exception as exc:
        got = f"{type(exc).__name__}: {exc}"
    check("an all-None config filters nothing", got == len(evs), str(got))

    proxy.set_advanced_filter(None)
    check("clearing restores every event", proxy.rowCount() == len(evs))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
