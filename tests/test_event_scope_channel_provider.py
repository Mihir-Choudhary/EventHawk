"""Session and power builders read an event ID only from its own channel and provider.

Gemini audit 8-06 (High): Logon Sessions took any 4624 (also one in the
Application log), HostPower took a Kernel-General 12 in any channel as a
boot, System Activity took a 4800 from a third-party provider writing to
Security, and inbound RDP took any event in a channel named like
TerminalServices whatever its provider.

Expected: those are not read; the genuine events still are; an event with
no channel or provider recorded is still read (a missing field is not
evidence against it).  Channel and provider pairs checked on the corpus.
Synthetic events.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import kernel_boot                      # noqa: E402

CHECKS = []
SA = "Microsoft-Windows-Security-Auditing"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(rid, secs, eid, provider, channel, data=None):
    e = T.ev("x.evtx", rid, "WS1", T.T0 + timedelta(seconds=secs), eid, provider, data or {})
    e["channel"] = channel
    return e


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import _LogonSessionDialog
    from evtx_tool.analysis.host_power import classify
    from evtx_tool.analysis import system_activity as sa
    from evtx_tool.analysis.inbound_rdp import is_inbound_event

    def sessions(evs):
        d = _LogonSessionDialog(events=evs, on_filter_fn=lambda *a: None)
        s = d._all_sessions
        d.close()
        return s

    lg = {"TargetLogonId": "0x31", "LogonType": "2", "TargetUserName": "u"}
    check("a 4624 in the Application log is no logon session",
          sessions([ev(1, 0, 4624, "SomeApp", "Application", lg)]) == [])
    check("a genuine Security 4624 still is", len(sessions([ev(1, 0, 4624, SA, "Security", lg)])) == 1)
    nochan = ev(1, 0, 4624, "", "", lg)
    check("a 4624 with no channel or provider recorded still is", len(sessions([nochan])) == 1)

    kg = kernel_boot("WS1", 1, 0, start=0)
    app_kg = dict(kg, channel="Application")
    check("a Kernel-General 12 outside the System log is no boot", classify(app_kg) is None)
    check("a System Kernel-General 12 still is", (classify(kg) or ("",))[0] == "boot")
    check("a 4608 from another provider is no boot",
          classify(ev(1, 0, 4608, "FakeProvider", "Security")) is None)
    check("Security 1100 from the Eventlog provider still is a shutdown",
          (classify(ev(1, 0, 1100, "Microsoft-Windows-Eventlog", "Security")) or ("",))[0] == "shutdown")

    third = ev(1, 0, 4800, "ThirdPartyAgent", "Security", {"TargetUserName": "u", "TargetLogonId": "0x5"})
    check("a 4800 from a third-party provider is not read", not sa.relevant(third))
    check("a genuine 4800 still is", sa.relevant(ev(1, 0, 4800, SA, "Security", {"TargetLogonId": "0x5"})))
    check("a Kernel-Power 42 outside the System log is not read",
          not sa.relevant(ev(1, 0, 42, "Microsoft-Windows-Kernel-Power", "Application")))
    check("Diagnostics-Performance 100 in its own channel still is",
          sa.relevant(ev(1, 0, 100, "Microsoft-Windows-Diagnostics-Performance",
                         "Microsoft-Windows-Diagnostics-Performance/Operational")))

    fields = lambda e: e.get("event_data") or {}                    # noqa: E731
    lsm = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"
    check("a TerminalServices-named channel with another provider is not RDP",
          not is_inbound_event(ev(1, 0, 21, "FakeProvider", lsm), fields))
    check("a genuine LocalSessionManager 21 still is",
          is_inbound_event(ev(1, 0, 21, "Microsoft-Windows-TerminalServices-LocalSessionManager", lsm), fields))
    check("a 4778 from another provider is not RDP",
          not is_inbound_event(ev(1, 0, 4778, "FakeProvider", "Security"), fields))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
