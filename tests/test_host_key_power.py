"""A restart applies to its host however the Computer field spells it.

Gemini audit 8-03 (High): restarts were matched to sessions by the raw or
lowercased Computer value, and blank hosts were dropped:
1. HostPower did not apply a restart of "SYNTH-HOST-01.corp.example" to a
   session of "SYNTH-HOST-01", nor one logged with a blank Computer to a
   session of a blank Computer (it skipped blank hosts);
2. Logon Sessions counted boots per raw Computer: a boot logged as
   "synth-host-01" did not split a LogonId of "SYNTH-HOST-01";
3. System Activity on a log with a blank Computer had no Power rows, though
   it had Lock rows;
4. WiFi (blank Computer) kept a duration across a restart.

Expected: one host key (short name, casefolded; blank is "(unknown)").  A
restart then voids or splits as for any host.  Synthetic events.
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402
from test_wifi_boot_barrier import kernel_boot, wlan                # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def at(secs):
    return T.iso(T.T0 + timedelta(seconds=secs))


def main() -> int:
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    from evtx_tool.analysis.host_power import HostPower

    hp = HostPower([kernel_boot("SYNTH-HOST-01.corp.example", 1, 100, start=99)])
    check("an FQDN restart applies to the short name", hp.assess("SYNTH-HOST-01", at(0), at(500)) is not None)
    hp = HostPower([kernel_boot("synth-host-01", 1, 100, start=99)])
    check("a lowercase restart applies to the uppercase name", hp.assess("SYNTH-HOST-01", at(0), at(500)) is not None)
    hp = HostPower([kernel_boot("", 1, 100, start=99)])
    check("a restart with a blank Computer applies to a blank-Computer session",
          hp.assess("", at(0), at(500)) is not None, str(hp.restarts.keys()))
    hp = HostPower([kernel_boot("OTHER-HOST", 1, 100, start=99)])
    check("another host's restart still does not apply", hp.assess("SYNTH-HOST-01", at(0), at(500)) is None)

    # Logon Sessions: 4624 on SYNTH-HOST-01, boot logged as synth-host-01, then a 4634 of the same LogonId.
    from evtx_tool.gui.main_window import _LogonSessionDialog
    evs = [T.ev("s.evtx", 1, "SYNTH-HOST-01", T.T0, 4624, data={"TargetLogonId": "0x77", "LogonType": "2",
                                                                "TargetUserName": "u"}),
           kernel_boot("synth-host-01", 2, 100, start=99),
           T.ev("s.evtx", 3, "SYNTH-HOST-01", T.T0 + timedelta(seconds=500), 4634, data={"TargetLogonId": "0x77"})]
    d = _LogonSessionDialog(events=evs, on_filter_fn=lambda *a: None)
    ss = d._all_sessions
    d.close()
    paired = [s for s in ss if s["logon_ev"] and s["logoff_ts"]]
    check("a boot with another case splits the LogonId (no logon paired across it)", not paired and len(ss) == 2,
          str([(s["user"], s["logoff_ts"]) for s in ss]))

    # System Activity, blank Computer: a lock and a restart.
    from evtx_tool.analysis import system_activity as sa
    lk = T.ev("s.evtx", 10, "", T.T0, 4800, data={"TargetUserName": "u", "TargetLogonId": "0x5"})
    ul = T.ev("s.evtx", 11, "", T.T0 + timedelta(seconds=30), 4801, data={"TargetUserName": "u", "TargetLogonId": "0x5"})
    out = sa.build([lk, ul, kernel_boot("", 12, 1000, start=999)])
    layers = sorted({r["layer"] for r in out["rows"]})
    check("System Activity on a blank-Computer log has Power rows too", "Power" in layers and "Lock" in layers,
          str(layers))

    # WiFi, blank Computer: connect, restart, disconnect.
    from evtx_tool.gui.main_window import _WifiHistoryDialog
    w = [wlan("", 1, 0, 8001, "Net"), kernel_boot("", 2, 100, start=99), wlan("", 3, 500, 8003, "Net")]
    ws = _WifiHistoryDialog._build_sessions(w)
    check("WiFi with a blank Computer has no duration across a restart",
          len(ws) == 1 and ws[0]["duration_secs"] < 0, str([(s["duration"], s["duration_secs"]) for s in ws]))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
