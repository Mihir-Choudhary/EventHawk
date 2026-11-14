"""Remote Assistance window: only a session from a remote address reads as RDP.

Found working a "was this machine accessed remotely?" case on real logs: the
window listed all 362 Terminal Services sessions as "RDP Session" in the
accent colour -- remote access at a glance -- although 121 had source Address
'LOCAL' (console logons at the machine) and 241 came from events that name no
source at all (logoff, disconnect); none had a remote address.  The
reconstruction is unchanged; the display now says what each record shows:

  * from a remote address  -> "RDP Session" (accent colour);
  * Address 'LOCAL'        -> "Console (local)", the LOCAL_CONSOLE help on hover;
  * no source address      -> "Session (no source)": on its own it cannot show
    remote access;
  * the summary splits the RDP records into those three counts;
  * the Type filter still works on the reconstructed type.

Synthetic events.
Run: QT_QPA_PLATFORM=offscreen python tests/test_ra_local_console_display.py
"""
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication  # noqa: E402
import evtx_tool.gui.main_window as mw     # noqa: E402

APP = QApplication.instance() or QApplication([])
CHECKS = []
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)
LSM = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, sec, sid, address):
    data = {"SessionID": sid, "User": r"HOST\alice"}
    if address is not None:
        data["Address"] = address
    return dict(event_id=eid, timestamp=(BASE + timedelta(seconds=sec)).isoformat().replace("+00:00", "Z"),
                channel=LSM, provider=LSM.split("/")[0], computer="HOST", source_file="lsm.evtx",
                record_id=sec * 10 + eid, event_data=data)


def main() -> int:
    events = [ev(21, 0, "2", "LOCAL"), ev(23, 600, "2", "LOCAL"),             # console logon/logoff
              ev(21, 1000, "3", "10.0.0.5"), ev(23, 1600, "3", "10.0.0.5"),   # remote
              ev(23, 2000, "4", None)]                                        # logoff only, no source
    dlg = mw._RemoteAssistanceDialog(events=events, on_filter_fn=lambda *a, **k: None, parent=None)
    APP.processEvents()
    tbl = dlg._tbl
    types = {tbl.item(r, 0).text(): tbl.item(r, 0) for r in range(tbl.rowCount())}
    check("three sessions reconstructed", tbl.rowCount() == 3, str(tbl.rowCount()))
    local = types.get("Console (local)")
    check("the console session's type reads 'Console (local)'", local is not None, str(list(types)))
    check("...with the reason on hover", local is not None and "NOT a remote connection" in local.toolTip())
    remote = types.get("RDP Session")
    check("the session from 10.0.0.5 keeps 'RDP Session'",
          remote is not None and tbl.item(remote.row(), 7).text() == "10.0.0.5", str(list(types)))
    unknown = types.get("Session (no source)")
    check("a session whose events name no source reads 'Session (no source)'", unknown is not None)
    check("...and says it cannot show remote access on its own",
          unknown is not None and "cannot show remote access" in unknown.toolTip())
    summary = dlg._lbl_summary.text()
    check("the summary splits the RDP records by origin",
          "<b>1</b> from a remote address" in summary and "<b>1</b> local console" in summary
          and "<b>1</b> with no source address" in summary, summary[-240:])
    dlg._cmb_type.setCurrentIndex(dlg._cmb_type.findText("RDP Session"))
    dlg._apply_display_filters()
    check("the Type filter still works on the reconstructed type (all three)",
          tbl.rowCount() == 3, str(tbl.rowCount()))
    dlg.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
