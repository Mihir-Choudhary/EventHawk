"""Logon sessions must not bridge a recorded Windows boot boundary.

Synthetic evidence only.  Security 4608 (or Kernel-General 12) ends the
previous boot epoch: a 4634 or a linked LUID from the next epoch cannot prove
the first session's end or sibling relationship.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evtx_tool.gui.main_window import _LogonSessionDialog as Dialog  # noqa: E402


def ev(eid, second, data=None, channel="Security", provider=""):
    return {"event_id": eid, "channel": channel, "computer": "SYNTH-HOST",
            "timestamp": f"2024-01-01T00:00:{second:02d}.000000Z",
            "record_id": str(second + eid), "source_file": "synthetic.evtx",
            "event_data": data or {}, "provider": provider}


def build(events):
    return Dialog._build_sessions(Dialog.__new__(Dialog), events)


def main():
    checks = []
    def check(name, value):
        checks.append(bool(value)); print(f"  {'PASS' if value else 'FAIL'}  {name}")

    rows = build([
        ev(4624, 0, {"TargetLogonId": "0xA", "TargetUserName": "SYNTH", "LogonType": "2"}),
        ev(4608, 10),
        ev(4634, 20, {"TargetLogonId": "0xA"}),
    ])
    first = next(r for r in rows if r["lid"] == "0xA")
    check("4634 after Security 4608 cannot close the pre-boot logon",
          first["duration"].startswith("Unavailable"))

    rows = build([
        ev(4624, 0, {"TargetLogonId": "0xA", "TargetLinkedLogonId": "0xB", "TargetUserName": "SYNTH", "LogonType": "2"}),
        ev(12, 10, channel="System", data={}, provider="Microsoft-Windows-Kernel-General"),
        ev(4624, 20, {"TargetLogonId": "0xB", "TargetLinkedLogonId": "0xA", "TargetUserName": "SYNTH", "LogonType": "2"}),
    ])
    check("linked LUIDs on opposite sides of Kernel-General 12 are not linked",
          all(not r["linked_lid"] for r in rows))

    print(f"\n{sum(checks)}/{len(checks)} checks passed")
    return 0 if all(checks) else 1


if __name__ == "__main__":
    sys.exit(main())
