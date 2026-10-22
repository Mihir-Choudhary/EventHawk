"""Remote Assistance sessions: same result, without scanning every event.

_RemoteAssistanceDialog._build_sessions received EVERY loaded event in Normal
mode and deduplicated, timestamp-parsed and sorted all of them before
discarding the ones no rule can use.  On a real 74,543-event load that was 5 s
(1.8 s with the GUI thread blocked) to find 60 sessions; Juggernaut already
narrows in SQL.  Events that _classify rejects on channel + event ID alone are
now dropped first: 0.48 s, GUI stall 0.17 s, identical table.

The real corpus has no Classic RA / Remote Help / Quick Assist / outbound RDP
events, so a synthetic set exercises every branch of _classify, accepted and
rejected IDs alike, with noise channels, host whitespace, both timestamp
shapes and copied records.  GOLDEN is the fingerprint of the sessions the
build BEFORE this change produced for it (identical on 6 seeds).
"""
import hashlib
import json
import os
import random
import sys
import time
from collections import Counter
from datetime import datetime, timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])

GOLDEN_COUNTS = {"Remote Help": 6, "RDP (Outbound)": 89, "Classic RA": 43,
                 "RDP Session": 67, "Quick Assist": 25}
GOLDEN_SHA = "929f398c8f114032ba58453d9a21a8e7b3afe57f66c6bb2744a8ee05c0ca98c5"

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def synth(seed=11, n=3000):
    rng = random.Random(seed)
    t0 = datetime(2026, 3, 1, 8, 0, 0)
    chans = {
        "Microsoft-Windows-RemoteAssistance/Operational": [1, 2, 3, 4, 7],
        "Microsoft-Windows-RemoteHelp/Operational": [1, 2, 5],
        "Microsoft-Windows-TerminalServices-RDPClient/Operational": [1024, 1025, 1026, 1027, 1029, 1102, 1103, 1105, 226],
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": [21, 22, 23, 24, 25, 39, 40, 41, 42],
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": [261, 1149, 20521],
        "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational": [131, 98],
        "Security": [4624, 4634, 4648, 4688, 4778, 4779, 4672, 4625],
        "System": [7036, 6005], "Application": [1000],
    }
    hosts = ["WS01", "WS02", " Srv-A "]
    evs = []
    for i in range(n):
        ch = rng.choice(list(chans)); eid = rng.choice(chans[ch])
        ts = t0 + timedelta(seconds=rng.randint(0, 6 * 3600), microseconds=rng.choice([0, 123456]))
        tss = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if rng.random() < .5 else ts.strftime("%Y-%m-%d %H:%M:%S.%f")
        ed = {}
        if eid in (4624, 4634):
            ed = {"LogonType": rng.choice(["10", "2", "3"]), "TargetLogonId": rng.choice(["0x1a", "0x2b", "0x3c"]),
                  "TargetUserName": "bob", "IpAddress": "10.0.0.5"}
        elif eid in (4778, 4779):
            ed = {"TargetLogonId": rng.choice(["0x1a", "0x2b"]), "AccountName": "bob", "ClientAddress": "10.0.0.9"}
        elif eid == 4648:
            ed = {"TargetInfo": rng.choice(["TERMSRV/dc01", "cifs/fs01", ""]), "TargetServerName": "dc01", "SubjectUserName": "bob"}
        elif eid == 4688:
            ed = {"NewProcessName": rng.choice([r"C:\Windows\System32\quickassist.exe", r"C:\Windows\notepad.exe"]),
                  "NewProcessId": hex(rng.randint(100, 9999)), "CommandLine": ""}
        elif "RemoteHelp" in ch:
            ed = {"SessionId": rng.choice(["", "s1", "s2"])}
        elif "RemoteAssistance" in ch:
            ed = {"LocalFQDNName": rng.choice(["", "ws01.corp"]), "UserName": rng.choice(["", "alice"])}
        elif "RDPClient" in ch:
            ed = {"Value": rng.choice(["dc01", "10.1.1.1", "0x3"]), "Name": "x"}
        elif "TerminalServices" in ch:
            ed = {"SessionID": rng.choice(["1", "2", ""]), "User": "CORP\\bob", "Address": "10.0.0.7"}
        evs.append({"event_id": eid, "channel": ch, "computer": rng.choice(hosts), "timestamp": tss,
                    "record_id": str(i + 1), "source_file": rng.choice(["a.evtx", "a - Copy.evtx"]),
                    "event_data": ed})
    # exact duplicates (same record from a copy)
    evs += [dict(e, source_file="b.evtx") for e in rng.sample(evs, 200)]
    rng.shuffle(evs)
    return evs


def fingerprint(sessions):
    norm = lambda o: sorted(map(str, o)) if isinstance(o, (set, frozenset)) else str(o)  # noqa: E731
    return hashlib.sha256(json.dumps(sessions, default=norm, sort_keys=True)
                          .encode("utf-8")).hexdigest()


def noise(n, seed=5):
    rng = random.Random(seed)
    t0 = datetime(2026, 3, 1, 8, 0, 0)
    chans = [("Security", [4625, 4672, 4689, 5379, 4799]), ("System", [7036, 7040]),
             ("Application", [1000, 16384]),
             ("Microsoft-Windows-PowerShell/Operational", [4104, 4103])]
    out = []
    for i in range(n):
        ch, ids = rng.choice(chans)
        out.append({"event_id": rng.choice(ids), "channel": ch, "computer": "WS01",
                    "timestamp": (t0 + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "record_id": str(10_000_000 + i), "source_file": "noise.evtx",
                    "event_data": {"SubjectUserName": "x", "LogonType": "10"}})
    return out


def main() -> int:
    import evtx_tool.gui.main_window as mw
    build = mw._RemoteAssistanceDialog._build_sessions

    print("=== 1. every _classify branch gives the pre-change result ===")
    s = build(synth(11))
    counts = dict(Counter(x.get("type") for x in s))
    check("session counts per type match the pre-change build", counts == GOLDEN_COUNTS,
          str(counts))
    check("the sessions themselves are identical (fingerprint)",
          fingerprint(s) == GOLDEN_SHA, fingerprint(s)[:16])

    print("\n=== 2. irrelevant events change nothing, and cost little ===")
    base = synth(11)
    t0 = time.monotonic()
    s2 = build(base + noise(100_000))
    el = time.monotonic() - t0
    check("100k events no rule can use leave the sessions unchanged",
          fingerprint(s2) == GOLDEN_SHA)
    print(f"  (info) 100k-event build took {el:.2f}s")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())