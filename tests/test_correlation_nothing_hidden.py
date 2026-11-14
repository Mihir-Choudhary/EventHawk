"""Correlation never hides a chain or an event of a chain.

User (2026-11-06): "dont hide anything, fix it".  Found by Claude's old-vs-new
comparison: the Sysmon ProcessGuid rule stopped at 50 chains, then correlate()
merged every chain with the same rule + hosts + start minute -- on the public
samples 39 Sysmon chains existed and 23 were shown.  Rules also attached only
the first 1-10 matching events to a chain (e.g. password spray: 10 of 25
failures; log clearing: the last 5 prior events), and the process-tree walk
stopped at depth 5 / 20 events.

Expected: every chain a rule finds is listed; chains are merged only when they
hold exactly the same events; every matching event is in its chain, and
event_count says how many.  Synthetic events.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
T0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
_rid = [0]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(eid, secs, comp="WS1", channel="Security", **data):
    _rid[0] += 1
    return {"event_id": eid, "timestamp": (T0 + timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "computer": comp, "channel": channel, "provider": "P", "record_id": _rid[0],
            "event_record_id": _rid[0], "source_file": rf"C:\c\{comp}-{channel.split('/')[0]}.evtx",
            "event_data": data}


def sysmon_tree(comp, secs, depth, width, tag):
    """winword -> cmd (suspicious) and a deep/wide subtree of distinct GUIDs."""
    out = [ev(1, secs, comp, "Microsoft-Windows-Sysmon/Operational", ProcessGuid=f"{{r-{tag}}}",
              ParentProcessGuid="{p}", Image=r"C:\Office\WINWORD.EXE")]
    parent = f"{{r-{tag}}}"
    for d in range(depth):
        g = f"{{d{d}-{tag}}}"
        out.append(ev(1, secs + 1 + d, comp, "Microsoft-Windows-Sysmon/Operational", ProcessGuid=g,
                      ParentProcessGuid=parent, Image=r"C:\Windows\System32\cmd.exe"))
        parent = g
    for w in range(width):
        out.append(ev(1, secs + 1, comp, "Microsoft-Windows-Sysmon/Operational", ProcessGuid=f"{{w{w}-{tag}}}",
                      ParentProcessGuid=f"{{r-{tag}}}", Image=r"C:\Windows\System32\cmd.exe"))
    return out


def by_rule(chains, prefix):
    return [c for c in chains if str(c.get("rule_name", "")).startswith(prefix)]


def main() -> int:
    from evtx_tool.analysis.correlator import correlate

    # 60 suspicious process trees on 60 hosts (old cap: 50 chains).
    evs = []
    for k in range(60):
        evs += sysmon_tree(f"H{k:02d}", k * 600, 1, 0, f"a{k}")
    got = by_rule(correlate(evs), "Sysmon ProcessGuid")
    check("60 suspicious process trees: 60 chains", len(got) == 60, str(len(got)))

    # Two different trees on one host starting in the same minute (old: merged into one).
    evs = sysmon_tree("WS1", 0, 1, 0, "x") + sysmon_tree("WS1", 20, 1, 0, "y")
    got = by_rule(correlate(evs), "Sysmon ProcessGuid")
    check("two different trees, same host, same minute: 2 chains", len(got) == 2, str(len(got)))

    # One tree 8 deep and 30 wide (old: depth 5, 20 events).
    evs = sysmon_tree("WS1", 0, 8, 30, "z")
    got = by_rule(correlate(evs), "Sysmon ProcessGuid")
    check("a deep, wide tree keeps every descendant (1 + 8 + 30 events)",
          len(got) == 1 and got[0]["event_count"] == 39 and len(got[0]["events"]) == 39,
          str([c["event_count"] for c in got]))

    # Password spray: 25 failures over 25 users in 60 s (old: 10 events).
    evs = [ev(4625, i, LogonType="3", TargetUserName=f"u{i}") for i in range(25)]
    got = by_rule(correlate(evs), "Password Spray")
    check("password spray: all 25 failures in the chain", len(got) == 1 and got[0]["event_count"] == 25,
          str([c["event_count"] for c in got]))

    # Brute force with two successes in the 2 minutes (old: the first only).
    evs = [ev(4625, i, TargetUserName="bob", SubStatus="0xc000006a") for i in range(6)]
    evs += [ev(4624, 30, TargetUserName="bob", LogonType="3"), ev(4624, 60, TargetUserName="bob", LogonType="3")]
    got = by_rule(correlate(evs), "Brute Force")
    check("brute force: 6 failures and both successes", len(got) == 1 and got[0]["event_count"] == 8,
          str([c["event_count"] for c in got]))

    # Log cleared after 8 Security events (old: the last 5).
    evs = [ev(4688, i, NewProcessName=r"C:\x.exe") for i in range(8)] + [ev(1102, 100)]
    got = by_rule(correlate(evs), "Log Clearing")
    check("log clearing: all 8 prior events and the clearing", len(got) == 1 and got[0]["event_count"] == 9,
          str([c["event_count"] for c in got]))

    # Logon then 4 scheduled tasks (old: 2).
    evs = [ev(4624, 0, TargetUserName="bob", LogonType="2")] + [ev(4698, 10 + i, TaskName=f"t{i}") for i in range(4)]
    got = by_rule(correlate(evs), "Logon -> Scheduled Task")
    check("scheduled tasks: all 4 in the chain", len(got) == 1 and got[0]["event_count"] == 5,
          str([c["event_count"] for c in got]))

    # Network logon then 4 service installs, one suspicious (old: the suspicious one only, at most 3).
    evs = [ev(4624, 0, TargetUserName="bob", LogonType="3", IpAddress="10.0.0.9")]
    evs += [ev(7045, 10, "WS1", "System", ServiceName="evil", ImagePath=r"C:\Users\Public\evil.exe")]
    evs += [ev(7045, 11 + i, "WS1", "System", ServiceName=f"ok{i}", ImagePath=r"C:\Windows\System32\ok.exe")
            for i in range(3)]
    got = by_rule(correlate(evs), "Network Logon -> Service Install")
    check("service installs: all 4 in the chain, every name in the description",
          len(got) == 1 and got[0]["event_count"] == 5
          and all(n in got[0]["description"] for n in ("evil", "ok0", "ok1", "ok2")),
          str([(c["event_count"], c["description"][:160]) for c in got]))

    # Output is the same every time (host/user lists sorted).
    evs = [ev(4625, i, LogonType="3", TargetUserName=f"u{i}") for i in range(25)]
    a = correlate(list(evs))
    check("chain host and user lists are sorted", all(c["users"] == sorted(c["users"])
                                                      and c["computers"] == sorted(c["computers"]) for c in a))

    # Shown everywhere: the HTML report listed 50 chains, the GUI tree 10 events per chain.
    import tempfile
    from evtx_tool.output.exporters import export
    evs = []
    for k in range(60):
        evs += sysmon_tree(f"H{k:02d}", k * 600, 1, 0, f"h{k}")
    chains = correlate(evs)
    path = os.path.join(tempfile.mkdtemp(prefix="chains_"), "r.html")
    export(evs, path, None, chains=chains)
    html = open(path, encoding="utf-8").read()
    check("HTML report lists every chain", html.count("class='chain sev-") == len(chains) == 60,
          f"{html.count(chr(39).join(['class=', 'chain sev-']))} of {len(chains)}")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    w._chains = correlate(sysmon_tree("WS1", 0, 8, 30, "g"))
    w._refresh_chains_tab()
    top = w._tree_chains.topLevelItem(0)
    if top is not None:
        w._tree_chains.expandItem(top)          # event rows are built on expand
    # Each event row: "Event <id>  ·  record <n>" under Rule (column 1).
    shown = sum(1 for i in range(top.childCount()) if top.child(i).text(1).startswith("Event ")) if top else 0
    check("GUI chain tree shows every event of the chain (39)", shown == 39, str(shown))
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
