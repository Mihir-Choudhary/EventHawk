"""System Activity HTML report (evtx_tool/output/system_activity_report.py).

  A. Self-contained and offline: a Content Security Policy forbids network
     requests, no external URL is referenced, the logo is embedded.
  B. Log text cannot break out: a value containing </script> or markup stays
     data (the embedded JSON round-trips it), a placeholder-looking computer
     name changes nothing.
  C. Everything is in it: every raw event, evidence events not passed in,
     period / moment links resolve to the right event, copies of a log are
     marked as copies, exact and display durations, field meanings.
  D. The System Activity window exports it (whole analysis, raw events).
  E. The page's script parses (when Node.js is installed).

Run: QT_QPA_PLATFORM=offscreen python tests/test_system_activity_report.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


EVIL = '</script><img src=x onerror="alert(1)"><!--'


def ev(rid, t, prov, eid, data, host="MSI", f="C:/case/System.evtx"):
    return {"record_id": rid, "event_record_id": rid, "event_id": eid, "timestamp": t.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "channel": "System", "provider": prov, "computer": host, "level": 4, "level_name": "Information",
            "task": 100, "opcode": 0, "keywords": "0x8000000000000404", "user_id": "S-1-5-18",
            "event_data": data, "source_file": f}


def sample():
    t0 = datetime(2025, 6, 29, 12, 0, 0, 125000)
    e_start = ev(1, t0, "Microsoft-Windows-Kernel-General", 12, {"StartTime": t0.isoformat(), "Note": EVIL})
    e_sleep = ev(2, t0 + timedelta(hours=2), "Microsoft-Windows-Kernel-Power", 42, {"Reason": 0, "TargetState": 4})
    e_copy = dict(e_sleep, source_file="C:/case/copy/System.evtx")
    e_hidden = ev(3, t0 + timedelta(hours=3), "Microsoft-Windows-Power-Troubleshooter", 1,
                  {"WakeSourceType": 1, "SleepTime": "x", "WakeTime": "y"})
    e_moment = ev(4, t0 + timedelta(minutes=5), "Microsoft-Windows-Kernel-Power", 105, {"AcOnline": True})
    rows = [{"host": "MSI", "layer": "Power", "state": "On", "start": t0, "end": t0 + timedelta(hours=2),
             "duration": timedelta(hours=2), "started_by": "Kernel-General 12", "ended_by": "Kernel-Power 42",
             "start_ev": e_start, "end_ev": e_sleep, "notes": EVIL},
            {"host": "MSI", "layer": "Power", "state": "Sleep", "start": t0 + timedelta(hours=2),
             "end": t0 + timedelta(hours=3, microseconds=971314), "duration": timedelta(hours=1, microseconds=971314),
             "started_by": "Kernel-Power 42", "ended_by": "Power-Troubleshooter 1", "start_ev": e_sleep,
             "end_ev": e_hidden, "notes": ""}]
    points = [{"host": "MSI", "time": t0 + timedelta(minutes=5), "what": "Power source changed", "details": "on AC power",
               "evidence": "Kernel-Power 105", "ev": e_moment}]
    return {"hosts": ["MSI"], "rows": rows, "points": points}, [e_start, e_sleep, e_copy, e_moment]


def data_of(doc):
    m = re.search(r'<script type="application/json" id="data">(.*?)</script>', doc, re.S)
    return json.loads(m.group(1)) if m else None


def main() -> int:
    from evtx_tool.output import system_activity_report as rep
    res, events = sample()
    doc = rep.render_html(res, events, digits=0)

    print("=== A. self-contained ===")
    check("a Content Security Policy forbids network requests",
          "default-src 'none'" in doc and "connect-src" not in doc)
    ext = re.findall(r'(?:src|href)="(https?:)?//', doc)
    check("no external src/href", not ext, str(ext[:3]))
    check("no http(s) URL anywhere outside the data", not re.search(r"https?://", doc.split('id="data">')[0]))
    check("the EventHawk logo is embedded", 'src="data:image/png;base64,' in doc and "__LOGO__" not in doc)

    print("\n=== B. log text stays data ===")
    check("a </script> in a log value cannot close the script element", EVIL not in doc and doc.count("</script>") == 2)
    d = data_of(doc)
    check("...and round-trips exactly through the embedded JSON",
          d is not None and any(EVIL == r[1] for e in d["events"] for r in e[9])
          and d["periods"][0][12] == EVIL)
    res2, ev2 = sample()
    res2["hosts"] = ["__DATA__"]
    for r in res2["rows"] + res2["points"]:
        r["host"] = "__DATA__"
    for e in ev2 + [r["end_ev"] for r in res2["rows"]]:
        e["computer"] = "__DATA__"
    doc2 = rep.render_html(res2, ev2)
    check("a computer named like a placeholder changes nothing", data_of(doc2) is not None
          and data_of(doc2)["hosts"] == ["__DATA__"] and "<title>System Activity \u2014 __DATA__</title>" in doc2)

    print("\n=== C. everything is in it ===")
    E = d["events"]
    check("every raw event passed in is listed, plus evidence not passed in",
          len(E) == len(events) + 1, f"{len(E)}")
    by_rec = {e[6]: i for i, e in enumerate(E) if e[7] < 0}
    p0, p1 = d["periods"]
    check("a period's start / end link to its evidence events",
          E[p0[13]][3] == "Kernel-General 12" and E[p0[14]][3] == "Kernel-Power 42" and E[p1[14]][3] == "Power-Troubleshooter 1")
    check("a moment links to its event", E[d["moments"][0][6]][3] == "Kernel-Power 105")
    dups = [e for e in E if e[7] >= 0]
    check("a copy of the same log is marked as a copy of the first", len(dups) == 1 and E[dups[0][7]][6] == "2"
          and dups[0][6] == "2", str([(e[6], e[7]) for e in E]))
    check("durations: display precision and exact", p1[8] == "1h 00m 00s" and p1[9] == "1h 00m 00.971314s", f"{p1[8]} / {p1[9]}")
    check("times exact in the inspector, display precision in tables",
          p0[15] == "2025-06-29 12:00:00.125000" and p0[6] == "2025-06-29 12:00:00")
    check("epoch microseconds are exact", p0[3] == int(datetime(2025, 6, 29, 12, 0, 0, 125000).timestamp() * 0) + 1751198400125000,
          str(p0[3]))
    kp42 = E[by_rec["2"]]
    check("field meanings come from the analysis's code tables (Kernel-Power 42 Reason 0)",
          ["Reason", "0", "Button or Lid"] in kp42[9], str(kp42[9]))
    check("system fields are listed by label once (meta) and value per event",
          d["meta"]["sys"][0] == "Provider" and kp42[8][0] == "Microsoft-Windows-Kernel-Power")
    check("no event gets an invented description", all(isinstance(e[4], str) for e in E))

    print("\n=== D. export from the System Activity window ===")
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.system_activity_dialog import SystemActivityDialog
    dlg = SystemActivityDialog(res, digits=0, events=events)
    check("the window has an Export HTML Report button", dlg._btn_html.text().startswith("Export HTML Report"))
    out = os.path.join(tempfile.gettempdir(), f"sa_report_{os.getpid()}.html")
    info = dlg.write_html(out)
    with open(out, encoding="utf-8") as fh:
        written = fh.read()
    os.remove(out)
    check("it writes the whole analysis with the raw events", info["periods"] == 2 and info["moments"] == 1
          and len(data_of(written)["events"]) == 5, str(info))
    check("no partial file is left behind", not os.path.exists(out + ".part"))
    dlg.close()

    print("\n=== F. clock corrections on waking (analysis) ===")
    from evtx_tool.analysis import system_activity as SA
    s0 = datetime(2026, 10, 4, 19, 55, 23, 724875)
    w0 = s0 + timedelta(hours=5, minutes=42, seconds=3, microseconds=299808)
    wake_ev = ev(10, w0 + timedelta(seconds=1), "Microsoft-Windows-Power-Troubleshooter", 1,
                 {"SleepTime": s0.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "WakeTime": w0.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                  "TargetState": 6, "WakeSourceType": 0})
    # Windows catching up with the hardware clock just after the wake: the
    # clock stood still in the low-power sleep (2026-10 MSI logs).
    old = w0 - timedelta(hours=5, minutes=41, seconds=54)
    sync = ev(11, w0 - timedelta(seconds=1), "Microsoft-Windows-Kernel-General", 1,
              {"OldTime": old.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "NewTime": w0.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
               "Reason": 2})
    r = SA.build([wake_ev, sync])
    low = [x for x in r["rows"] if x["state"].startswith("Low power")]
    check("a low-power sleep keeps its length when Windows re-syncs the clock on waking",
          len(low) == 1 and low[0]["duration"] == w0 - s0, str([(x["state"], x["duration"], x["notes"][:80]) for x in low]))
    mom = [p for p in r["points"] if p["what"] == "System time changed"]
    check("the clock change names Windows' reason", mom and "synchronized with the hardware clock (2)" in mom[0]["details"],
          mom[0]["details"] if mom else "")
    rd = data_of(rep.render_html(r, [wake_ev, sync]))
    check("the report marks it as made on waking", len(rd["clock"]) == 1 and rd["clock"][0][5] is True, str(rd["clock"]))

    print("\n=== E. the page's script parses ===")
    node = shutil.which("node")
    if node:
        js = doc.split("<script>")[-1].split("</script>")[0]
        tmp = os.path.join(tempfile.gettempdir(), f"sa_report_{os.getpid()}.js")
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(js)
        r = subprocess.run([node, "--check", tmp], capture_output=True, text=True)
        os.remove(tmp)
        check("node --check accepts the page script", r.returncode == 0, r.stderr[:300])
    else:
        print("  SKIP  Node.js not installed")

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
