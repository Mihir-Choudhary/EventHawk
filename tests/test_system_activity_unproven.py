"""The System Activity report never counts unproven time, and never hides undated events (Codex PR19-1, PR19-4).

PR19-1: a period whose start and end are known but whose length is not proven
(its duration is Unavailable) was still added as on-time to the calendar, the
brush and the weekly heat map. The overview said Unavailable while the calendar
said "On 4 h".
PR19-4: a raw event without a usable timestamp is in the report's data but the
raw-events table filtered it out under every range, with no count or note.

Expected, in a real browser (headless Edge/Chrome): the day of the unproven
period counts no on-time, its tooltip says the length is unavailable, the heat
map shows no on-time for those hours; the raw-events table lists the undated
event with the full range, and a narrowed range says how many undated events it
leaves out. Skips (exit 0) when no browser is found. Synthetic data only.
"""
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import test_html_report_browser as B                                # noqa: E402
import test_system_activity_report as S                             # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def build(path):
    from evtx_tool.output import system_activity_report as rep
    res, events = S.sample()
    t0 = res["rows"][0]["start"]
    d2 = t0 + timedelta(days=3)                       # another weekday
    e_a = S.ev(11, d2, "Microsoft-Windows-Kernel-General", 12, {})
    e_b = S.ev(12, d2 + timedelta(hours=4), "Microsoft-Windows-Kernel-Power", 42, {})
    res["rows"].append({"host": "MSI", "layer": "Power", "state": "On", "start": d2, "end": d2 + timedelta(hours=4),
                        "duration": None, "started_by": "Kernel-General 12", "ended_by": "Kernel-Power 42",
                        "start_ev": e_a, "end_ev": e_b, "notes": "length not proven"})
    undated = S.ev(13, t0, "Microsoft-Windows-Kernel-Power", 105, {"AcOnline": True})
    undated["timestamp"] = ""
    events += [e_a, e_b, undated]
    open(path, "w", encoding="utf-8").write(rep.render_html(res, events, digits=0))
    return d2


def main() -> int:
    exe = next((c for c in B.CANDIDATES if c and os.path.exists(c)), None)
    if not exe:
        print("SKIP: no Edge/Chrome found\n\n0/0 passed")
        return 0
    work = tempfile.mkdtemp(prefix="saunp_")
    proc, port = None, 0
    try:
        page = os.path.join(work, "r.html")
        d2 = build(page)
        with socket.socket() as so:
            so.bind(("127.0.0.1", 0))
            port = so.getsockname()[1]
        proc = subprocess.Popen([exe, "--headless=new", f"--remote-debugging-port={port}",
                                 f"--user-data-dir={os.path.join(work, 'p')}", "--no-first-run",
                                 "--disable-extensions", "about:blank"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tab = None
        for _ in range(150):
            try:
                tab = next(t for t in json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2))
                           if t.get("type") == "page")
                break
            except Exception:
                time.sleep(0.2)
        check("browser started", tab is not None)
        if tab is None:
            return 1
        ws = B._WS(tab["webSocketDebuggerUrl"])
        ws.call("Runtime.enable")
        ws.call("Page.enable")
        ws.call("Page.addScriptToEvaluateOnNewDocument",
                source="window.__errs=[];addEventListener('error',e=>window.__errs.push(String(e.message)));")
        ws.call("Page.navigate", url=pathlib.Path(page).as_uri())
        t0 = time.time()
        while ws.js("document.readyState") != "complete" and time.time() - t0 < 60:
            time.sleep(0.2)
        time.sleep(0.5)
        import test_system_activity_report as S2
        data = S2.data_of(open(page, encoding="utf-8").read())
        n_all = sum(1 for e in data["events"] if e[7] < 0)
        n_undated = sum(1 for e in data["events"] if e[7] < 0 and e[0] is None)
        check("setup: one undated raw event in the report data", n_undated == 1, str(n_undated))
        day = int(d2.timestamp() * 1_000_000) // (86400 * 1_000_000)
        r = ws.js(f"""(() => {{
            const set = (id, v) => {{ const el = document.getElementById(id); el.value = v; el.dispatchEvent(new Event('change')); }};
            const f = document.getElementById('r-from'), t = document.getElementById('r-to');
            set('r-from', f.min); set('r-to', t.max);
            const full = document.getElementById('c-events').textContent, nEv = document.getElementById('n-events').textContent;
            const b = document.querySelector('#cal button[data-d="{day}"]');
            if (b) b.dispatchEvent(new MouseEvent('mouseover', {{bubbles: true, clientX: 5, clientY: 5}}));
            const tip = document.getElementById('tip').textContent, aria = b ? b.getAttribute('aria-label') : null;
            const wd = (new Date({day} * 86400000).getUTCDay() + 6) % 7;
            const cells = [...document.querySelectorAll('#heat i[data-h]')].map(i => i.getAttribute('data-h').split(',').map(Number))
                .filter(([w, hh]) => w === wd && hh >= 12 && hh < 16);
            const d0 = f.min.slice(0, 10);
            set('r-from', d0 + 'T00:00'); set('r-to', d0 + 'T23:59');
            const narrow = document.getElementById('c-events').textContent;
            return {{full, nEv, tip, aria, cells, narrow}};
        }})()""")
        check("the unproven period adds no on-time to its day", r["aria"] is not None and "on 4" not in r["aria"].lower(), str(r["aria"]))
        check("...and the day's tooltip says its length is unavailable", "unavailable" in r["tip"].lower(), r["tip"])
        check("...and claims no measured on-time for it", "On 0" not in r["tip"], r["tip"])
        check("the heat map shows no on-time for those hours", r["cells"] and all(pc <= 0 for _, _, pc in r["cells"]), str(r["cells"]))
        check("with the full range the raw-events table counts every event, the undated one too",
              r["full"].replace(",", "").startswith(str(n_all)) and r["nEv"].replace(",", "") == str(n_all),
              f"table {r['full']!r} summary {r['nEv']!r}, expected {n_all}")
        check("a narrowed range says how many undated events it leaves out", "without a date" in r["narrow"], r["narrow"])
        errs = ws.js("window.__errs || ['no error hook']")
        check("no script errors", not errs, str(errs)[:200])
    finally:
        B._stop_browser(proc, port)
        shutil.rmtree(work, ignore_errors=True)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
