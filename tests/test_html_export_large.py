"""The HTML report must open fast and respond while it opens, at any size.

Measured in Edge on a real 41,648-event export (139 MB) from 022c8d4:

  * every event's detail panel was written into the page up front, hidden --
    3.2 million elements -- so the page took 45 s to load;
  * the page's script was the last thing in the file: for those 45 s the
    rows were on screen but the expand button and every filter did nothing
    (toggleDetail / applyFilters were not defined yet);
  * a field search (eid:4624, level:error) looked every matching row up with
    document.querySelector, a scan of the whole page per row: 31 s on 10,655
    events, minutes on 41,648;
  * "PS: Has Analysis" filtered on data-has-ps, which no row had: 0 results
    whatever the data (5,959 PowerShell events in that export).

This test checks the page structure that fixes those (no browser needed);
the timings are checked in a real browser separately.

Run: QT_QPA_PLATFORM=offscreen python tests/test_html_export_large.py
"""
import json, os, re, shutil, sys, tempfile
from html.parser import HTMLParser

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ev(i, eid, channel, provider="P", data=None, tags=None):
    return {"event_id": eid, "timestamp": f"2026-01-01T00:{i // 60 % 60:02d}:{i % 60:02d}Z", "channel": channel,
            "provider": provider, "computer": "HOST-01", "level": 4, "level_name": "Information",
            "source_file": rf"C:\case\{channel}.evtx", "event_record_id": i + 1, "record_id": i + 1,
            "event_data": data or {"N": str(i)}, "attack_tags": tags or []}


class _Scan(HTMLParser):
    def __init__(self):
        super().__init__(); self.tags = 0; self.on = []; self.rows = []; self.in_head = True
        self.script_before_rows = False; self.detail_rows = 0
    def handle_starttag(self, tag, attrs):
        self.tags += 1
        a = dict(attrs)
        self.on += [(tag, k) for k in a if k.startswith("on") and tag not in ("button", "th", "select", "input", "tr")]
        if tag == "tr" and "event-row" in (a.get("class") or ""):
            self.rows.append(a)
        if tag == "tr" and "detail-row" in (a.get("class") or ""):
            self.detail_rows += 1


def detail_entries(html, labels):
    """The detail panels' data as the browser shows it: [description,
    [[label, value]...] (empty values left out), [[name, value]...] or None,
    ATT&CK line], decoded from the page's _DDp chunks and string table."""
    st, out = [], []
    for c in re.findall(r"<script>_DDp\((\[.*?\])\);</script>", html, flags=re.S):
        new, ents = json.loads(c)
        st += new
        s_ = lambda x: st[x] if isinstance(x, int) else x
        for d in ents:
            out.append([s_(d[0]), [[lab, s_(v)] for lab, v in zip(labels, d[1]) if s_(v)],
                        None if d[2] is None else [[s_(k), s_(v)] for k, v in d[2]], s_(d[3])])
    return out


def main() -> int:
    import evtx_tool.output.exporters as ex
    res = []

    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))

    hostile = "</script><img src=x onerror=alert(1)>"
    events = []
    for i in range(3000):
        k = i % 6
        if k == 0:
            events.append(ev(i, 800, "Windows PowerShell", "PowerShell", {"Data": {"#text": [f"Get-Item {i}\n", "\tHostApplication=powershell.exe\r\n"]}}))
        elif k == 1:
            events.append(ev(i, 4104, "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell",
                             {"ScriptBlockText": f"Write-Host {i}"}, [{"tid": "T1059.001", "name": "PowerShell", "tactic": "Execution"}]))
        elif k == 2:
            events.append(ev(i, 4624, "Security", "Microsoft-Windows-Security-Auditing", {"TargetUserName": f"user{i}"}))
        elif k == 3:
            events.append(ev(i, 800, "Application", "SomeApp"))          # 800, not PowerShell
        elif k == 4:
            events.append(ev(i, 1, "Test", "T", {"Evil": hostile}))
        else:
            events.append(ev(i, 4688, "Security", "Microsoft-Windows-Security-Auditing", {"CommandLine": f"cmd /c {i}"}))
    work = tempfile.mkdtemp(prefix="htmlbig_")
    try:
        p = os.path.join(work, "r.html")
        ex.export_html(events, p)
        html = open(p, encoding="utf-8").read()
        first_row = html.find("<tr class='event-row")
        head_end = html.find("</head>")

        # ── the script works while the page is still loading ────────────────
        for fn in ("toggleDetail", "applyFilters", "toggleFilter", "sortTable"):
            pos = html.find(f"function {fn}(")
            check(f"{fn} is defined in <head>, before the first row", 0 <= pos < head_end < first_row, f"at {pos}, head ends {head_end}")
        check("the search box is wired without needing it to exist yet",
              "getElementById('searchInput').addEventListener" not in html)
        check("a 'still loading' notice is shown, and removed when loaded",
              "id='ehLoading'" in html and "DOMContentLoaded" in html)

        # ── no hidden detail panel per event in the page ───────────────────
        s = _Scan(); s.feed(html)
        check("all events are rows", len(s.rows) == len(events), len(s.rows))
        check("no detail rows written up front (built when ▶ is clicked)", s.detail_rows == 0, s.detail_rows)
        per_event = s.tags / len(events)
        check("page elements per event is small (was ~77)", per_event < 20, f"{per_event:.1f}")
        chunks = re.findall(r"<script>_DDp\((\[.*?\])\);</script>", html, flags=re.S)
        dd = detail_entries(html, ex._DETAIL_CORE_LABELS)
        check("detail data for every event, in order, next to its rows (every 100)",
              len(dd) == len(events) and len(chunks) == 30, f"{len(dd)} entries in {len(chunks)} chunks")
        between = html.split("<script>_DDp(")
        check("…each chunk follows its own 100 rows", all(seg.count("<tr class='event-row") == 100 for seg in between[1:-1])
              and between[0].count("<tr class='event-row") == 100, [seg.count("<tr class='event-row") for seg in between[:4]])
        repeated = html.count("Microsoft-Windows-Security-Auditing")
        check("values repeated across events are written once in the detail data", repeated <= 2, repeated)
        if len(dd) == len(events):
            desc, core, data, atk = dd[0]
            check("detail data: event properties", ["Event ID", "800"] in core and ["Channel", "Windows PowerShell"] in core, core[:3])
            check("detail data: event data as readable text",
                  data == [["Data", "Get-Item 0\n\n\tHostApplication=powershell.exe\r\n"]], data)
            check("detail data: ATT&CK line", "T1059.001 PowerShell [Execution]" in dd[1][3], dd[1][3])
            check("detail data: hostile value kept as text", any(hostile in v for _k, v in dd[4][2]), dd[4][2])
        ctl = os.path.join(work, "ctl.html")
        ex.export_html([ev(0, 1, "Test", "T", {"Payload": "A\x00B\x1fC"})], ctl)
        cdd = detail_entries(open(ctl, encoding="utf-8").read(), ex._DETAIL_CORE_LABELS)
        check("detail data: a control byte is shown as \\xNN (as the XML export)",
              cdd and ["Payload", "A\\x00B\\x1FC"] in cdd[0][2], cdd[:1])
        bad_script = [m.start() for m in re.finditer(r"</script", html[html.find("<body"):], flags=re.I)]
        n_scripts = len(re.findall(r"<script", html[html.find("<body"):], flags=re.I))
        check("no event value closes a <script> early", len(bad_script) == n_scripts, f"{len(bad_script)} closes vs {n_scripts} opens")
        check("no injected event handler in the page", not s.on, s.on[:3])

        # ── field search does not rescan the page per row ───────────────────
        script = "".join(re.findall(r"<script>(.*?)</script>", html, flags=re.S))
        check("no per-row document.querySelector lookups in the filter code",
              "querySelector('tr.event-row[data-idx=" not in script, "found")

        # ── PS: Has Analysis has something to filter on ─────────────────────
        ps_flags = [r.get("data-has-ps") for r in s.rows]
        want = ["1" if e["event_id"] in (800, 4104) and "powershell" in (e["channel"] + e["provider"]).lower() else "0" for e in events]
        check("every row says whether it is a PowerShell event the analysis reads", ps_flags == want,
              f"{sum(1 for x in ps_flags if x == '1')} flagged, want {want.count('1')}")
        check("…an event ID 800 that is not PowerShell is not flagged", s.rows[3].get("data-has-ps") == "0")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = sum(1 for _, o in res if o)
    print(f"\n{ok}/{len(res)} checks passed")
    return 0 if ok == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
