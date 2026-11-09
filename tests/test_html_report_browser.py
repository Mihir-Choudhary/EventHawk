"""The HTML report's JavaScript, run in a real browser (headless Edge/Chrome).

test_html_export_large.py checks the page's structure; this one runs it.
User actions are injected while the page is still loading -- the moment the
old report ignored them and the new one must get right:

  * ▶ on a row whose detail data has not arrived yet -> "Loading..." that
    fills in when the data comes;
  * an Event ID filter and a sort by Timestamp -> after loading they cover
    EVERY row, not only the rows that were there when they were clicked
    (sorting during load used to leave the rest unsorted under a ▲ arrow);

then, after loading: field search, PS: Has Analysis, ▶ on the last row,
sorting with open panels, and no script errors.

Skips (exit 0) when no Edge or Chrome is found; set EVTX_TEST_BROWSER to a
browser executable to choose one.

Run: python tests/test_html_report_browser.py
"""
import base64, json, os, pathlib, random, shutil, socket, struct, subprocess, sys, tempfile, time, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CANDIDATES = [
    os.environ.get("EVTX_TEST_BROWSER", ""),
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/microsoft-edge",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


class _WS:
    """Just enough of a WebSocket client for the DevTools protocol (stdlib only)."""

    def __init__(self, url):
        hostport, path = url[len("ws://"):].split("/", 1)
        host, port = hostport.split(":")
        self.s = socket.create_connection((host, int(port)), timeout=120)
        key = base64.b64encode(os.urandom(16)).decode()
        self.s.sendall((f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += self.s.recv(4096)
        self.buf = buf.split(b"\r\n\r\n", 1)[1]
        self.n = 0
        self.errors = []

    def _take(self, n):
        while len(self.buf) < n:
            self.buf += self.s.recv(1 << 20)
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _recv(self):
        msg = b""
        while True:
            b1, b2 = self._take(2)
            n = b2 & 0x7F
            n = struct.unpack(">H", self._take(2))[0] if n == 126 else struct.unpack(">Q", self._take(8))[0] if n == 127 else n
            msg += self._take(n)
            if b1 & 0x80:
                return json.loads(msg)

    def call(self, method, **params):
        self.n += 1
        data = json.dumps({"id": self.n, "method": method, "params": params}).encode()
        hdr = bytearray([0x81])
        ln = len(data)
        hdr += bytes([0x80 | ln]) if ln < 126 else bytes([0x80 | 126]) + struct.pack(">H", ln) if ln < 65536 \
            else bytes([0x80 | 127]) + struct.pack(">Q", ln)
        mask = os.urandom(4)
        self.s.sendall(bytes(hdr) + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(data)))
        while True:
            m = self._recv()
            if m.get("method") == "Runtime.exceptionThrown":
                self.errors.append(m["params"]["exceptionDetails"].get("exception", {}).get("description", "exception"))
            elif m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] == "error":
                self.errors.append(" ".join(str(a.get("value", "")) for a in m["params"]["args"]))
            if m.get("id") == self.n:
                if "error" in m:
                    raise RuntimeError(m["error"])
                return m["result"]

    def js(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, awaitPromise=True, returnByValue=True)
        if "exceptionDetails" in r:
            raise RuntimeError(json.dumps(r["exceptionDetails"])[:500])
        return r["result"].get("value")


def _stop_browser(proc, port):
    """Make the browser quit with all its processes.  proc.kill() ended only
    the process we started -- Edge hands over to a new main process -- and
    each run left a dozen renderer/GPU processes behind (482 of them, 7.3 GB,
    after a day of runs).  Browser.close over DevTools ends them all; killing
    the process tree is the fallback."""
    if proc is None:
        return
    try:
        ver = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=5))
        _WS(ver["webSocketDebuggerUrl"]).call("Browser.close")
    except Exception:
        pass                          # the socket closes as the browser quits
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=1)
            time.sleep(0.2)
        except Exception:
            break                     # gone
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        import signal
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            proc.kill()
    try:
        proc.wait(10)
    except Exception:
        pass


def _events(n):
    rnd = random.Random(7)
    evs = []
    for i in range(n):
        k = i % 5
        ts = f"2026-01-{1 + rnd.randrange(28):02d}T{rnd.randrange(24):02d}:{rnd.randrange(60):02d}:{rnd.randrange(60):02d}Z"
        if k == 0:
            e = dict(event_id=4104, channel="Microsoft-Windows-PowerShell/Operational", provider="Microsoft-Windows-PowerShell",
                     event_data={"ScriptBlockText": f"Write-Host {i}"},
                     attack_tags=[{"tid": "T1059.001", "name": "PowerShell", "tactic": "Execution"}])
        elif k == 1:
            e = dict(event_id=800, channel="Windows PowerShell", provider="PowerShell",
                     event_data={"Data": {"#text": [f"Get-Item {i}\n", "\tHostApplication=powershell.exe\r\n"]}})
        else:
            e = dict(event_id=4624, channel="Security", provider="Microsoft-Windows-Security-Auditing",
                     event_data={"TargetUserName": f"user{i}"})
        e.update(timestamp=ts, computer="HOST-01", level=4, level_name="Information",
                 source_file=rf"C:\case\{e['channel'].replace('/', '-')}.evtx", event_record_id=i + 1, record_id=i + 1)
        evs.append(e)
    return evs


DURING_LOAD = """<script>
window.__T = {rowsAtInject: document.querySelectorAll('tr.event-row').length, dataAtInject: _DD.length};
toggleDetail(5);                                   // its data is not here yet
var _d5 = document.getElementById('detail-5');
window.__T.placeholder = _d5 ? _d5.textContent : null;
_F.eid = '4104'; applyFilters();                   // filter while loading
sortTable(1);                                      // sort by Timestamp while loading
</script>
"""

AFTER_LOAD = r"""(function(){
  var R = {}, rows = Array.from(document.querySelectorAll('tr.event-row'));
  var vis = rows.filter(function(r){ return r.style.display !== 'none'; });
  R.rows = rows.length; R.visible = vis.length;
  R.visibleAll4104 = vis.every(function(r){ return r.dataset.eid === '4104'; });
  var ts = rows.map(function(r){ return r.dataset.ts; });
  R.sortedAll = ts.every(function(t, i){ return i === 0 || ts[i - 1] <= t; });
  var arrow = document.querySelectorAll('thead th')[1].querySelector('.sort-arrow');
  R.arrow = arrow ? arrow.textContent : null;
  var d5 = document.querySelectorAll('#detail-5');
  R.detail5Copies = d5.length;
  R.detail5Text = d5.length ? d5[0].textContent : '';
  R.detail5Shown = d5.length ? d5[0].style.display !== 'none' : false;
  var r5 = rows.find(function(r){ return r.dataset.idx === '5'; });
  R.detail5AfterItsRow = !!(r5 && d5.length && r5.nextElementSibling === d5[0]);
  R.loadingNoticeHidden = document.getElementById('ehLoading').style.display === 'none';
  R.dataEntries = _DD.length;
  return R;
})()"""

INTERACT = r"""(function(){
  var R = {};
  var shown = function(){ return Array.from(document.querySelectorAll('tr.event-row')).filter(function(r){ return r.style.display !== 'none'; }); };
  resetFilters(); R.afterReset = shown().length;
  _F.text = 'eid:800'; applyFilters(); R.field800 = shown().length;
  R.field800AllMatch = shown().every(function(r){ return r.dataset.eid === '800'; });
  var r = shown()[shown().length - 1]; r.querySelector('.expand-btn').click();
  var d = document.getElementById('detail-' + r.dataset.idx);
  R.lastPanel = d ? d.textContent : '';
  _F.text = ''; applyFilters();
  toggleFilter('hasPS', document.getElementById('togglePS'), 'on-ps'); R.ps = shown().length;
  toggleFilter('hasPS', document.getElementById('togglePS'), 'on-ps');
  sortTable(2); sortTable(2);                       // EventID descending, with panels open
  var rows = Array.from(document.querySelectorAll('tr.event-row'));
  R.eidDesc = rows.every(function(x, i){ return i === 0 || +rows[i - 1].dataset.eid >= +x.dataset.eid; });
  var dets = Array.from(document.querySelectorAll('tr.detail-row'));
  R.panelsNextToRows = dets.every(function(t){ var p = t.previousElementSibling;
    return p && p.classList.contains('event-row') && 'detail-' + p.dataset.idx === t.id; });
  return R;
})()"""


def main() -> int:
    exe = next((c for c in CANDIDATES if c and os.path.exists(c)), None)
    if not exe:
        print("SKIP: no Edge/Chrome found (set EVTX_TEST_BROWSER)\n\n0/0 checks passed")
        return 0
    import evtx_tool.output.exporters as ex
    res = []

    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))

    work = tempfile.mkdtemp(prefix="htmlbrowser_")
    proc = None
    port = 0
    try:
        evs = _events(2500)
        page = os.path.join(work, "r.html")
        ex.export_html(evs, page)
        html = open(page, encoding="utf-8").read()
        cut = html.find("<script>_DDp(")
        check("the report has detail data chunks", cut > 0)
        open(page, "w", encoding="utf-8").write(html[:cut] + DURING_LOAD + html[cut:])

        with socket.socket() as so:
            so.bind(("127.0.0.1", 0)); port = so.getsockname()[1]
        prof = os.path.join(work, "profile")
        proc = subprocess.Popen([exe, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={prof}",
                                 "--no-first-run", "--disable-extensions", "about:blank"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=(os.name != "nt"))
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
        ws = _WS(tab["webSocketDebuggerUrl"])
        ws.call("Runtime.enable"); ws.call("Page.enable")
        ws.call("Page.navigate", url=pathlib.Path(page).as_uri())
        t0 = time.time()
        while ws.js("document.readyState") != "complete" and time.time() - t0 < 120:
            time.sleep(0.2)
        time.sleep(0.3)

        T = ws.js("window.__T") or {}
        n4104 = sum(1 for e in evs if e["event_id"] == 4104)
        check("actions ran while loading (rows there, detail data not yet)",
              T.get("rowsAtInject", 0) >= 1000 and T.get("dataAtInject") == 0, T)
        check("▶ before its data arrived shows 'Loading…'", "Loading" in (T.get("placeholder") or ""), T.get("placeholder"))
        A = ws.js(AFTER_LOAD)
        check("every row is in the page", A["rows"] == len(evs), A["rows"])
        check("the filter used while loading covers every row once loaded",
              A["visible"] == n4104 and A["visibleAll4104"], f"{A['visible']} shown, want {n4104}")
        check("the sort used while loading covers every row once loaded (▲ is true)",
              A["sortedAll"] and A["arrow"] == "\u25B2", A)
        check("…the 'Loading…' panel was filled in with the event's data, once",
              A["detail5Copies"] == 1 and "Write-Host 5" in A["detail5Text"] and "Loading" not in A["detail5Text"]
              and A["detail5Shown"], A["detail5Text"][:120])
        check("…and stays right under its row after the sort", A["detail5AfterItsRow"])
        check("the loading notice is gone; all detail data arrived",
              A["loadingNoticeHidden"] and A["dataEntries"] == len(evs), A)

        B = ws.js(INTERACT)
        n800 = sum(1 for e in evs if e["event_id"] == 800)
        check("after Reset every row shows", B["afterReset"] == len(evs), B["afterReset"])
        check("field search eid:800 finds exactly the 800s", B["field800"] == n800 and B["field800AllMatch"], B["field800"])
        check("▶ on the last shown row opens its panel, event data readable",
              "Get-Item" in B["lastPanel"] and "HostApplication=powershell.exe" in B["lastPanel"]
              and "{'#text'" not in B["lastPanel"], B["lastPanel"][:160])
        check("PS: Has Analysis shows the PowerShell events", B["ps"] == n4104 + n800, f"{B['ps']} vs {n4104 + n800}")
        check("sorting with panels open keeps each panel under its row", B["eidDesc"] and B["panelsNextToRows"], B)
        check("no script errors", not ws.errors, ws.errors[:3])
    finally:
        _stop_browser(proc, port)
        shutil.rmtree(work, ignore_errors=True)

    ok = sum(1 for _, o in res if o)
    print(f"\n{ok}/{len(res)} checks passed")
    return 0 if ok == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
