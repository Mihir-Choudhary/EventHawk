"""The Event Detail pane shows nested event data as text, not a Python printout.

Structured UserData -- e.g. Setup / CBS servicing events -- is kept as a
nested value:

    {"CbsPackageChangeState": {"#attributes": {"xmlns": "http://..."},
                               "Client": "UpdateAgentLCU", "ErrorCode": "0x0", ...}}

The detail pane (Full mode, EVENT DATA) showed it with ``str(dict)``:
``CbsPackageChangeState : {'Client': 'UpdateAgentLCU', 'ErrorCode': '0x0', ...}``.
It now shows one ``Name: value`` line per field, like the CSV/HTML exports.
What already worked stays as it was: unnamed PowerShell items one per line,
plain values, empty values skipped, XML attributes such as xmlns hidden.

Run: QT_QPA_PLATFORM=offscreen python tests/test_detail_pane_nested.py
"""
import os, re, sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

XMLNS = "http://manifests.microsoft.com/win/2004/08/windows/setup_provider"
CBS = {"#attributes": {"xmlns": XMLNS}, "Client": "UpdateAgentLCU", "ErrorCode": "0x0",
       "IntendedPackageState": 5112, "PackageIdentifier": "KB0000000"}
PS_ITEMS = ["  Get-ChildItem -Path C:\\Temp\n", "\tDetailSequence=1\r\n\tHostApplication=powershell.exe\r\n"]
DEEP = {"Outer": {"Inner": {"#text": ["one", "two"]}, "Count": 2}, "List": ["a", {"k": "v"}]}
PRINTOUT = re.compile(r"\{'|\['|'#text'|'#attributes'|\\r\\n")

EVENTS = [
    {"event_id": 2, "timestamp": "2026-08-09T17:27:00Z", "channel": "Setup",
     "provider": "Microsoft-Windows-Servicing", "computer": "HOST-01", "level": 0, "level_name": "LogAlways",
     "source_file": "C:\\case\\HOST-01\\Setup.evtx", "event_record_id": 2002, "record_id": 2002,
     "event_data": {"CbsPackageChangeState": CBS}},
    {"event_id": 800, "timestamp": "2026-06-23T16:38:49Z", "channel": "Windows PowerShell",
     "provider": "PowerShell", "computer": "HOST-01", "level": 4, "level_name": "Information",
     "source_file": "C:\\case\\HOST-01\\Windows PowerShell.evtx", "event_record_id": 1001, "record_id": 1001,
     "event_data": {"Data": {"#text": PS_ITEMS}}},
    {"event_id": 9, "timestamp": "2026-08-09T17:28:00Z", "channel": "Test", "provider": "T",
     "computer": "HOST-01", "level": 4, "level_name": "Information", "source_file": "t.evtx",
     "event_record_id": 3, "record_id": 3,
     "event_data": {"Deep": DEEP, "Plain": "value 1", "Zero": 0, "Empty": "", "Nothing": None,
                    "OnlyAttr": {"#attributes": {"xmlns": "x"}}}},
]


def main() -> int:
    res = []

    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail!r}" if detail and not ok else ""))

    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    f = mw.MainWindow._flatten_ev_val

    # ── the value helper ────────────────────────────────────────────────────
    s = f(CBS)
    check("CBS: one line per field", s == "Client: UpdateAgentLCU\nErrorCode: 0x0\n"
          "IntendedPackageState: 5112\nPackageIdentifier: KB0000000", s)
    check("CBS: no printout", s and not PRINTOUT.search(s), s)
    check("CBS: xmlns attribute stays hidden (as before)", s and XMLNS not in s, s)
    s = f(DEEP)
    check("deeper levels as dotted names", s == "Outer.Inner: one\nOuter.Inner: two\nOuter.Count: 2\n"
          "List: a\nList.k: v", s)
    check("list holding a dict: no printout", f(["a", {"k": "v"}]) == "a\nk: v", f(["a", {"k": "v"}]))
    check("text next to fields keeps both", f({"#text": "T", "F": "x"}) == "T\nF: x", f({"#text": "T", "F": "x"}))
    # unchanged behaviour
    check("unnamed items one per line (unchanged)", f({"#text": ["v1", "v2"]}) == "v1\nv2")
    check("blank unnamed items dropped (unchanged)", f({"#text": ["v1", None, "  ", "v2"]}) == "v1\nv2")
    check("#text scalar stripped (unchanged)", f({"#text": "  v "}) == "v")
    check("#text with attributes -> text only (unchanged)", f({"#text": "v", "#attributes": {"a": "1"}}) == "v")
    check("plain list (unchanged)", f(["a", "b"]) == "a\nb")
    check("plain string stripped (unchanged)", f("  s ") == "s")
    check("0 is shown (unchanged)", f(0) == "0")
    for v in (None, "", "   ", {}, [], {"#text": None}, {"#attributes": {"xmlns": "x"}}, {"#text": []}):
        check(f"skipped: {v!r} (unchanged)", f(v) is None, f(v))

    # ── the rendered pane (Full mode) ───────────────────────────────────────
    w = mw.MainWindow()
    try:
        if not w._detail_full_mode:
            w._on_detail_mode_toggled(True)
        texts = []
        for ev in EVENTS:
            w._last_detail_key = None
            w._render_event_detail(ev)
            app.processEvents()
            texts.append(w._detail_browser.toPlainText())
        cbs, ps, misc = texts
        check("pane CBS: no printout", not PRINTOUT.search(cbs), cbs[-400:])
        for line in ("Client: UpdateAgentLCU", "ErrorCode: 0x0", "IntendedPackageState: 5112",
                     "PackageIdentifier: KB0000000"):
            check(f"pane CBS shows '{line}'", line in cbs, cbs[-400:])
        check("pane CBS: field name shown", "CbsPackageChangeState" in cbs, cbs[-400:])
        check("pane PS 800: command on its own line", "Get-ChildItem -Path C:\\Temp" in ps
              and not PRINTOUT.search(ps), ps[-400:])
        check("pane misc: dotted names", "Outer.Inner: one" in misc and "List.k: v" in misc, misc[-400:])
        check("pane misc: 0 shown, empty fields skipped", "Zero" in misc and "Empty" not in misc
              and "Nothing" not in misc and "OnlyAttr" not in misc, misc[-400:])
        check("pane misc: no printout", not PRINTOUT.search(misc), misc[-400:])
    finally:
        w.close()
        app.processEvents()

    ok = sum(1 for _, p in res if p)
    print(f"\n{ok}/{len(res)} checks passed")
    return 0 if ok == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
