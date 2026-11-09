"""Nested event-data values are exported as data, not as a Python printout.

The parser keeps two kinds of event data as nested values:

  * unnamed <Data> items, e.g. Windows PowerShell 800 / 400 / 403 / 600:
        {"Data": {"#text": ["  Add-Type ...\\n", "\\tDetailSequence=1\\r\\n..."]}}
  * structured UserData, e.g. Setup / CBS servicing events:
        {"CbsPackageChangeState": {"#attributes": {"xmlns": "http://..."},
                                   "Client": "UpdateAgentLCU", "ErrorCode": "0x0", ...}}

XML, CSV and HTML wrote these with ``str(value)``: a Python printout such as
``{'#text': ['  Add-Type ...\\n', '\\tDetailSequence=1\\r\\n...']}`` -- quotes,
brackets and the two-character sequence backslash-r backslash-n instead of
real line breaks.  On a real 44,225-event export that was 8,291 values,
including the PowerShell script text.  JSON was already right (it keeps the
nesting), so it is the reference here.

Also: the stdlib XML writer (used when lxml is missing) opened the file in
text mode on Windows and did not escape CR, so a value "a\\r\\nb" read back as
"a\\n\\nb".

Run: QT_QPA_PLATFORM=offscreen python tests/test_export_nested_values.py
"""
import csv, json, os, re, shutil, sys, tempfile
import xml.etree.ElementTree as ET

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PS_ITEMS = ["  Add-Type -TypeDefinition $code -ReferencedAssemblies System.Drawing\n",
            "\tDetailSequence=1\r\n\tDetailTotal=1\r\n\r\n\tHostApplication=powershell.exe -NoProfile\r\n",
            "CommandInvocation(Add-Type): \"Add-Type\"\r\n"]
CBS = {"#attributes": {"xmlns": "http://manifests.microsoft.com/win/2004/08/windows/setup_provider"},
       "Client": "UpdateAgentLCU", "ErrorCode": "0x0", "IntendedPackageState": 5112,
       "PackageIdentifier": "KB5058411"}
HOSTILE = {"#text": ["</Data><evil>x</evil>", "O'Brien \"q\" & <b>", "ctrl\x01byte", "=cmd|' /C calc'!A0"]}
DEEP = {"Outer": {"Inner": {"#text": ["one", "two"]}, "Count": 2}, "List": ["a", {"k": "v"}]}
# text next to child elements (mixed content), and an #attributes that is not a dict
MIXED = {"Mix": {"#text": "T\r\n", "#attributes": {"a": "1"}}, "Mix2": {"#text": "T", "F": "x"},
         "BadAttr": {"#attributes": "STR", "F": "x"}}

EVENTS = [
    {"event_id": 800, "timestamp": "2026-06-23T16:38:49.381261Z", "channel": "Windows PowerShell",
     "provider": "PowerShell", "computer": "HOST-01", "level": 4, "level_name": "Information",
     "source_file": r"C:\case\HOST-01\Windows PowerShell.evtx", "event_record_id": 1,
     "event_data": {"Data": {"#text": PS_ITEMS}}},
    {"event_id": 2, "timestamp": "2026-08-09T17:27:00Z", "channel": "Setup", "provider": "Microsoft-Windows-Servicing",
     "computer": "HOST-01", "level": 0, "level_name": "LogAlways",
     "source_file": r"C:\case\HOST-01\Setup.evtx", "event_record_id": 2,
     "event_data": {"CbsPackageChangeState": CBS}},
    {"event_id": 9, "timestamp": "2026-08-09T17:28:00Z", "channel": "Test", "provider": "T", "computer": "HOST-01",
     "level": 4, "level_name": "Information", "source_file": "t.evtx", "event_record_id": 3,
     "event_data": {"Hostile": HOSTILE, "Deep": DEEP, "Plain": "a\r\nb\tc", "Zero": 0, "Empty": "", "Nothing": None}},
    {"event_id": 10, "timestamp": "2026-08-09T17:29:00Z", "channel": "Test", "provider": "T", "computer": "HOST-01",
     "level": 4, "level_name": "Information", "source_file": "t.evtx", "event_record_id": 4, "event_data": MIXED},
]
PRINTOUT = re.compile(r"\{'|\['|'#text'|'#attributes'|\\r\\n")


def main() -> int:
    import evtx_tool.output.exporters as ex
    res = []

    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail and not ok else ""))

    work = tempfile.mkdtemp(prefix="nested_")
    try:
        # ── the shared text form (CSV, HTML, search) ────────────────────────
        text = getattr(ex, "event_data_text", None)
        check("exporters.event_data_text exists", callable(text))
        if callable(text):
            t = text({"#text": PS_ITEMS})
            check("unnamed items: each item verbatim, one after another",
                  all(i in t for i in PS_ITEMS) and t.index(PS_ITEMS[0]) < t.index(PS_ITEMS[1]) < t.index(PS_ITEMS[2]), repr(t))
            check("unnamed items: no printout (quotes, brackets, \\r\\n as text)", not PRINTOUT.search(t), repr(t[:120]))
            c = text(CBS)
            check("structured data: one 'Name: value' line per field",
                  all(f"{k}: {v}" in c.splitlines() for k, v in CBS.items() if k != "#attributes"), repr(c))
            check("structured data: attributes kept, marked with @", "@xmlns: " + CBS["#attributes"]["xmlns"] in c.splitlines(), repr(c))
            check("structured data: no printout", not PRINTOUT.search(c), repr(c))
            d = text(DEEP)
            check("deeper nesting: every leaf value present, no printout",
                  all(s in d for s in ("one", "two", "Count: 2", "a", "k: v")) and not PRINTOUT.search(d), repr(d))
            check("an #attributes that is not a dict is kept, not dropped", "STR" in text(MIXED["BadAttr"]), repr(text(MIXED["BadAttr"])))
            check("plain values unchanged", text("a\r\nb\tc") == "a\r\nb\tc" and text(0) == "0" and text("") == "" and text(None) == "")

        # ── XML: both writers, structured, exact, identical ─────────────────
        trees = {}
        for label, fn in (("lxml", ex._export_xml_lxml), ("stdlib", ex._export_xml_stdlib)):
            p = os.path.join(work, f"{label}.xml")
            fn(EVENTS, p)
            raw = open(p, encoding="utf-8").read()
            try:
                root = ET.parse(p).getroot()
            except ET.ParseError as e:
                check(f"XML {label}: parses", False, str(e)); continue
            trees[label] = root
            check(f"XML {label}: no printout anywhere", not PRINTOUT.search(raw), PRINTOUT.search(raw) and raw[max(0, PRINTOUT.search(raw).start() - 60):][:160])
            evs = root.findall("Event")
            ps = evs[0].find("EventData/Data[@Name='Data']")
            items = [i.text or "" for i in ps.findall("Item")] if ps is not None else []
            check(f"XML {label}: unnamed items are <Item> children, each exact (CR kept)", items == PS_ITEMS, repr(items)[:200])
            cbs = evs[1].find("EventData/Data[@Name='CbsPackageChangeState']")
            fields = {f.get("Name"): f.text for f in cbs.findall("Field")} if cbs is not None else {}
            attrs = {a.get("Name"): a.text for a in cbs.findall("Attribute")} if cbs is not None else {}
            check(f"XML {label}: structured data are <Field Name=...> children",
                  fields == {k: str(v) for k, v in CBS.items() if k != "#attributes"}, fields)
            check(f"XML {label}: attributes are <Attribute Name=...> children", attrs == CBS["#attributes"], attrs)
            ed3 = {d.get("Name"): d for d in evs[2].findall("EventData/Data")}
            hostile = [i.text for i in ed3["Hostile"].findall("Item")] if "Hostile" in ed3 else []
            check(f"XML {label}: hostile items stay text (control byte shown as \\x01)",
                  hostile == ["</Data><evil>x</evil>", "O'Brien \"q\" & <b>", "ctrl\\x01byte", "=cmd|' /C calc'!A0"]
                  and root.find(".//evil") is None, hostile)
            check(f"XML {label}: plain value exact, CR kept", ed3.get("Plain") is not None and ed3["Plain"].text == "a\r\nb\tc",
                  repr(ed3.get("Plain") is not None and ed3["Plain"].text))
            ed4 = {d.get("Name"): d for d in evs[3].findall("EventData/Data")} if len(evs) > 3 else {}
            mix = ed4.get("Mix")
            check(f"XML {label}: text next to child elements is exact (no added whitespace)",
                  mix is not None and mix.text == "T\r\n" and [(a.get("Name"), a.text) for a in mix.findall("Attribute")] == [("a", "1")]
                  and ed4["Mix2"].text == "T" and [(f.get("Name"), f.text) for f in ed4["Mix2"].findall("Field")] == [("F", "x")],
                  repr(mix is not None and mix.text))
            bad = ed4.get("BadAttr")
            check(f"XML {label}: an #attributes that is not a dict is kept",
                  bad is not None and "STR" in [x.text for x in bad.iter()], ET.tostring(bad) if bad is not None else None)
            check(f"XML {label}: 0 stays 0, empty and None stay empty",
                  ed3["Zero"].text == "0" and not (ed3["Empty"].text or "") and not (ed3["Nothing"].text or ""))

            def back(el):            # rebuild the value from the XML
                items_, fields_, attrs_ = el.findall("Item"), el.findall("Field"), el.findall("Attribute")
                if not (items_ or fields_ or attrs_):
                    return el.text or ""
                if items_ and not (fields_ or attrs_):
                    return [back(i) for i in items_]
                out = {}
                if attrs_:
                    out["#attributes"] = {a.get("Name"): a.text or "" for a in attrs_}
                if items_:
                    out["#text"] = [back(i) for i in items_]
                for f in fields_:
                    out[f.get("Name")] = back(f)
                return out
            # {"#text": [items]} alone is the parser's wrapper for a sequence of
            # unnamed items: the same thing as the list, written the same way.
            norm = lambda v: (norm(v["#text"]) if isinstance(v, dict) and set(v) == {"#text"}
                              and isinstance(v["#text"], list)
                              else {k: norm(x) for k, x in v.items()} if isinstance(v, dict)
                              else [norm(x) for x in v] if isinstance(v, list)
                              else "" if v is None else str(v))
            want = norm(DEEP)
            got = back(ed3["Deep"]) if "Deep" in ed3 else None
            check(f"XML {label}: deeper nesting round-trips to the same value", got == want, f"{got} != {want}")
            got_cbs = back(cbs) if cbs is not None else None
            check(f"XML {label}: structured data round-trips to the same value", got_cbs == norm(CBS), got_cbs)
        if len(trees) == 2:
            check("XML: lxml and stdlib writers give the same document",
                  ET.tostring(trees["lxml"].find("Event/EventData")) == ET.tostring(trees["stdlib"].find("Event/EventData"))
                  and [ET.tostring(e.find("EventData")) for e in trees["lxml"].findall("Event")]
                  == [ET.tostring(e.find("EventData")) for e in trees["stdlib"].findall("Event")])

        # ── CSV: readable cells, compact layout still JSON ───────────────────
        p = os.path.join(work, "x.csv")
        ex.export_csv(EVENTS, p)
        rows = list(csv.DictReader(open(p, encoding="utf-8-sig", newline="")))
        cell = rows[0].get("ED_Data", "")
        check("CSV: unnamed items are the readable text", callable(text) and cell == text({"#text": PS_ITEMS}), repr(cell[:120]))
        check("CSV: no printout in any cell", not any(PRINTOUT.search(v or "") for r in rows for v in r.values()),
              [v[:80] for r in rows for v in r.values() if PRINTOUT.search(v or "")][:2])
        check("CSV: structured data readable", "Client: UpdateAgentLCU" in rows[1].get("ED_CbsPackageChangeState", ""))
        check("CSV: formula guard still applies inside nested text",
              not rows[2].get("ED_Hostile", "").lstrip().startswith(("=", "+", "-", "@"))
              and "=cmd|' /C calc'!A0" in rows[2].get("ED_Hostile", ""))
        pos = {"EventData": 0}
        compact = ex.csv_row(EVENTS[0], {**{h: i for i, h in enumerate(ex.CSV_BASE_KEYS)}, "EventData": len(ex.CSV_BASE_KEYS)},
                             len(ex.CSV_BASE_KEYS) + 1)[len(ex.CSV_BASE_KEYS)]
        check("CSV compact layout: still the JSON of the nested value", json.loads(compact) == EVENTS[0]["event_data"])

        # ── HTML: details and search use the readable text ──────────────────
        p = os.path.join(work, "x.html")
        ex.export_html(EVENTS, p)
        html = open(p, encoding="utf-8").read()
        # Outside <script>: the page text.  Inside: JSON, where a line break
        # MUST be written as backslash-r backslash-n -- so decode the JSON strings and check those.
        page = re.sub(r"<script>.*?</script>", "", html, flags=re.S)
        check("HTML: no printout in the page", not PRINTOUT.search(page),
              PRINTOUT.search(page) and page[max(0, PRINTOUT.search(page).start() - 80):][:200])
        strings = [json.loads(m) for m in re.findall(r'"(?:[^"\\]|\\.)*"',"".join(re.findall(r"<script>(.*?)</script>", html, flags=re.S)))]
        bad = [x for x in strings if PRINTOUT.search(x)]
        check("HTML: no printout in the page's data (decoded)", strings and not bad, repr(bad[:1])[:200])
        sd = ex._build_search_string(EVENTS[0])
        check("HTML search index: finds the command text, no printout", "add-type -typedefinition" in sd and not PRINTOUT.search(sd), sd[:160])

        # ── a lone surrogate inside a nested value: shown, not a crash ───────
        sur = [{**EVENTS[0], "event_data": {"D": {"#text": ["a\ud800b"]}}}]
        for fmt, fn in (("csv", ex.export_csv), ("html", ex.export_html), ("xml", ex.export_xml)):
            p = os.path.join(work, "sur." + fmt)
            try:
                fn(sur, p)
                body = open(p, encoding="utf-8-sig").read()
                check(f"{fmt.upper()}: a lone surrogate in a nested value is shown as \\ud800, no crash",
                      "\\ud800" in body or "\\\\ud800" in body or "\\xD800" in body or "\\\\xD800" in body, body[-300:])
            except Exception as e:      # noqa: BLE001
                check(f"{fmt.upper()}: a lone surrogate in a nested value is shown as \\ud800, no crash", False, repr(e)[:160])

        # ── JSON: the reference, unchanged ───────────────────────────────────
        p = os.path.join(work, "x.json")
        ex.export_json(EVENTS, p)
        j = json.load(open(p, encoding="utf-8"))
        j = j.get("events", j) if isinstance(j, dict) else j
        check("JSON: nested values unchanged", j[0]["event_data"] == EVENTS[0]["event_data"] and j[1]["event_data"]["CbsPackageChangeState"]["Client"] == "UpdateAgentLCU")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    ok = sum(1 for _, o in res if o)
    print(f"\n{ok}/{len(res)} checks passed")
    return 0 if ok == len(res) else 1


if __name__ == "__main__":
    sys.exit(main())
