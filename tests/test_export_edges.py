"""Event values cannot break the HTML report's markup or collide in CSV headers.

Codex audit-5b (synthetic, shared exporter):
* A5B-HTML-SCRIPT: the HTML report's search index writes each event's text as
  JSON straight inside <script>.  An EventData value containing "</script>"
  ends that script early, and whatever follows becomes real markup: a value
  "</script><script id=...>" produced one extra script element.
* A5B-CSV-ED: a custom column titled "ED_payload" is renamed
  "ED_payload (custom)", which is exactly the CSV header of an EventData field
  named "payload (custom)".  Two columns, one header: a reader keyed by header
  sees one value instead of two.

Expected: no script element comes from event data, and the search index still
holds the value; every CSV header is unique and both values are readable.
Synthetic data only.
"""
import csv
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []
MARK = "eh-injected-marker"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(data, custom=None):
    e = {"event_id": 4688, "computer": "SYNTH", "source_file": r"C:\s\Security.evtx", "record_id": 1,
         "timestamp": "2024-01-01T00:00:00.000000Z", "provider": "P", "channel": "Security",
         "level": 4, "level_name": "Information", "event_data": data}
    if custom is not None:
        e["custom_columns"] = custom
    return e


def main() -> int:
    from lxml import html as lhtml
    from evtx_tool.output.exporters import export
    d = tempfile.mkdtemp(prefix="export_edges_")

    payload = f'a</script><script id="{MARK}">window.__x=1</script><b>'
    out = os.path.join(d, "r.html")
    export([ev({"CommandLine": payload})], out, None)
    text = open(out, encoding="utf-8").read()
    doc = lhtml.fromstring(text)
    # Look for the injected element by its CONTENT: the JSON encoder escapes
    # the quotes, so its id attribute comes out as \"eh-injected-marker\".
    injected = [s for s in doc.iter("script") if (s.text or "").strip() == "window.__x=1"]
    check("HTML: event data creates no script element", len(injected) == 0, f"{len(injected)} injected")
    sd = re.search(r"window\._SD=(\[.*?\]);</script>", text, re.S)
    idx = json.loads(sd.group(1)) if sd else []
    check("HTML: the search index still holds the value, unchanged",
          len(idx) == 1 and payload.lower() in idx[0], str(idx)[:200])

    # A5B-HTML-CONTROL (Minor): raw C0 control characters were written into
    # the page, where an HTML parser drops or changes them (4 controls read
    # back as nothing plus one space).  Expected: the same visible, reversible
    # \xNN escape the XML export uses, so the report shows which byte was there.
    out = os.path.join(d, "ctl.html")
    ctl = "A\x00B\x01C\x08D\x1fE"
    export([ev({"Payload": ctl})], out, None)
    page = lhtml.fromstring(open(out, encoding="utf-8").read()).text_content()
    want = "A\\x00B\\x01C\\x08D\\x1FE"
    check("HTML: control characters are shown as \\xNN, as in the XML export", want in page,
          repr(page[page.find("A"):page.find("A") + 30]) if "A" in page else "value not found")

    out = os.path.join(d, "r.csv")
    export([ev({"payload (custom)": "ED-VALUE"}, {"ED_payload": "CC-VALUE"})], out, None)
    with open(out, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    hdr = rows[0]
    check("CSV: every header is unique", len(hdr) == len(set(hdr)),
          f"{len(hdr)} headers, {len(set(hdr))} unique")
    with open(out, encoding="utf-8-sig", newline="") as fh:
        rec = next(csv.DictReader(fh))
    vals = set(rec.values())
    check("CSV: a header-keyed reader sees both values", {"ED-VALUE", "CC-VALUE"} <= vals,
          str({k: v for k, v in rec.items() if "payload" in k}))

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
