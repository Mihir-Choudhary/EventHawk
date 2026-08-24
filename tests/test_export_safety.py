"""Exports are the deliverable — hostile field values must not corrupt them.

Every string in an event is attacker-influenced: hostnames, command lines,
registry values, usernames. Three real defects were found here, all of which
damage the artifact an examiner hands to someone else.

  HTML  ``_esc`` escaped ``& < > "`` but NOT the apostrophe, while every
        attribute in the report is written with SINGLE quotes. A hostname of
        ``PC' onmouseover='alert(1)`` closed ``data-computer`` and injected a
        live event handler — parsed back out of the file, 2 real handler
        attributes. The same bug silently TRUNCATED an ordinary
        ``O'Brien-PC`` to ``PC``, so it corrupted data as well as being an
        injection.

  XML   Control bytes are legal in Windows event data and illegal in XML 1.0.
        lxml raised ValueError (uncaught — ``export_xml`` only catches
        ImportError) so the export died; the stdlib fallback wrote them
        through and produced a file that will not parse, which is worse
        because nothing says so.

Checks parse the output rather than grepping it: a substring search cannot
tell an inert escaped ``onmouseover=`` from a live attribute, and it reported
the fix as broken when it was not.

Run: QT_QPA_PLATFORM=offscreen python tests/test_export_safety.py
"""
import os, sys, csv, json, tempfile, shutil
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ATTR_BREAK = "PC' onmouseover='alert(1)"
APOSTROPHE = "O'Brien-PC"
XML_INJECT = "</Computer><evil>pwned</evil>"
CTRL       = "bad\x01char"
SENTINEL   = 18446744073709551615
UNICODE    = "héllo-中文-🙂"


class _Handlers(HTMLParser):
    def __init__(self):
        super().__init__(); self.on_attrs = []; self.by_name = {}
    def handle_starttag(self, tag, attrs):
        for k, v in attrs:
            if k.startswith("on"):
                self.on_attrs.append((tag, k, v))
            self.by_name.setdefault(k, []).append(v)


def main() -> int:
    import evtx_tool.output.exporters as ex

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    work = tempfile.mkdtemp(prefix="expsafe_")
    try:
        ev = {"record_id": 1, "event_id": 4624, "level_name": "Information",
              "timestamp": "2025-01-01T00:00:00Z", "channel": "Security",
              "computer": ATTR_BREAK, "user_id": APOSTROPHE,
              "provider": "A & B <tag>", "source_file": UNICODE,
              "event_data": {"bandwidthLimit": SENTINEL, "ctrl": CTRL}}

        # ── HTML ─────────────────────────────────────────────────────────
        hp = os.path.join(work, "r.html")
        ex.export_html([ev], hp)
        parser = _Handlers()
        parser.feed(open(hp, encoding="utf-8").read())
        # The report legitimately ships its own onclick/onchange handlers for
        # sorting and filtering, so "no handlers at all" is the wrong test --
        # it fails on correct output. What must never appear is a handler the
        # report does not author, or one carrying event-derived content.
        OWN = {"onclick", "onchange"}
        foreign = [h for h in parser.on_attrs if h[1] not in OWN]
        tainted = [h for h in parser.on_attrs if "alert(1)" in (h[2] or "")]
        check("HTML: no event handler beyond the report's own is created",
              not foreign,
              f"{foreign[:2]} — an injected handler escaped an attribute")
        check("HTML: no handler carries attacker-controlled content",
              not tainted, f"{tainted[:1]}")
        comp = parser.by_name.get("data-computer", [])
        check("HTML: the hostile hostname survives INTACT in its attribute",
              bool(comp) and comp[0] == ATTR_BREAK,
              f"parsed {comp[:1]!r}, want {ATTR_BREAK!r} — a short value means "
              f"the attribute was cut at the apostrophe")

        ev2 = dict(ev, computer=APOSTROPHE)
        hp2 = os.path.join(work, "r2.html")
        ex.export_html([ev2], hp2)
        p2 = _Handlers(); p2.feed(open(hp2, encoding="utf-8").read())
        got = p2.by_name.get("data-computer", [])
        check("HTML: an ordinary apostrophe hostname is not truncated",
              bool(got) and got[0] == APOSTROPHE,
              f"parsed {got[:1]!r}, want {APOSTROPHE!r}")

        # ── XML: both back ends ──────────────────────────────────────────
        ev3 = dict(ev, computer=XML_INJECT)
        for label, fn in (("lxml", getattr(ex, "_export_xml_lxml", None)),
                          ("stdlib", getattr(ex, "_export_xml_stdlib", None))):
            if fn is None:
                continue
            xp = os.path.join(work, f"r_{label}.xml")
            try:
                fn([ev3], xp)
                root = ET.parse(xp).getroot()
                ok, detail = True, ""
            except Exception as exc:
                root, ok, detail = None, False, f"{type(exc).__name__}: {exc}"
            check(f"XML ({label}): control bytes still yield well-formed XML",
                  ok, detail)
            if root is None:
                continue
            check(f"XML ({label}): injected markup did not become an element",
                  root.find(".//evil") is None,
                  "an <evil> element means the close-tag escaped")
            check(f"XML ({label}): the injected text is preserved verbatim",
                  root.findtext(".//Computer") == XML_INJECT,
                  f"got {root.findtext('.//Computer')!r}")
            body = open(xp, encoding="utf-8").read()
            check(f"XML ({label}): the control byte is shown, not dropped",
                  "\\x01" in body and "\x01" not in body,
                  "evidence must stay visible as an escape, never be discarded")

        # ── JSON ─────────────────────────────────────────────────────────
        jp = os.path.join(work, "r.json")
        ex.export_json([ev], jp)
        try:
            doc = json.load(open(jp, encoding="utf-8"))
            rec = doc[0] if isinstance(doc, list) else (doc.get("events") or [{}])[0]
            ok = True
        except Exception as exc:
            rec, ok = {}, False
            check("JSON: output parses", False, f"{type(exc).__name__}: {exc}")
        if ok:
            check("JSON: output parses", True)
            ed = rec.get("event_data") or {}
            check("JSON: the unsigned 64-bit sentinel survives exactly",
                  ed.get("bandwidthLimit") == SENTINEL, f"got {ed.get('bandwidthLimit')!r}")
            check("JSON: unicode survives exactly",
                  rec.get("source_file") == UNICODE, f"got {rec.get('source_file')!r}")

        # ── CSV ──────────────────────────────────────────────────────────
        ev4 = dict(ev, computer='has "quotes"', user_id="two\nlines")
        cp = os.path.join(work, "r.csv")
        ex.export_csv([ev4], cp)
        rows = list(csv.reader(open(cp, encoding="utf-8", newline="")))
        check("CSV: embedded quotes and newlines round-trip through a parser",
              len(rows) == 2 and 'has "quotes"' in rows[1] and
              any("two\nlines" == c for c in rows[1]),
              f"{len(rows)} row(s) parsed")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
