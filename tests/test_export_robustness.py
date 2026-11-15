"""Exports survive hostile strings and keep the Activity ID.

Gemini audit 6-04 / 6-05 / 6-14 / 6-15 (High):
- PDF: a C0 control byte (legal in event strings) went into ReportLab markup
  unescaped; XML 1.0 forbids it, so the PDF export failed.
- HTML: a correlation chain's severity / timestamp and a threat-intel verdict
  went into the report unescaped (markup injection), and a permalink of any
  scheme ("javascript:") became a link.
- HTML: the detail drawer read ev["activity_id"] -- no such key; the Activity
  ID (correlation_id) was always blank.
- CSV / JSON / HTML / STIX: a lone UTF-16 surrogate (a broken WCHAR string)
  made the UTF-8 write raise, aborting the export.

Expected: each export completes; the HTML has no raw "<script>" from those
fields and no "javascript:" link; the Activity ID is in the HTML; a lone
surrogate is written as the text "\\udXXX".  Synthetic events.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from evtx_tool.output import exporters as X
    d = tempfile.mkdtemp(prefix="exprob_")
    try:
        ev = {"record_id": 1, "event_record_id": 1, "event_id": 4688, "level": 4, "level_name": "Information",
              "timestamp": "2026-01-01T00:00:00.000000Z", "channel": "Security", "provider": "P",
              "computer": "HOST\x01A", "user_id": "", "source_file": r"C:\c\a.evtx", "keywords": "0x0",
              "correlation_id": "{11111111-2222-3333-4444-555555555555}",
              "event_data": {"CommandLine": "bad \ud800 text"}}
        chains = [{"rule_name": "R", "severity": "<script>alert(1)</script>", "tactic": "T",
                   "first_ts": "<script>x</script>", "last_ts": "2026", "event_count": 1,
                   "computers": ["H"], "users": ["u"], "events": [], "description": "d"}]
        iocs = {"summary": {"total": 1, "ipv4": 1},
                "ipv4": [{"value": "203.0.113.9", "count": 1, "first_seen": "", "last_seen": "", "score": 1,
                          "threat_intel": {"verdict": "<img src=x onerror=1>",
                                           "permalink": "javascript:alert(1)"}}]}
        ti = None
        for fmt in ("csv", "json", "html"):
            p = os.path.join(d, f"o.{fmt}")
            try:
                if fmt == "html":
                    X.export_html([dict(ev)], p, chains=chains, iocs=iocs)
                else:
                    X.export([dict(ev)], p, fmt=fmt)
                err = ""
            except Exception as e:
                err = repr(e)
            check(f"{fmt}: the export completes with a lone surrogate", os.path.exists(p) and not err, err)
            if os.path.exists(p) and fmt in ("csv", "json"):
                txt = open(p, encoding="utf-8").read()
                check(f"{fmt}: the surrogate is written as text", "\\ud800" in txt, txt[:120].replace("\n", " "))
        hp = os.path.join(d, "o.html")
        html = open(hp, encoding="utf-8").read() if os.path.exists(hp) else ""
        check("html: a chain's severity / time are escaped", "<script>alert(1)</script>" not in html
              and "<script>x</script>" not in html)
        check("html: no javascript: link", "href='javascript:" not in html and 'href="javascript:' not in html)
        check("html: the threat-intel verdict is escaped", "<img src=x onerror=1>" not in html)
        check("html: the Activity ID is in the report", "11111111-2222-3333-4444-555555555555" in html)
        try:
            from evtx_tool.output import pdf_exporter as P
            out = P._x("A\x01B\x0bC")
            from reportlab.platypus import Paragraph
            from reportlab.lib.styles import getSampleStyleSheet
            Paragraph(out, getSampleStyleSheet()["Normal"])
            check("pdf: control bytes do not break the markup", True)
        except ImportError:
            print("  (reportlab not installed: PDF check skipped)")
        except Exception as e:
            check("pdf: control bytes do not break the markup", False, repr(e))
    finally:
        shutil.rmtree(d, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
