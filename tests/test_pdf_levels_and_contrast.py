"""PDF report: the level table counts every event, and page text is readable (Codex FO-3/FO-4).

FO-3  The level summary listed only Critical/Error/Warning/Information/
      Verbose: a Setup log (all LogAlways) got an empty table, and a combined
      report left every level-0 event out of it.  Expected: every level that
      occurs, summing to the event total.
FO-4  Cover and summary text were light grey (0.88) meant for a dark page, on
      white pages.  Expected: page text with contrast >= 4.5:1 against white;
      chain-card text stays light on its dark card.
Checked on the rendered PDF (PyMuPDF).  Synthetic events.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def lum(rgb):
    def ch(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(x) for x in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def main() -> int:
    import fitz
    from evtx_tool.output.pdf_exporter import export_pdf
    evs = []
    for i, lv in enumerate(["LogAlways"] * 7 + ["Information"] * 3 + ["Error"] * 2 + [""]):
        evs.append({"event_id": 4624, "timestamp": f"2024-01-02T03:04:{i:02d}Z", "provider": "P",
                    "channel": "C", "computer": "PC", "record_id": i + 1, "source_file": "a.evtx",
                    "level_name": lv, "event_data": {}})
    path = os.path.join(tempfile.mkdtemp(prefix="pdf_lv_"), "r.pdf")
    export_pdf(evs, path)
    doc = fitz.open(path)
    text = "\n".join(p.get_text() for p in doc)
    rows = dict(re.findall(r"^(LogAlways|Critical|Error|Warning|Information|Verbose|\(no level\))\n([\d,]+)$",
                           text, re.M))
    total = sum(int(v.replace(",", "")) for v in rows.values())
    check("LogAlways is in the level table", rows.get("LogAlways") == "7", str(rows))
    check("the level table sums to the event total", total == len(evs), f"{total} vs {len(evs)}")
    faint = []
    for page in doc:
        for b in page.get_text("dict")["blocks"]:
            for line in b.get("lines", []):
                for s in line["spans"]:
                    if not s["text"].strip():
                        continue
                    c = s["color"]
                    rgb = (((c >> 16) & 255) / 255, ((c >> 8) & 255) / 255, (c & 255) / 255)
                    # White text sits on the dark table-header cells by design.
                    if rgb != (1.0, 1.0, 1.0) and contrast(rgb, (1, 1, 1)) < 4.5:
                        faint.append(s["text"].strip()[:30])
    check("no page text is too faint to read on white (contrast >= 4.5)", not faint, str(faint[:6]))
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
