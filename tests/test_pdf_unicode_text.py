"""PDF report shows non-Latin text, not black boxes (Codex FO-12).

The PDF used Helvetica, which has no Cyrillic, CJK or emoji glyphs: a computer
named "Русский 中文 🙂 café" printed as boxes (accented Latin survived), while
CSV/JSON/XML/HTML kept the value.  Expected: each character drawn from a font
that has it; a character no available font has is written as U+XXXX, never a
box.  Checked on the text PyMuPDF extracts from the rendered PDF.  Synthetic.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


SAMPLES = {"Cyrillic": "Русский", "Chinese": "中文", "Korean": "한국어", "accented Latin": "café",
           "emoji": "🙂"}


def main() -> int:
    import fitz
    from evtx_tool.output.pdf_exporter import export_pdf
    name = " ".join(SAMPLES.values())
    evs = [{"event_id": 4624, "timestamp": f"2024-01-02T03:04:0{i}Z", "provider": "P", "channel": "Канал",
            "computer": name, "record_id": i + 1, "source_file": "журнал.evtx",
            "level_name": "Information", "event_data": {}} for i in range(3)]
    path = os.path.join(tempfile.mkdtemp(prefix="pdf_uni_"), "r.pdf")
    export_pdf(evs, path)
    text = "\n".join(p.get_text() for p in fitz.open(path))
    for label, s in SAMPLES.items():
        shown = s in text or all(f"U+{ord(c):04X}" in text for c in s)
        check(f"{label} text is in the PDF (or written as U+XXXX)", shown, repr(s))
    check("channel and file name in Cyrillic are in the event table",
          "Канал" in text and "журнал.evtx" in text)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
