"""The PDF report survives missing fields and markup characters, shows IOC values whole, and chain titles are readable.

Found while fixing Codex RT6-1 (2026-11-06):
  * the PDF event table cut `ev.get("channel", "")[:22]` - a record with no
    Channel (None, 29,109 real records) stopped the whole PDF export;
  * no text was escaped: a rule name, user, description or IOC value holding
    "<" or "&" (e.g. a user "<unknown>", a command line "a & b") is read as
    ReportLab markup - the export fails or the text is altered;
  * IOC values were cut to 80 characters with no marker (a long path or
    command line silently shortened);
  * Codex: chain titles were dark blue (0.06, 0.19, 0.38) on the dark
    severity cards - hard to read.
Expected: the export works; every such value appears exactly, in full; the
chain title colour contrasts with every card (WCAG ratio >= 4.5).
Synthetic data only.  Needs reportlab and PyMuPDF (fitz) to read the text back.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def lum(c):
    def ch(v):
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = c
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def contrast(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


LONG = "C:\\Program Files\\Vendor\\Some Long Product Name\\bin\\x64\\release\\agent-service-host-process.exe"


def main() -> int:
    import pymupdf as fitz
    from evtx_tool.output import exporters as X
    from evtx_tool.output import pdf_exporter as P

    base = {"event_id": 4624, "record_id": 1, "timestamp": "2024-01-02T03:04:05Z", "level": 4,
            "level_name": "Information", "computer": "HOST-A", "channel": "Security",
            "source_file": "C:\\x\\a.evtx", "event_data": {}}
    events = [dict(base, channel=None), dict(base, record_id=2, computer=None, level_name=None,
                                             source_file=None), dict(base, record_id=3)]
    chains = [{"rule_name": "Rule <A> & B", "severity": "high", "tactic": "Execution", "event_count": 2,
               "first_ts": "2024-01-02T03:04:05Z", "last_ts": "2024-01-02T03:05:05Z",
               "description": "cmd /c a & b <script>", "computers": ["HOST-A"], "users": ["<unknown>"],
               "events": []}]
    iocs = {"processes": [LONG, "a&b<c>.exe"], "users": ["<unknown>"]}
    tmp = tempfile.mkdtemp(prefix="pdfrob_")
    try:
        p = os.path.join(tmp, "r.pdf")
        try:
            X.export_pdf(events, p, iocs=iocs, chains=chains)
            text = "".join(pg.get_text() for pg in fitz.open(p))
            flat = " ".join(text.split())
            check("PDF export with no-Channel / no-Computer events works", True)
            check("the chain title with < & shows exactly", "Rule <A> & B" in flat, flat[:0])
            check("the description with < & shows exactly", "cmd /c a & b <script>" in flat)
            check("the user <unknown> shows exactly", "<unknown>" in flat)
            check("an IOC value with & < > shows exactly", "a&b<c>.exe" in flat)
            check("a long IOC value shows whole, not cut at 80 characters",
                  LONG in text.replace("\n", "") or LONG in flat.replace(" ", " "), LONG[78:])
            check("the event table lists all 3 events", flat.count("2024-01-02 03:04:05") >= 3,
                  str(flat.count("2024-01-02 03:04:05")))
        except Exception as e:                              # noqa: BLE001
            check("PDF export with no-Channel / no-Computer events works", False, repr(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    cards = [(0.3, 0.05, 0.05), (0.3, 0.15, 0.02), (0.15, 0.1, 0.0), (0.05, 0.1, 0.2)]
    title = getattr(P, "_C_CHAIN_TITLE", P._C_ACCENT)
    worst = min(contrast(title, c) for c in cards)
    check("chain titles contrast with every severity card (>= 4.5)", worst >= 4.5, f"worst {worst:.2f}")

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
