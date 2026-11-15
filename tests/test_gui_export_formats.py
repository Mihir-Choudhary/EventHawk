"""GUI exports: a .json IOC file is JSON; GUI CSV files open in Excel as UTF-8.

Gemini audit 6-10 (Medium): saving IOCs as "x.json" without choosing the STIX
or MISP filter wrote the plain-text list into a .json file; the tactic, IOC
and bookmark CSV writers wrote UTF-8 without the BOM Excel needs, so
non-ASCII names turned into mojibake (the main CSV export has the BOM).

Expected: IOCs saved as .json with the Text filter parse as JSON; the tactic
CSV and the IOC CSV start with the UTF-8 BOM.  Synthetic events.
"""
import json
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QFileDialog, QMessageBox
    QMessageBox.information = staticmethod(lambda *a, **k: None)
    QMessageBox.warning = staticmethod(lambda *a, **k: None)
    out = tempfile.mkdtemp(prefix="guifmt_")
    e = T.ev(r"C:\c\a.evtx", 1, "HÖST", T.T0, 4688, data={"IpAddress": "198.51.100.3"})
    e["attack_tags"] = [{"tactic": "Execution", "tid": "T1059", "name": "x"}]
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    m.load(w, [e])
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    w._iocs = extract_iocs([e])
    pj = os.path.join(out, "i.json")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (pj, "Text — one value per line (*.txt)"))
    w._on_export_iocs_clicked()
    try:
        json.load(open(pj, encoding="utf-8"))
        ok, d = True, ""
    except Exception as x:
        ok, d = False, repr(x)
    check("IOCs saved as .json with the Text filter are JSON", ok, d)
    pc = os.path.join(out, "i.csv")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (pc, "CSV — type + value + score (*.csv)"))
    w._on_export_iocs_clicked()
    check("the IOC CSV has the UTF-8 BOM", os.path.exists(pc) and open(pc, "rb").read(3) == b"\xef\xbb\xbf")
    pt = os.path.join(out, "t.csv")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (pt, ""))
    w._export_tactic_csv("Execution")
    check("the tactic CSV has the UTF-8 BOM", os.path.exists(pt) and open(pt, "rb").read(3) == b"\xef\xbb\xbf")
    T.teardown(w, False, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
