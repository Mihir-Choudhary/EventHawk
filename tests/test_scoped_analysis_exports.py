"""With Analysis scope "This File", the tactic and IOC exports export that file.

Gemini audit 6-06 (High): in the separate view with scope "This File" the
ATT&CK and IOC tabs show the active file's tactics and IOCs, but "Export
<Tactic> Events as CSV" and "Export IOCs" took every loaded file's.

Expected: with host A's tab active and scope "This File", the tactic CSV
holds only host A's event and the IOC text export only host A's IP.
Synthetic events.
"""
import csv
import os
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
FA, FB = r"C:\c\hostA\Security.evtx", r"C:\c\hostB\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QFileDialog, QMessageBox
    out = tempfile.mkdtemp(prefix="scoped_")
    QMessageBox.information = staticmethod(lambda *a, **k: None)
    QMessageBox.warning = staticmethod(lambda *a, **k: None)
    tag = [{"tactic": "Execution", "tid": "T1059", "name": "x"}]
    ea = T.ev(FA, 1, "HOST-A", T.T0, 4688, data={"IpAddress": "198.51.100.1"})
    eb = T.ev(FB, 1, "HOST-B", T.T0 + timedelta(seconds=1), 4688, data={"IpAddress": "198.51.100.2"})
    for e in (ea, eb):
        e["attack_tags"] = list(tag)
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    m.load(w, [ea, eb])
    from evtx_tool.analysis.ioc_extractor import extract_iocs
    w._iocs = extract_iocs([ea, eb])
    w._view_mode = "separate"
    w._per_file_data = {FA: {"events": [ea], "search_cache": []}, FB: {"events": [eb], "search_cache": []}}
    w._create_file_tab(FA)
    w._active_file_tab = FA
    w._analysis_scope = "file"
    p = os.path.join(out, "t.csv")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (p, ""))
    w._export_tactic_csv("Execution")
    rows = list(csv.reader(open(p, encoding="utf-8-sig"))) if os.path.exists(p) else []
    txt = open(p, encoding="utf-8-sig").read() if os.path.exists(p) else ""
    check("the tactic CSV holds only the active file's event", "HOST-A" in txt and "HOST-B" not in txt,
          f"{len(rows)} rows")
    p2 = os.path.join(out, "i.txt")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (p2, "Text — one value per line (*.txt)"))
    w._on_export_iocs_clicked()
    t2 = open(p2, encoding="utf-8").read() if os.path.exists(p2) else ""
    check("the IOC export holds only the active file's IP", "198.51.100.1" in t2 and "198.51.100.2" not in t2,
          t2[:120].replace("\n", " "))
    T.teardown(w, False, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
