"""Export details: "n/a" vs 0, IOC section without a summary, XML paths, file order.

Gemini audit 6-03 (Medium): the HTML report showed "0" Attack Chains / IOCs
when correlation or IOC extraction had not been run -- read as "none found".
Gemini audit 6-18 (Low): the HTML IOC section counted only iocs["summary"];
category lists without one left the whole section out.
Gemini audit 6-08 (Medium): XML export raised TypeError on a None source_file
and wrote only the file name, unlike CSV/JSON.
Gemini audit 6-16 (Medium): "Specific files -> Into one file" took the files in
set order and concatenated them, so events came out in per-file blocks in a
different order each run.

Expected: "n/a" for not-run analyses; the IOC section present from category
lists; XML with a None source_file completes and has the full path otherwise;
the one-file export is chronological across files.  Synthetic events.
"""
import json
import os
import re
import shutil
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
    from evtx_tool.output import exporters as X
    d = tempfile.mkdtemp(prefix="exm_")
    try:
        ev = dict(T.ev(FA, 1, "H", T.T0, 4624))
        p = os.path.join(d, "a.html")
        X.export_html([ev], p, chains=None, iocs=None)
        html = open(p, encoding="utf-8").read()
        check("not-run correlation / IOCs read n/a, not 0",
              "<div class='num'>n/a</div><div class='label'>Attack Chains" in html
              and "<div class='num'>n/a</div><div class='label'>IOCs Extracted" in html)
        iocs = {"ipv4": [{"value": "198.51.100.7", "count": 1, "first_seen": "", "last_seen": "", "score": 0}]}
        X.export_html([ev], p, chains=[], iocs=iocs)
        html = open(p, encoding="utf-8").read()
        check("the IOC section is there without a summary", "198.51.100.7" in html and "ioc-section" in html)
        px = os.path.join(d, "a.xml")
        try:
            X.export([dict(ev, source_file=None)], px, fmt="xml")
            err = ""
        except Exception as e:
            err = repr(e)
        check("XML with a None source_file completes", not err, err)
        X.export([ev], px, fmt="xml")
        check("XML writes the full source path", FA in open(px, encoding="utf-8").read())
    finally:
        shutil.rmtree(d, ignore_errors=True)

    import evtx_tool.gui.main_window as mw
    from PySide6.QtWidgets import QFileDialog, QMessageBox, QDialog
    out = os.path.join(tempfile.mkdtemp(prefix="exm2_"), "one.json")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, ""))
    mw._export_save_path = lambda *a, **k: (out, "json")
    QMessageBox.information = staticmethod(lambda *a, **k: None)

    class FakeScope:
        def __init__(self, *a, **k):
            pass

        def exec(self):
            return QDialog.DialogCode.Accepted

        def selected_scope(self):
            return "specific"

        def selected_files(self):
            return [FB, FA]

        def selected_format(self):
            return "json"

        def specific_separate(self):
            return False

        def available_formats(self):
            return ["json"]
    mw._ExportScopeDialog = FakeScope
    evs = [T.ev(FA if i % 2 == 0 else FB, i + 1, "H", T.T0 + timedelta(seconds=i), 4624) for i in range(6)]
    w = mw.MainWindow()
    m = T.Mode(mw, False)
    m.load(w, evs)
    w._warn_blocking = lambda *a, **k: None
    w._on_export_clicked()
    import time
    t0 = time.monotonic()
    while not os.path.exists(out) and time.monotonic() - t0 < 20:
        T.pump(200)
    T.pump(500)
    got = [e["timestamp"] for e in json.load(open(out, encoding="utf-8"))] if os.path.exists(out) else []
    check("Specific files -> one file is one time line across files", got == sorted(got) and len(got) == 6,
          f"{len(got)} events")
    T.teardown(w, False, m)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
