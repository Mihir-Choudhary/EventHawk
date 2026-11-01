"""Separate export writes one file per source, and never overwrites one.

Codex PR review, PR-R2: each output was named after its source's base name
only, so two "Security.evtx" from two machines both went to Security.json and
the second replaced the first, while the message said two files had been
exported.  On two real logs, 966 of 1,537 events were missing from the output
set.  Also: a file already in the chosen folder was silently overwritten.

Expected: every source's events are in the folder, each in its own file; an
existing file is left alone; the message counts the files really written.
Synthetic data only.
"""
import glob
import json
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication, QMessageBox             # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(sf, rid, comp):
    return {"event_id": 4624, "computer": comp, "source_file": sf, "record_id": rid,
            "timestamp": "2024-01-01T00:00:00.000000Z", "provider": "P", "channel": "Security",
            "level": 4, "level_name": "Information", "event_data": {}}


def main() -> int:
    import evtx_tool.gui.main_window as mw
    out_dir = tempfile.mkdtemp(prefix="sep_export_")
    keep = os.path.join(out_dir, "System.json")
    with open(keep, "w", encoding="utf-8") as fh:
        fh.write("an earlier export the analyst kept")
    a, b, c = r"C:\case\HOST-A\Security.evtx", r"C:\case\HOST-B\Security.evtx", r"C:\case\HOST-A\System.evtx"
    w = mw.MainWindow()
    w._per_file_data = {a: {"events": [ev(a, 1, "HOST-A"), ev(a, 2, "HOST-A")]},
                        b: {"events": [ev(b, 1, "HOST-B")]},
                        c: {"events": [ev(c, 7, "HOST-A")]}}
    boxes = []
    mw.QFileDialog.getExistingDirectory = staticmethod(lambda *x, **k: out_dir)
    from PySide6.QtWidgets import QInputDialog
    QInputDialog.getItem = staticmethod(lambda *x, **k: ("JSON", True))
    QMessageBox.information = staticmethod(lambda p, t, text, *x, **k: boxes.append(text))
    QMessageBox.critical = staticmethod(lambda p, t, text, *x, **k: boxes.append("CRITICAL " + text))
    w._export_separate([a, b, c])

    files = sorted(glob.glob(os.path.join(out_dir, "*.json")))
    got = {}
    for f in files:
        if f == keep:
            continue
        data = json.load(open(f, encoding="utf-8"))
        evs = data if isinstance(data, list) else data.get("events", [])
        for e in evs:
            got[(e.get("source_file"), str(e.get("record_id") or e.get("EventRecordID")))] = os.path.basename(f)
    want = {(a, "1"), (a, "2"), (b, "1"), (c, "7")}
    check("every source's events are in the export folder", set(got) == want,
          f"missing {sorted(want - set(got))}")
    fa, fb = got.get((a, "1")), got.get((b, "1"))
    check("the two same-named sources went to two different files",
          fa is not None and fb is not None and fa != fb, f"{fa} / {fb}")
    check("a file already in the folder is not overwritten",
          open(keep, encoding="utf-8").read() == "an earlier export the analyst kept")
    msg = boxes[-1] if boxes else ""
    written = len(set(got.values()))
    check("three files were really written, and the message says 3",
          written == 3 and ("across 3 files" in msg or "3 files" in msg), f"{written} written; {msg[:200]}")
    w.close()

    ok = sum(1 for _n, c_, _d in CHECKS if c_)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c_, d in CHECKS:
        if not c_:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
