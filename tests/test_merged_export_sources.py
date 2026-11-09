"""Per-source export works from the merged view too (Normal mode).

Codex audit-5b A5B-MERGED-EXPORT: after a parse in "Merge All" view, Export >
All files separate wrote 0 files / 0 events (real corpus: expected 36 files,
130,889 events, all four formats) and said "Exported 0 events across 0 files".
The per-source map the export reads is filled only when the view is Separate;
the same empty map also left "Specific files" with nothing to choose.

Expected: the same files and events as from the Separate view, and Specific
files lists every source.  Synthetic data only.
"""
import glob
import json
import os
import sys
import tempfile
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication, QDialog, QMessageBox    # noqa: E402

app = QApplication.instance() or QApplication([])
CHECKS = []
A, B, C = r"C:\case\HOST-A\Security.evtx", r"C:\case\HOST-B\Security.evtx", r"C:\case\HOST-A\System.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(sf, rid, comp):
    return {"event_id": 4624, "computer": comp, "source_file": sf, "record_id": rid,
            "timestamp": f"2024-01-01T00:00:{rid:02d}.000000Z", "provider": "P", "channel": "Security",
            "level": 4, "level_name": "Information", "event_data": {}}


def events():
    return [ev(A, 1, "HOST-A"), ev(B, 1, "HOST-B"), ev(A, 2, "HOST-A"), ev(C, 7, "HOST-A")]


def exported(out_dir):
    got = {}
    for f in sorted(glob.glob(os.path.join(out_dir, "*.json"))):
        data = json.load(open(f, encoding="utf-8"))
        evs = data if isinstance(data, list) else data.get("events", [])
        for e in evs:
            got[(e.get("source_file"), str(e.get("record_id") or e.get("EventRecordID")))] = os.path.basename(f)
    return got


def run(mw, view_mode, scope):
    out_dir = tempfile.mkdtemp(prefix=f"merged_export_{view_mode}_{scope}_")
    w = mw.MainWindow()
    w._view_mode = view_mode
    w._last_parsed_files = [A, B, C]
    w._parse_start_ts = time.monotonic()
    w._on_parse_finished(events(), None, False, False, None)
    for _ in range(20):
        app.processEvents()

    seen = {}

    class FakeScope(QDialog):
        def __init__(self, all_file_paths=None, **k):
            super().__init__()
            seen["paths"] = sorted(all_file_paths or [])

        def exec(self):
            return QDialog.DialogCode.Accepted

        def selected_scope(self):
            return scope

        def selected_files(self):
            return {A, C}

        def specific_separate(self):
            return True

        def selected_format(self):       # chosen in the dialog (was a JSON prompt)
            return "json"

    real = mw._ExportScopeDialog
    mw._ExportScopeDialog = FakeScope
    boxes = []
    try:
        mw.QFileDialog.getExistingDirectory = staticmethod(lambda *x, **k: out_dir)
        from PySide6.QtWidgets import QInputDialog
        QInputDialog.getItem = staticmethod(lambda *x, **k: ("JSON", True))
        QMessageBox.information = staticmethod(lambda p, t, text, *x, **k: boxes.append(text))
        QMessageBox.warning = staticmethod(lambda p, t, text, *x, **k: boxes.append("WARN " + text))
        QMessageBox.critical = staticmethod(lambda p, t, text, *x, **k: boxes.append("CRIT " + text))
        w._on_export_clicked()
    finally:
        mw._ExportScopeDialog = real
    got = exported(out_dir)
    w.close()
    return seen.get("paths", []), got, boxes


def main() -> int:
    import evtx_tool.gui.main_window as mw
    want_all = {(A, "1"), (A, "2"), (B, "1"), (C, "7")}
    want_specific = {(A, "1"), (A, "2"), (C, "7")}
    for view in ("separate", "merged"):
        paths, got, boxes = run(mw, view, "separate")
        check(f"{view} view: the export dialog lists all three sources", paths == sorted([A, B, C]), str(paths))
        check(f"{view} view: All files separate writes every event, one file per source",
              set(got) == want_all and len(set(got.values())) == 3,
              f"{len(got)} events in {len(set(got.values()))} files; {boxes[-1:]}")
        paths, got, boxes = run(mw, view, "specific")
        check(f"{view} view: Specific files (separate) writes the chosen sources' events",
              set(got) == want_specific and len(set(got.values())) == 2,
              f"{len(got)} events in {len(set(got.values()))} files; {boxes[-1:]}")
    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
