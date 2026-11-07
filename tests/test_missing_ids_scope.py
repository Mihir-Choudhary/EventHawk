"""Identify Missing Record IDs covers the same files in both modes (Codex C3-2).

From a file tab, Normal analysed that file; Juggernaut analysed every loaded
file (real: 1 section vs 100, 235,397,422 vs 471,436,736 missing XML IDs).
Expected: a file tab -> that file only, in both modes; All Events -> every file.
Synthetic data only.
"""
import os
import sys
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import pyarrow as pa
    import evtx_tool.gui.main_window as mw
    rows = [("a.evtx", i) for i in (1, 2, 5)] + [("b.evtx", i) for i in (10, 20)]
    table = pa.table({"source_file": [r[0] for r in rows], "record_id": [r[1] for r in rows]})
    got = {}

    class FakeDlg:
        def __init__(self, **kw):
            got.clear()
            got.update(kw)

        def exec(self):
            pass
    mw._MissingRecordIdDialog = FakeDlg
    w = mw.MainWindow()
    front = {"model": None}
    type(w)._active_table = property(lambda self: SimpleNamespace(model=lambda: front["model"]))
    w._hw_model = SimpleNamespace(_full_table=table)

    front["model"] = SimpleNamespace(_full_table=table, _fixed_where_sql="source_file = ?", _fixed_params=["a.evtx"])
    w._on_identify_missing_record_ids()
    secs = got.get("sections", [])
    check("Juggernaut, file tab a.evtx: only that file is analysed",
          len(secs) == 1 and "a.evtx" in secs[0] and "b.evtx" not in "".join(secs), str(secs)[:200])
    # Codex C3-R1: an Around tab (a fixed time/host filter on the same table)
    # is its own scope too: here the window holds a.evtx records 1 and 2 only.
    front["model"] = SimpleNamespace(_full_table=table, _fixed_where_sql="record_id BETWEEN ? AND ?",
                                     _fixed_params=[1, 2])
    w._on_identify_missing_record_ids()
    secs = got.get("sections", [])
    check("Juggernaut, an Around tab: only the files and records in its window",
          len(secs) == 1 and "a.evtx" in secs[0] and "Events: 2" in secs[0], str(secs)[:200])
    front["model"] = w._hw_model
    w._on_identify_missing_record_ids()
    secs = got.get("sections", [])
    check("Juggernaut, All Events: every file", len(secs) == 2, str(len(secs)))
    w._hw_model = None
    w.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
