"""JM: a filter that has not produced its first result counts as pending (Codex RA-3).

filter_pending() compared the request generation with the last finished one,
defaulting the finished one to the CURRENT generation while no filter had ever
finished: before the first result it said "not pending", so a current-view
export wrote the whole unfiltered table (10 rows written, 4 requested).
Expected: until the requested filter's result arrives, filter_pending() is
True (main and per-file models) and a current-view export writes no file and
says so; afterwards the export holds exactly the requested events.  Synthetic.
"""
import json
import os
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import test_around_pivot as T                                       # noqa: E402
from test_jm_export_text_filter import write_jm                     # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QDialog, QFileDialog
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.core.filters import empty_filter, passes_filter

    words = ["alpha", "beta", "alpha gamma", "delta", "gamma"]
    evs = [T.ev(r"C:\a\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i),
                data={"Msg": words[i % len(words)]}) for i in range(10)]
    cfg = dict(empty_filter(), text_search=["alpha"], search_mode="AND")
    want = sorted(e["record_id"] for e in evs if passes_filter(e, cfg))
    tmp = tempfile.mkdtemp(prefix="jm_first_")
    table = write_jm(evs, tmp)

    # Model level: no event-loop turn between construction and the request,
    # so no filter result can have arrived yet.
    m = ArrowTableModel(table, parquet_dir=tmp)
    m.apply_filter(cfg)
    check("main model: first filter not yet done -> pending", m.filter_pending())
    T.wait_for(lambda: m.rowCount() == len(want), 30); T.pump(200)
    check("main model: after the result -> not pending, view = request",
          not m.filter_pending() and m.rowCount() == len(want), f"{m.rowCount()} vs {len(want)}")
    m.close()
    pf = ArrowTableModel(table, parquet_dir=tmp, fixed_where="source_file = ?",
                         fixed_params=[evs[0]["source_file"]])
    check("per-file model: before its first result -> pending", pf.filter_pending())
    pf.close()

    # Real export path: Export (current view) right after the request.
    w = mw.MainWindow()
    mode = T.Mode(mw, True)
    mode.load(w, table=table, parquet_dir=tmp)
    w._table.setModel(w._hw_model)
    msgs = []
    w._warn_blocking = lambda title, text, **k: msgs.append(text)

    class _Scope(mw._ExportScopeDialog):
        def exec(self):
            self._rb_view.setChecked(True)
            self._fmt_buttons["json"].setChecked(True)
            self._on_ok()
            return QDialog.DialogCode.Accepted

    real = (mw._ExportScopeDialog, QFileDialog.getSaveFileName, mw.QMessageBox.information)
    out = tempfile.mkdtemp(prefix="jm_first_out_")
    notices = []
    mw._ExportScopeDialog = _Scope
    mw.QMessageBox.information = staticmethod(lambda *a, **k: notices.append(a[2] if len(a) > 2 else ""))
    try:
        fresh = ArrowTableModel(table, parquet_dir=tmp)
        w._hw_model = fresh
        w._table.setModel(fresh)
        early = os.path.join(out, "early.json")
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (early, ""))
        fresh.apply_filter(cfg)
        w._export_juggernaut()
        T.pump(500)
        check("export before the first result: no file written, user told to wait",
              not os.path.exists(early) and notices, f"file={os.path.exists(early)} notices={len(notices)}")
        T.wait_for(lambda: fresh.rowCount() == len(want), 30); T.pump(200)
        late = os.path.join(out, "late.json")
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (late, ""))
        n0 = len(msgs)
        w._export_juggernaut()
        T.wait_for(lambda: len(msgs) > n0 and os.path.exists(late), 60); T.pump(200)
        try:
            with open(late, encoding="utf-8") as fh:
                data = json.load(fh)
            got = sorted(int(e["record_id"]) for e in (data.get("events", data) if isinstance(data, dict) else data))
        except Exception as exc:                                  # noqa: BLE001
            got = repr(exc)
        check("export after the result = exactly the requested events", got == want, f"{got} vs {want}")
    finally:
        mw._ExportScopeDialog, QFileDialog.getSaveFileName, mw.QMessageBox.information = real
        w.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    sys.exit(main())
