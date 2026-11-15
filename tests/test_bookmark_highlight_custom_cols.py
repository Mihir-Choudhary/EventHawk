"""Bookmark highlighting repaints custom columns too.

Gemini audit 5-11 (Low): set_bookmark_highlights told the view to repaint up
to the last BUILT-IN column, so a custom column kept its old background when
a bookmark was added or removed.  (The Bookmarks tab's own times already
follow the display zone.)

Expected, both models: with one custom column, the dataChanged range after
set_bookmark_highlights reaches the last column (columnCount() - 1).
Synthetic events.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    import test_around_pivot as T
    from datetime import timedelta
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec
    from evtx_tool.gui.models import compute_custom_values
    from evtx_tool.gui.models import EventTableModel
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    evs = [T.ev(r"C:\a\Security.evtx", i + 1, "HOST", T.T0 + timedelta(seconds=i)) for i in range(3)]
    c = compile_spec(CustomColumnSpec(col_id=1, title="x", template="{EventID}", kind="text"))
    nm = EventTableModel()
    nm.set_events([dict(e) for e in evs])
    nm.add_custom_column(c, compute_custom_values(c, nm._events))
    tmp = tempfile.mkdtemp(prefix="bmhl_")
    try:
        jm = ArrowTableModel(T.write_jm(evs, tmp), parquet_dir=tmp)
        T.wait_for(lambda: jm.rowCount() == 3, 30)
        prep = ArrowTableModel.prepare_custom_values(c, [str(e["event_id"]) for e in evs])
        jm.add_custom_column(c, prep)
        T.pump(300)
        for label, m in (("Normal", nm), ("Juggernaut", jm)):
            spans = []
            m.dataChanged.connect(lambda tl, br, *a: spans.append(br.column()))
            m.set_bookmark_highlights({(r"C:\a\Security.evtx", 1)})
            check(f"{label}: the repaint reaches the custom column", spans and max(spans) == m.columnCount() - 1,
                  f"{spans} vs last {m.columnCount() - 1}")
        jm.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
