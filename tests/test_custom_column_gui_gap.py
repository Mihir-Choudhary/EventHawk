"""Adding a computed custom column does not freeze the Juggernaut window.

Codex audit-5 E5-12: after a custom column was computed in the background, the
window still froze for 0.92 s on 1.84 M rows, because the GUI thread turned
the computed values into Arrow arrays and computed every row's sort key there.

Expected: the worker hands over ready arrays (ArrowTableModel.
prepare_custom_values), so the GUI thread's add_custom_column /
update_custom_column takes a few milliseconds; the grid shows the same values
and sorts by the same keys as before.  Synthetic data only.
"""
import os
import shutil
import sys
import tempfile
import time
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


N = 600_000


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    _app = QApplication.instance() or QApplication([])
    from evtx_tool.core.custom_columns import CustomColumnSpec, compile_spec, sort_key_text
    from evtx_tool.gui.heavyweight_model import ArrowTableModel
    from evtx_tool.gui.models import COLUMNS

    evs = [T.ev(r"C:\a\Security.evtx", i + 1, "HOST", T.T0 + timedelta(milliseconds=i)) for i in range(N)]
    tmp = tempfile.mkdtemp(prefix="ccgap_")
    try:
        table = T.write_jm(evs, tmp)
        m = ArrowTableModel(table, parquet_dir=tmp)
        T.wait_for(lambda: m.rowCount() == N, 60)
        values = [str((i * 7919) % 1000) if i % 5 else "" for i in range(N)]
        for kind in ("text", "int"):
            c = compile_spec(CustomColumnSpec(col_id=1 if kind == "text" else 2, title=kind,
                                              template="{Data[1]}", kind=kind))
            prep = getattr(ArrowTableModel, "prepare_custom_values", None)
            ready = prep(c, values) if prep else values
            t0 = time.perf_counter()
            idx = m.add_custom_column(c, ready)
            dt = time.perf_counter() - t0
            check(f"{kind}: adding the column on the GUI thread takes under 50 ms",
                  prep is not None and dt < 0.05, f"{dt * 1000:.0f} ms")
            t = m._full_table
            got_v = t.column(f"cc_{c.spec.col_id}").to_pylist()
            got_s = t.column(f"cc_{c.spec.col_id}_s").to_pylist()
            check(f"{kind}: every value and sort key as computed",
                  got_v == values and got_s == [sort_key_text(v, kind) for v in values], "")
            T.wait_for(lambda: m._filter_thread._q.empty(), 60)
            T.pump(300)
            shown = m.data(m.index(1, idx), Qt.ItemDataRole.DisplayRole)
            check(f"{kind}: the grid shows the value", shown == values[1], repr(shown))
        c2 = compile_spec(CustomColumnSpec(col_id=1, title="text2", template="{Data[2]}"))
        v2 = [v + "!" for v in values]
        prep = getattr(ArrowTableModel, "prepare_custom_values", None)
        ready = prep(c2, v2) if prep else v2
        t0 = time.perf_counter()
        m.update_custom_column(1, c2, ready)
        dt = time.perf_counter() - t0
        check("editing a column on the GUI thread takes under 50 ms", prep is not None and dt < 0.05,
              f"{dt * 1000:.0f} ms")
        check("...and holds the new values", m._full_table.column("cc_1").to_pylist() == v2, "")
        check("column count unchanged by the edit", m.columnCount() == len(COLUMNS) + 2, str(m.columnCount()))
        m.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
