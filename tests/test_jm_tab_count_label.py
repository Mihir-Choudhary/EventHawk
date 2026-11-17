"""A filtered Juggernaut per-file tab says "shown / total" (Gemini 5-12).

In Juggernaut separate tabs the count of a file tab gave only the rows its
filters leave ("3 events"), never against the file's own total, so a narrowed
tab looked like the whole file. Merged view and Normal mode say "3 / 10 events".
Expected: a file tab says "<shown> / <file total> events" when filtered and
"<file total> events" when not; the file total is that file's rows, not the
whole dataset's. Synthetic data only.
"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
A, B = r"C:\synthetic\A\Security.evtx", r"C:\synthetic\B\System.evtx"
BASE = datetime(2024, 1, 1, tzinfo=timezone.utc)


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    evs = [T.ev(A, i + 1, "H1", BASE + timedelta(seconds=i), 4624 if i < 3 else 4688) for i in range(7)]
    evs += [T.ev(B, i + 1, "H1", BASE + timedelta(seconds=i), 7036) for i in range(5)]
    m = T.Mode(mw, True)
    w = mw.MainWindow()
    m.load(w, evs)
    w._jm_pending = getattr(w, "_jm_pending", {}) or {}
    w._jm_pending[A] = w._hw_model._full_table
    w._open_jm_file_tab(A)
    T.pump(300)
    fp = next((k for k in w._file_tabs if k == A), None)
    check("a per-file tab for file A opened", fp is not None, str(list(w._file_tabs)))
    if fp is not None:
        w._active_file_tab = A
        st = w._file_tabs[A]
        T.wait_for(lambda: st.model._total_rows == 7, 10)
        w._update_count_label_text()
        check("unfiltered: the file's own total", w._lbl_count.text() == "7 events", w._lbl_count.text())
        st.model.set_quick_filters([{"key": "event_id", "value": "4624", "include": True}])
        T.wait_for(lambda: st.model._total_rows == 3, 10)
        T.pump(200)
        w._update_count_label_text()
        check("filtered: shown / the file's total", w._lbl_count.text() == "3 / 7 events", w._lbl_count.text())
    w.close()
    T.pump(200)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    tempfile.tempdir = None
    sys.exit(main())
