"""Normal-mode column values: the hour level is filled; no always-empty Session ID popup.

Gemini audit 3-18 (Medium): NormalColValueWorker.run() handled
"timestamp_date" but not "timestamp_hour" (its own _ev_val handles both), so
asking it for hours read ev["timestamp_hour"] -- absent -- and returned
nothing.  Session ID (column 15) was offered as a filterable column though
no parser fills session_id, so its popup was always empty.  The cascade
helper also read a missing value as the text "none".

Expected: the worker returns one hour bucket per distinct hour; column 15 is
not offered as filterable; _ev_val reads None as "".  Synthetic events.
"""
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QApplication
    QApplication.instance() or QApplication([])
    from evtx_tool.gui.jm_col_worker import NormalColValueWorker
    evs = [{"record_id": i, "timestamp": f"2026-01-01T{h:02d}:05:00.000000Z", "event_id": 1, "user_id": None}
           for i, h in enumerate((1, 1, 2, 5))]
    w = NormalColValueWorker(evs, "timestamp_hour")
    out = []
    w.finished.connect(lambda v: out.append(v))
    w.run()
    vals = out[0] if out else {}
    keys = list(vals.keys()) if hasattr(vals, "keys") else []
    check("the hour level has one bucket per distinct hour (3)", len(keys) == 3, str(keys))
    from evtx_tool.gui.main_window import ColumnFilterPopup
    check("Session ID (col 15) is not offered as a filterable column", 15 not in ColumnFilterPopup.FILTERABLE)
    check("the cascade helper reads a missing value as ''",
          NormalColValueWorker._ev_val({"user_id": None}, "user_id") == "",
          repr(NormalColValueWorker._ev_val({"user_id": None}, "user_id")))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
