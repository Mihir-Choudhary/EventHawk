"""A missing value is not the text "None" in a Normal-mode quick filter.

Gemini audit 3-14 (Medium): the Normal view's quick filter read a field
with value None as str(None) = "none", so "User = None" matched both the
event whose user is the literal text "None" and every event with no user,
while Juggernaut's SQL (NULL is not 'none') matched only the first.

Expected, Normal view: "User = None" keeps only the literal-"None" event;
"User ≠ None" keeps the event with no user (as Juggernaut does).
Synthetic events.
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
    from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
    base = {"event_id": 1, "level": 4, "level_name": "Information", "channel": "C", "computer": "H",
            "provider": "P", "timestamp": "2026-01-01T00:00:00.000000Z", "event_data": {}, "source_file": "f.evtx"}
    evs = [dict(base, record_id=1, user_id=None), dict(base, record_id=2, user_id="None")]

    def rows(include):
        src = EventTableModel()
        src.set_events([dict(e) for e in evs])
        px = EventFilterProxyModel()
        px.setSourceModel(src)
        px.add_quick_filter("user_id", "None", include)
        return sorted(src.get_event(px.mapToSource(px.index(r, 0)).row())["record_id"] for r in range(px.rowCount()))
    check("'User = None' keeps only the literal 'None' event", rows(True) == [2], str(rows(True)))
    check("'User ≠ None' keeps the event with no user", rows(False) == [1], str(rows(False)))
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
