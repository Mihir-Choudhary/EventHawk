"""An event whose Channel (or another text field) is missing renders as an empty cell.

Codex retest 2026-11-06, RT6-1: in Normal mode a real record with no Channel
(the parser stores channel=None) raised AttributeError in EventTableModel.data
(`None.removeprefix`), repeatedly, while the grid painted - the row could not be
read and Normal's exports of that source could not be driven.

Expected: every cell of such an event, in every role, returns without an
exception; the Channel cell is "" (nothing is invented); sorting on every
column, the text search and every export (CSV, JSON, XML, HTML) work and keep
the event.  (The Juggernaut grid already reads a missing value as "": _v.)
Synthetic data only.
"""
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui import models as M

    base = {"event_id": 4624, "record_id": 7, "event_record_id": 7, "timestamp": "2024-01-02T03:04:05.123456Z",
            "level": 4, "level_name": "Information", "computer": "HOST-A", "provider": "Prov",
            "user_id": "", "source_file": "C:\\x\\a.evtx", "keywords": "0x0", "opcode": 0,
            "task": 0, "event_data": {"A": "1"}}
    nulls = dict(base, channel=None)
    all_null = dict(base, channel=None, computer=None, provider=None, user_id=None, level_name=None,
                    keywords=None, log=None)
    good = dict(base, record_id=8, event_record_id=8, channel="Microsoft-Windows-Sysmon/Operational")
    events = [nulls, all_null, good]

    m = M.EventTableModel()
    m.set_events(events)
    roles = [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ForegroundRole, Qt.ItemDataRole.BackgroundRole,
             Qt.ItemDataRole.ToolTipRole, Qt.ItemDataRole.TextAlignmentRole, Qt.ItemDataRole.FontRole,
             Qt.ItemDataRole.UserRole]
    errs = []
    for r in range(m.rowCount()):
        for c in range(m.columnCount()):
            for role in roles:
                try:
                    m.data(m.index(r, c), role)
                except Exception as e:                      # noqa: BLE001
                    errs.append((r, c, int(role), repr(e)))
    check("Normal: every cell of a no-Channel event renders without an error", not errs, str(errs[:3]))
    ch = lambda r: m.data(m.index(r, M.COL_CHANNEL), Qt.ItemDataRole.DisplayRole)
    try:
        check("Normal: the Channel cell of a no-Channel event is empty", ch(0) == "" and ch(1) == "",
              repr((ch(0), ch(1))))
    except Exception as e:                                  # noqa: BLE001
        check("Normal: the Channel cell of a no-Channel event is empty", False, repr(e))
    check("Normal: a present Channel still shows without the Microsoft-Windows- prefix",
          ch(2) == "Sysmon/Operational", repr(ch(2)))

    # The grid really paints it (paint errors print instead of raising: count them).
    from PySide6.QtWidgets import QTableView
    import io, contextlib
    v = QTableView(); v.setModel(m); v.resize(1600, 300)
    buf = io.StringIO()
    old = sys.excepthook
    hits = []
    sys.excepthook = lambda *a: hits.append(a[1])
    with contextlib.redirect_stderr(buf):
        v.show(); app.processEvents(); v.grab(); app.processEvents()
    sys.excepthook = old
    v.close()
    check("Normal: painting the grid raises nothing", not hits and "Error" not in buf.getvalue(),
          (repr(hits[:2]) + buf.getvalue()[-300:]))

    sort_errs = []
    for c in range(m.columnCount()):
        for order in (Qt.SortOrder.AscendingOrder, Qt.SortOrder.DescendingOrder):
            try:
                m.sort(c, order)
            except Exception as e:                          # noqa: BLE001
                sort_errs.append((c, repr(e)))
    check("Normal: sorting on every column works and keeps all 3 events",
          not sort_errs and m.rowCount() == 3, str(sort_errs[:3]))

    try:
        s = M.EventTableModel._build_search_str(all_null)
        check("Normal: the search text of an all-missing event builds", isinstance(s, str))
    except Exception as e:                                  # noqa: BLE001
        check("Normal: the search text of an all-missing event builds", False, repr(e))

    from evtx_tool.output import exporters as X
    tmp = tempfile.mkdtemp(prefix="nullf_")
    try:
        for name, fn, ext in (("CSV", X.export_csv, "csv"), ("JSON", X.export_json, "json"),
                              ("XML", X.export_xml, "xml"), ("HTML", X.export_html, "html")):
            p = os.path.join(tmp, "out." + ext)
            try:
                fn(events, p)
                txt = open(p, encoding="utf-8").read()
                ok = os.path.getsize(p) > 0 and "Sysmon/Operational" in txt
                if name == "JSON":
                    data = json.loads(txt)
                    rows = data if isinstance(data, list) else data.get("events", [])
                    ok = ok and len(rows) == 3
                if name == "CSV":
                    ok = ok and len(txt.strip().splitlines()) == 4
                check(f"export {name} of no-Channel events works and keeps all 3", ok)
            except Exception as e:                          # noqa: BLE001
                check(f"export {name} of no-Channel events works and keeps all 3", False, repr(e))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
