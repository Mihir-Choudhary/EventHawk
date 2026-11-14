"""Seeing a table's whole content without dragging columns, and System Activity.

  A. A clipped cell shows its full text on hover (any item view); a cell that
     fits, or has a tooltip of its own, is left alone.
  B. View > Grid Lines switches cell grid lines for every table, open now or
     later; off by default.
  C. System Activity:
     - the summary groups totals per layer in reading units (exact on hover);
     - split-second periods are hidden by default, the checkbox says how many;
     - durations follow the display precision, the exact value is the cell's
       tooltip and the CSV's;
     - the selected period is shown in full below the table (notes, evidence,
       exact duration).

Run: QT_QPA_PLATFORM=offscreen python tests/test_table_visibility.py
"""
import csv
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QEvent, QPoint, Qt
    from PySide6.QtGui import QHelpEvent
    from PySide6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem, QToolTip
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.system_activity_dialog import SystemActivityDialog

    mw.install_calm_tables(app)

    print("=== A. clipped cells ===")
    long_text = "shutdown logged between 12:05:09 and 12:05:28 by Kernel-General 13 and 12 " * 3
    t = QTableWidget(3, 2)
    t.setItem(0, 0, QTableWidgetItem(long_text))
    t.setItem(1, 0, QTableWidgetItem("short"))
    own = QTableWidgetItem(long_text)
    own.setToolTip("my own tip")
    t.setItem(2, 0, own)
    t.setColumnWidth(0, 120)
    t.resize(400, 200)
    t.show()
    app.processEvents()

    def hover(row):
        QToolTip.hideText()
        app.processEvents()
        rect = t.visualItemRect(t.item(row, 0))
        pos = rect.center()
        ev = QHelpEvent(QEvent.Type.ToolTip, pos, t.viewport().mapToGlobal(pos))
        app.sendEvent(t.viewport(), ev)
        app.processEvents()
        return QToolTip.text() if QToolTip.isVisible() else ""

    check("a cell that fits gets no tooltip", hover(1) == "", hover(1))
    check("a clipped cell shows its full text on hover", hover(0) == long_text, hover(0)[:60])
    check("a cell's own tooltip is kept", hover(2) in ("", "my own tip") and hover(2) != long_text, hover(2))

    print("\n=== B. grid lines ===")
    check("grid lines are off by default", not t.showGrid())
    mw.set_grid_lines(app, True)
    check("View > Grid Lines turns them on for an open table", t.showGrid())
    t2 = QTableWidget(2, 2)
    t2.show()
    app.processEvents()
    check("...and for a table opened later", t2.showGrid())
    mw.set_grid_lines(app, False)
    check("...and off again", not t.showGrid() and not t2.showGrid())
    t.close(); t2.close()

    print("\n=== C. System Activity ===")
    T0 = datetime(2025, 6, 29, 12, 0, tzinfo=timezone.utc)

    def row(state, start_s, dur, layer="Power", notes=""):
        st = T0 + timedelta(seconds=start_s)
        return {"host": "MSI", "layer": layer, "state": state, "start": st, "end": st + dur,
                "duration": dur, "started_by": "Kernel-General 12", "ended_by": "Kernel-Power 507",
                "notes": notes, "start_ev": None, "end_ev": None}
    long_note = "shutdown logged between the two events, no Power-Troubleshooter record " * 2
    rows = [row("On", 0, timedelta(hours=6, minutes=16, seconds=5, microseconds=971314), notes=long_note),
            row("Modern Standby", 30000, timedelta(microseconds=9985)),
            row("On", 30001, timedelta(microseconds=24)),
            row("Sleep", 31000, timedelta(hours=2, minutes=44, seconds=42, microseconds=904999)),
            row("Screen on", 0, timedelta(hours=1), layer="Screen")]
    res = {"hosts": ["MSI"], "rows": rows, "points": []}
    dlg = SystemActivityDialog(res, digits=0)
    dlg.resize(1300, 700)
    dlg.show()
    app.processEvents()
    summ = dlg._lbl_summary.text()
    check("the summary has a Power line and a Screen line",
          "<b>Power</b>" in summ and "<b>Screen</b>" in summ, summ[:160])
    check("...in reading units, no microseconds", "6 h 16 m" in summ and ".971314" not in summ, summ[:200])
    # The On total counts every On period, the hidden 24 µs one too.
    check("...exact totals on hover (every period counted)",
          "Power / On: 6h 16m 05.971338s" in dlg._lbl_summary.toolTip(), dlg._lbl_summary.toolTip())
    check("split-second periods are hidden by default, and counted on the checkbox",
          dlg._tbl.rowCount() == 3 and "(2)" in dlg._chk_short.text(), f"{dlg._tbl.rowCount()} {dlg._chk_short.text()}")
    dlg._chk_short.setChecked(False)
    check("...unticking shows them", dlg._tbl.rowCount() == 5, str(dlg._tbl.rowCount()))
    dlg._chk_short.setChecked(True)
    dlg._tbl.sortItems(3, Qt.SortOrder.AscendingOrder)
    r_on = next(r for r in range(dlg._tbl.rowCount()) if dlg._tbl.item(r, 2).text() == "On")
    dur_cell = dlg._tbl.item(r_on, 5)
    check("durations follow the display precision (seconds)", dur_cell.text() == "6h 16m 05s", dur_cell.text())
    check("...with the exact value on hover", "05.971314" in dur_cell.toolTip(), dur_cell.toolTip())
    out = os.path.join(tempfile.gettempdir(), f"sa_vis_{os.getpid()}.csv")
    dlg.write_csv(out, timeline=True)
    with open(out, encoding="utf-8-sig", newline="") as fh:
        lines = list(csv.reader(fh))
    os.remove(out)
    check("the CSV keeps the exact duration", any("05.971314" in ln[5] for ln in lines[1:]), str(lines[1][5:6]))
    check("with nothing selected the details strip says how to use it",
          "Select a row" in dlg._lbl_details.text())
    dlg._tbl.selectRow(r_on)
    app.processEvents()
    det = dlg._lbl_details.text()
    check("the selected period is shown in full: notes, exact duration",
          long_note.strip()[:60] in det and "6h 16m 05.971314s" in det, det[:120])
    check("the last column (Notes) takes the spare width", dlg._tbl.horizontalHeader().stretchLastSection())
    dlg.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
