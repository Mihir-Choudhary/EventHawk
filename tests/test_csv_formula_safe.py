"""CSV and XLSX exports cannot be run as formulas, and no value spills into another cell.

User (2026-11-06): "CSV formula injection, okay. Fix it, but fix it in such a way
that the data does not leak to the other cell, or the data is in proper format".
Event values are attacker-controlled (a command line, a user name, a script
block): a cell starting with = + - @ TAB or CR is run as a formula by Excel /
LibreOffice when the CSV is opened (e.g. =HYPERLINK(...) or a DDE call).

Expected, in every CSV EventHawk writes: such a cell gets ONE leading apostrophe
(the spreadsheet then shows it as text); plain numbers ("-1", "+44", "1e5") and
the lone "-" Windows writes for "no value" are untouched; every other value is
byte-for-byte the same; commas, quotes and line breaks stay inside their cell
(each row reads back with exactly its header's number of cells).  XLSX: a
value starting with "=" is stored as text, not a formula, unchanged.
JSON keeps the exact values.  Synthetic data only.
"""
import csv
import json
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []
NASTY = ['=HYPERLINK("http://x","click")', "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1:A2)", "\t=1+1",
         "\r=1+1", "=cmd,with,\"commas\"\nand a newline"]
SAFE = ["-1", "+44", "1e5", "-0.5", "-", "normal text", "a=b", "", "C:\\Windows\\cmd.exe"]


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def ev(i, value):
    return {"record_id": i + 1, "event_record_id": i + 1, "event_id": 4688, "timestamp": f"2026-01-01T00:00:{i:02d}.000000Z",
            "channel": "Security", "provider": "P", "computer": "WS1", "level": 4, "level_name": "Information",
            "source_file": r"C:\c\Security.evtx", "event_data": {"CommandLine": value}}


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.reader(fh))
    return rows[0], rows[1:]


def main() -> int:
    from evtx_tool.output.exporters import export
    values = NASTY + SAFE
    evs = [ev(i, v) for i, v in enumerate(values)]
    tmp = tempfile.mkdtemp(prefix="csvsafe_")
    try:
        p = os.path.join(tmp, "n.csv")
        export(evs, p, None)
        hdr, rows = read_csv(p)
        col = hdr.index("ED_CommandLine")
        got = [r[col] for r in rows]
        check("Normal CSV: every row has exactly the header's cells (nothing spills over)",
              all(len(r) == len(hdr) for r in rows) and len(rows) == len(values), f"{len(rows)} rows")
        check("Normal CSV: each formula-like value gets one leading apostrophe, otherwise unchanged",
              got[:len(NASTY)] == ["'" + v for v in NASTY], str(got[:3]))
        check("Normal CSV: numbers, '-', and ordinary text are untouched", got[len(NASTY):] == SAFE,
              str(got[len(NASTY):]))
        pj = os.path.join(tmp, "n.json")
        export(evs, pj, None)
        js = json.load(open(pj, encoding="utf-8"))
        check("JSON keeps the exact values", [e["event_data"]["CommandLine"] for e in js] == values)

        # Juggernaut CSV through the GUI's export worker.
        import test_around_pivot as T
        from test_export_parity import jm_export
        from evtx_tool.core.heavyweight.engine import load_arrow_table
        jdir = os.path.join(tmp, "jm")
        os.makedirs(jdir)
        tevs = [T.ev(r"C:\c\Security.evtx", i + 1, "WS1", T.T0, 4688, data={"CommandLine": v})
                for i, v in enumerate(values)]
        table = T.write_jm(tevs, jdir)
        pj2 = os.path.join(tmp, "j.csv")
        errs = jm_export(table, jdir, pj2, "csv")
        hdr, rows = read_csv(pj2)
        col = hdr.index("ED_CommandLine")
        got = {r[hdr.index("RecordNumber")]: r[col] for r in rows}
        want = {str(i + 1): ("'" + v if v in NASTY else v) for i, v in enumerate(values)}
        check("Juggernaut CSV: same protection, same untouched values", not errs and got == want,
              str([(k, got.get(k), want[k]) for k in want if got.get(k) != want[k]][:3]))

        # A dialog CSV (WiFi history) uses the same writer.
        import evtx_tool.gui.main_window as mw
        from PySide6.QtWidgets import QApplication, QFileDialog
        _app = QApplication.instance() or QApplication([])
        from test_wifi_boot_barrier import wlan
        w = [wlan("HOST-Z", 1, 0, 8001, NASTY[0]), wlan("HOST-Z", 2, 60, 8003, NASTY[0])]
        d = mw._WifiHistoryDialog(w)
        pw = os.path.join(tmp, "wifi.csv")
        from PySide6.QtWidgets import QMessageBox
        real = (QFileDialog.getSaveFileName, QMessageBox.information, QMessageBox.critical)
        QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (pw, "CSV (*.csv)"))
        QMessageBox.information = staticmethod(lambda *a, **k: None)     # no modal box offscreen
        QMessageBox.critical = staticmethod(lambda *a, **k: print("  export error box:", a[2:3]))
        try:
            d._on_export_csv()
        finally:
            QFileDialog.getSaveFileName, QMessageBox.information, QMessageBox.critical = real
        hdr, rows = read_csv(pw)
        check("WiFi dialog CSV: the SSID cell is protected", rows and rows[0][0] == "'" + NASTY[0],
              str(rows[0][:1] if rows else rows))
        d.close()

        # XLSX (PowerShell timeline): '=' text is stored as text, not as a formula.
        from openpyxl import Workbook, load_workbook
        from evtx_tool.output.exporters import xlsx_text_cells
        wb = Workbook(); ws = wb.active
        ws.append([NASTY[0], "-1", "plain"])
        xlsx_text_cells(ws[1])
        px = os.path.join(tmp, "t.xlsx"); wb.save(px)
        c = load_workbook(px).active["A1"]
        check("XLSX: '=' value stored as text with the exact value", c.data_type == "s" and c.value == NASTY[0],
              f"{c.data_type} {c.value!r}")
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
