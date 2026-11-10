"""IOC CSV export keeps first_seen / last_seen exactly (Codex FO-5).

The CSV writer sliced both to 19 characters: every fraction of a second and
the UTC marker were lost (138 of 138 values on a real case), while the
analysis held them.  Expected: the stored values, unchanged.  Synthetic.
"""
import csv
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtWidgets import QFileDialog, QMessageBox
    import evtx_tool.gui.main_window as mw
    first, last = "2024-01-02T03:04:05.123456Z", "2024-01-03T23:59:59.999999Z"
    w = mw.MainWindow()
    w._iocs = {"ipv4": [{"value": "10.1.2.3", "count": 2, "first_seen": first,
                         "last_seen": last, "score": 40}]}
    path = os.path.join(tempfile.mkdtemp(prefix="ioc_ts_"), "iocs.csv")
    QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (path, ""))
    for n in ("information", "warning", "critical"):
        setattr(QMessageBox, n, staticmethod(lambda *a, **k: QMessageBox.StandardButton.Ok))
    w._warn_blocking = lambda *a, **k: None
    w._on_export_iocs_clicked()
    with open(path, encoding="utf-8-sig") as fh:
        rows = list(csv.DictReader(fh))
    row = rows[0] if rows else {}
    check("first_seen written exactly", row.get("first_seen") == first, row.get("first_seen"))
    check("last_seen written exactly", row.get("last_seen") == last, row.get("last_seen"))
    w.close()
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
