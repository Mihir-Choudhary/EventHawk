"""Smoke test of a built EventHawk standalone folder (portable or installed).

Run it with THAT folder's own Python, so the check covers what ships, not the
checkout or a system Python:

    <folder>\\python.exe scripts\\smoke_standalone.py <folder> <log.evtx> <record count> <version>

<record count> comes from an independent reader (the release workflow takes it
from Windows' Get-WinEvent).  Checks, each fatal:
  1. the app's code and packages load from <folder> (not from anywhere else);
  2. the CLI reports <version>, and the Sentinel CLI starts;
  3. a CLI parse of <log.evtx> writes exactly <record count> events;
  4. a Juggernaut parse (worker processes of this Python) holds the same count;
  5. the main window opens and closes (offscreen).
Exit code 0 only when all pass.
"""
import csv
import multiprocessing
import os
import subprocess
import sys
import tempfile


def fail(msg: str) -> None:
    print(f"SMOKE FAIL: {msg}", flush=True)
    sys.exit(1)


def main() -> None:
    folder, log, expected, version = (os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2]),
                                      int(sys.argv[3]), sys.argv[4])
    os.chdir(folder)
    if folder not in [os.path.abspath(p) for p in sys.path]:
        sys.path.insert(0, folder)
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    py = sys.executable
    if os.path.dirname(os.path.abspath(py)).lower() != folder.lower():
        fail(f"run this with the folder's own python.exe, not {py}")

    # 1. everything loads from the folder
    import evtx_tool, sentinel, PySide6, duckdb, pyarrow, evtx  # noqa: F401,E401
    for mod in (evtx_tool, sentinel, PySide6, duckdb, pyarrow, evtx):
        where = os.path.abspath(mod.__file__)
        if not where.lower().startswith(folder.lower()):
            fail(f"{mod.__name__} loaded from outside the folder: {where}")
    print("ok  packages load from the folder", flush=True)

    # 2. CLI version, Sentinel CLI
    out = subprocess.run([py, "evtx_tool.py", "--version"], capture_output=True, text=True, timeout=120)
    if out.returncode != 0 or version not in out.stdout:
        fail(f"evtx_tool.py --version: exit {out.returncode}, output {out.stdout!r} {out.stderr[-300:]!r}")
    out = subprocess.run([py, "-m", "sentinel.cli", "--help"], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        fail(f"sentinel.cli --help: exit {out.returncode} {out.stderr[-300:]!r}")
    print(f"ok  CLI reports {version}; Sentinel CLI starts", flush=True)

    # 3. CLI parse to CSV
    tmp = tempfile.mkdtemp(prefix="eh_smoke_")
    csv_path = os.path.join(tmp, "out.csv")
    out = subprocess.run([py, "evtx_tool.py", "parse", log, "-o", csv_path, "--format", "csv", "--no-tui"],
                         capture_output=True, text=True, timeout=900)
    if out.returncode != 0 or not os.path.isfile(csv_path):
        fail(f"CLI parse: exit {out.returncode} {out.stderr[-500:]!r}")
    with open(csv_path, encoding="utf-8-sig", newline="") as fh:
        rows = sum(1 for _ in csv.DictReader(fh))
    if rows != expected:
        fail(f"CLI parse wrote {rows} events, the log holds {expected}")
    print(f"ok  CLI parse: {rows} of {expected} events", flush=True)

    # 4. Juggernaut parse
    from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
    pq_dir = os.path.join(tmp, "jm")
    os.makedirs(pq_dir)
    table = load_arrow_table(HeavyweightEngine(parquet_dir=pq_dir).run([log]))
    if table.num_rows != expected:
        fail(f"Juggernaut parse holds {table.num_rows} events, the log holds {expected}")
    print(f"ok  Juggernaut parse: {table.num_rows} of {expected} events", flush=True)

    # 5. main window
    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QApplication
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, os.path.join(tmp, "settings"))
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow
    w = MainWindow()
    w.show()
    app.processEvents()
    w.close()
    app.processEvents()
    print("ok  main window opens and closes", flush=True)
    print("SMOKE PASS", flush=True)


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()
