"""The GUI starts and logs normally with no console (pythonw.exe, a shortcut).

Under pythonw sys.stderr is None.  _setup_gui_logging still added a console
handler on it, so every warning failed inside that handler; logging reported
the failure on stderr -- by then the stderr tee, which logged it as a warning
again -- and the loop ran until RecursionError broke whatever was logging.
The first Qt warning at start-up (offscreen: "Cannot find font directory")
made QLineEdit() return NULL and the installed app exited at once (exit code
1, about 860 "--- Logging error ---" lines).  Expected: with no console, Qt and
Python warnings land in the log file once each, nothing loops, the window's
widgets build.  Run in a subprocess with its own log folder.
"""
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


CHILD = r'''
import sys, logging
sys.stdout = None
sys.stderr = None                      # what pythonw.exe gives the process
sys.path.insert(0, sys.argv[1])
from evtx_tool.gui.app import _setup_gui_logging
_setup_gui_logging()
from PySide6.QtWidgets import QApplication, QLineEdit
from PySide6.QtCore import qWarning
app = QApplication([])
logging.getLogger("probe").warning("PROBE-PYTHON-WARNING")
qWarning("PROBE-QT-WARNING")
for _ in range(20):
    QLineEdit()                        # failed with "returned NULL" after the loop
open(sys.argv[2], "w").write("BUILT")
'''


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="nocon_")
    marker = os.path.join(tmp, "marker.txt")
    env = dict(os.environ, LOCALAPPDATA=tmp, APPDATA=tmp, QT_QPA_PLATFORM="offscreen")
    env.pop("QT_QPA_FONTDIR", None)    # offscreen without fonts: Qt warns at the first widget
    r = subprocess.run([sys.executable, "-c", CHILD, REPO, marker], env=env, capture_output=True,
                       text=True, timeout=120)
    check("the process ends normally", r.returncode == 0, f"exit {r.returncode} {r.stderr[-300:]!r}")
    check("the widgets were built", os.path.isfile(marker) and open(marker).read() == "BUILT")
    logs = os.path.join(tmp, "EventHawk", "logs")
    text = ""
    if os.path.isdir(logs):
        for f in os.listdir(logs):
            with open(os.path.join(logs, f), encoding="utf-8", errors="replace") as fh:
                text += fh.read()
    check("no '--- Logging error ---' loop", text.count("Logging error") == 0,
          f"{text.count('Logging error')} found")
    check("the Python warning is in the log once", text.count("PROBE-PYTHON-WARNING") == 1,
          str(text.count("PROBE-PYTHON-WARNING")))
    check("the Qt warning is in the log once", text.count("PROBE-QT-WARNING") == 1,
          str(text.count("PROBE-QT-WARNING")))
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
