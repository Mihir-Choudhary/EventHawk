#!/usr/bin/env bash
# EventHawk launcher (Linux/macOS).
#
# Uses the project virtualenv in .venv rather than the system Python.
# Why a venv and not the system Python, on Debian/Ubuntu:
#   1. The distro "PySide6" in /usr/lib/python3/dist-packages is only a
#      NAMESPACE STUB -- it ships no QtWidgets/QtCore. Those live in separate
#      apt packages (python3-pyside6.qtwidgets, .qtcore, .qtgui, ...).
#   2. Installing PySide6 from pip alongside it puts a second copy in ~/.local
#      that needs a different shiboken6 version than the distro one. Only one
#      shiboken6 can exist, so each install breaks the other and the app will
#      not start either way. --break-system-packages does not fix this; it
#      just flips which half is broken, and damages the distro Python.
# A venv ignores ~/.local entirely and pins one matched PySide6 + shiboken6.
#
# To run against the SYSTEM python instead, install the Qt modules from apt:
#   sudo apt install python3-pyside6.qtcore python3-pyside6.qtwidgets \
#                    python3-pyside6.qtgui
#
#   ./run.sh            → launch the GUI
#   ./run.sh --cli ...  → run the CLI (evtx_tool.py) with the given arguments
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "No .venv found — creating one and installing requirements…"
    # pip comes from the interpreter itself (ensurepip): no script is
    # downloaded and run (Gemini audit 13-04).
    if ! python3 -m venv .venv; then
        rm -rf .venv
        echo "Could not create a virtual environment with pip." >&2
        echo "On Debian / Ubuntu install it first:  sudo apt install python3-venv" >&2
        exit 1
    fi
    ./.venv/bin/python -m pip install -q -r requirements.txt
    echo "Dependencies installed."
fi

if [ "${1:-}" = "--cli" ]; then
    shift
    exec ./.venv/bin/python evtx_tool.py "$@"
fi
exec ./.venv/bin/python eventhawk_gui.py "$@"
