#!/usr/bin/env bash
# EventHawk launcher (Linux/macOS).
#
# Uses the project virtualenv in .venv rather than the system Python.
# On Debian/Ubuntu the system Python often carries TWO PySide6 installs --
# the distro one in /usr/lib/python3/dist-packages and a pip --user one in
# ~/.local -- which need different, mutually exclusive shiboken6 versions.
# Installing either one breaks the other, so the app cannot start. A venv
# sidesteps that entirely: it ignores ~/.local and pins one matched set.
#
#   ./run.sh            → launch the GUI
#   ./run.sh --cli ...  → run the CLI (evtx_tool.py) with the given arguments
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
    echo "No .venv found — creating one and installing requirements…"
    python3 -m venv --without-pip .venv
    curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/eventhawk-get-pip.py
    ./.venv/bin/python /tmp/eventhawk-get-pip.py -q
    ./.venv/bin/python -m pip install -q -r requirements.txt
    echo "Dependencies installed."
fi

if [ "${1:-}" = "--cli" ]; then
    shift
    exec ./.venv/bin/python evtx_tool.py "$@"
fi
exec ./.venv/bin/python eventhawk_gui.py "$@"
