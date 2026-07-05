"""
EventHawk — standalone GUI entry point.

Compiled by ``EventHawk-standalone.spec`` into a single, fully self-contained
``EventHawk.exe`` that bundles Python, PySide6 (Qt), DuckDB, PyArrow and every
other dependency plus the profile/mapping data files. End users need nothing
installed — no Python, no pip.

This is the opposite of ``launcher.py``: launcher.py is a tiny stub that finds
a *system* Python and re-launches the app, whereas this entry point *is* the
frozen application.
"""

from __future__ import annotations

import multiprocessing
import os
import sys


def _main() -> None:
    # When frozen, the evtx_tool package tree is unpacked under sys._MEIPASS.
    # Make sure it is importable no matter what the current working directory is.
    base = getattr(sys, "_MEIPASS", None) or os.path.dirname(os.path.abspath(__file__))
    if base not in sys.path:
        sys.path.insert(0, base)

    from evtx_tool.gui.app import launch

    # argv[1:] carries any .evtx path passed via Windows "Open with" / drag-drop.
    # Tolerate a leading "gui" token (the CLI convention `evtx_tool.py gui`) so a
    # shortcut/launcher that passes it does NOT turn "gui" into a bogus initial
    # file path — which makes the GUI open and then quit a few seconds later.
    args = sys.argv[1:]
    if args and args[0] == "gui":
        args = args[1:]
    launch(args)


if __name__ == "__main__":
    # MUST be the very first statement: PyInstaller + ProcessPoolExecutor use
    # the 'spawn' start method on Windows, which re-executes this entry point
    # for every worker process. freeze_support() intercepts those re-launches
    # so they run the worker instead of opening another GUI window.
    multiprocessing.freeze_support()
    _main()
