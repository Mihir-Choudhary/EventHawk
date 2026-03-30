"""
EventHawk — Entry point.

Usage:
  py -3 evtx_tool.py parse Logs/ --profile "Logon/Logoff Activity"
  py -3 evtx_tool.py parse Logs/ --event-id 4624,4625 --output results.html
  py -3 evtx_tool.py parse Logs/ --profile "RDP Activity" --profile "Lateral Movement" -o report.json
  py -3 evtx_tool.py profiles list
  py -3 evtx_tool.py profiles show "PowerShell Execution"
  py -3 evtx_tool.py benchmark Logs/
  py -3 evtx_tool.py interactive
  py -3 evtx_tool.py parse Logs/ --help

IMPORTANT: The if __name__ == '__main__' guard is required for ProcessPoolExecutor
on Windows (spawn start method). DO NOT remove it.
"""

import os
import sys
import multiprocessing

# Add this directory to sys.path so 'evtx_tool' package is importable
# in both the main process and spawned worker processes.
_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

if __name__ == "__main__":
    # REQUIRED for PyInstaller + ProcessPoolExecutor on Windows.
    # Must be the very first call inside the __main__ guard.
    multiprocessing.freeze_support()

    from evtx_tool.cli import cli
    cli()
