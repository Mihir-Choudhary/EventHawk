"""
Where EventHawk's log files live, and the log sink for worker processes.

Every process writes under one folder the user can open from Help > Open Log
Folder: ``%LOCALAPPDATA%\\EventHawk\\logs`` (then %APPDATA%, then the temp
folder).  It used to be split: the GUI wrote there, the analysis worker wrote
to ``evtx_tool_logs`` beside the code (read-only under Program Files), and the
parse worker processes wrote nowhere, so a warning raised in one was lost
whenever the app ran without a console.

Files:
  eventhawk_gui.log       GUI process, INFO and above (rotating, 5 MB x 4)
  eventhawk_analysis.log  analysis worker process (rotating, 5 MB x 4)
  eventhawk_workers.log   parse worker processes, WARNING and above.  Many
                          processes append to it, so it is never rotated by
                          a worker; the GUI rolls it over at start-up.
"""

from __future__ import annotations

import logging
import os
import tempfile

GUI_LOG = "eventhawk_gui.log"
ANALYSIS_LOG = "eventhawk_analysis.log"
WORKERS_LOG = "eventhawk_workers.log"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATEFMT = "%Y-%m-%d %H:%M:%S"
_WORKERS_ROLL_BYTES = 5 * 1024 * 1024


def log_directory() -> str:
    """The folder every EventHawk log file is written to (created if needed)."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or tempfile.gettempdir()
    path = os.path.join(base, "EventHawk", "logs")
    try:
        os.makedirs(path, exist_ok=True)
    except OSError:
        path = tempfile.gettempdir()
    return path


def setup_child_logging(role: str) -> None:
    """Give a worker PROCESS a file sink for WARNING and above.

    A no-op in the main process: the thread fallbacks run the same worker
    code inside the GUI process, whose own log already catches it.
    """
    try:
        import multiprocessing
        if multiprocessing.parent_process() is None:
            return
        root = logging.getLogger()
        if any(getattr(h, "_eventhawk_workers", False) for h in root.handlers):
            return
        handler = logging.FileHandler(os.path.join(log_directory(), WORKERS_LOG),
                                      encoding="utf-8", delay=True)
        handler.setLevel(logging.WARNING)
        handler.setFormatter(logging.Formatter(
            f"%(asctime)s [%(levelname)s] [{role} pid=%(process)d] %(name)s: %(message)s",
            datefmt=LOG_DATEFMT,
        ))
        handler._eventhawk_workers = True
        root.addHandler(handler)
        if root.level == logging.NOTSET or root.level > logging.WARNING:
            root.setLevel(logging.WARNING)
    except Exception:
        pass   # logging must never stop a parse


def roll_workers_log() -> None:
    """Called once by the GUI at start-up, before any worker exists."""
    path = os.path.join(log_directory(), WORKERS_LOG)
    try:
        if os.path.getsize(path) > _WORKERS_ROLL_BYTES:
            os.replace(path, path + ".1")
    except OSError:
        pass
