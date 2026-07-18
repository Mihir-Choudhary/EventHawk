"""
EventHawk — GUI entry point.

Usage:
    py -3 evtx_tool.py gui
    py -3 evtx_tool.py gui D:\\Logs
    py -3 evtx_tool.py gui D:\\Logs\\Security.evtx
"""

from __future__ import annotations

import logging
import multiprocessing
import os
import sys
import traceback
from logging.handlers import RotatingFileHandler


def _flush_log_handlers() -> None:
    """Force-flush every handler on the root logger to disk."""
    for _h in logging.getLogger().handlers:
        try:
            _h.flush()
        except Exception:
            pass


def _setup_gui_logging() -> None:
    """Configure comprehensive logging for the GUI process.

    Layer 1 — Rotating file handler (WARNING+): all Python/Qt warnings and
               errors land in evtx_tool_logs/eventhawk_gui.log (5 MB × 3).
    Layer 2 — Startup / clean-exit markers in the log (context for crashes).
    Layer 3 — faulthandler: writes a Python traceback to
               evtx_tool_logs/eventhawk_crash.log on SIGSEGV / SIGABRT /
               SIGFPE / SIGILL / SIGBUS.  This is the only mechanism that
               survives hard native crashes that never reach Python.
    Layer 4 — sys.excepthook with explicit flush (unhandled main-thread
               exceptions that bubble past Qt's event loop).
    Layer 5 — threading.excepthook (Python 3.8+): unhandled exceptions in
               non-Qt Python threads (QRunnable workers, futures callbacks).
    Layer 6 — sys.unraisablehook (Python 3.8+): exceptions in __del__,
               weakref callbacks, and similar "can't raise" locations.
    Layer 7 — stderr tee: PySide6 prints slot exceptions to stderr rather
               than calling sys.excepthook.  Teeing stderr to the log file
               captures these before they vanish when the app is launched
               without a terminal (double-click on Windows).
    Layer 8 — Qt message handler: Qt-internal warnings / criticals / fatals.
    """
    import atexit
    import platform
    import tempfile

    # Logs must go to a user-writable location. When installed under Program
    # Files (per-machine), the app's own directory is read-only for non-admin
    # users, so creating evtx_tool_logs next to the app raises PermissionError
    # and crashes startup. Prefer %LOCALAPPDATA%\EventHawk\logs, then fall back.
    _log_base = (os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
                 or tempfile.gettempdir())
    log_dir = os.path.join(_log_base, "EventHawk", "logs")
    try:
        os.makedirs(log_dir, exist_ok=True)
    except OSError:
        log_dir = tempfile.gettempdir()
    log_path   = os.path.join(log_dir, "eventhawk_gui.log")
    crash_path = os.path.join(log_dir, "eventhawk_crash.log")

    # ── Layer 1: rotating file handler ───────────────────────────────────
    handler = RotatingFileHandler(
        log_path,
        maxBytes=5 * 1024 * 1024,   # 5 MB per file
        backupCount=3,               # keep 3 rotated backups
        encoding="utf-8",
    )
    handler.setLevel(logging.WARNING)
    handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    root = logging.getLogger()
    root.setLevel(logging.WARNING)
    # Avoid adding duplicate handlers if launch() is somehow called twice
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(handler)

    # ── Layer 1b: console handler ────────────────────────────────────────
    # Also stream WARNING+ to the terminal the GUI was launched from, so
    # problems (e.g. a filter/profile wiring failure) are visible immediately
    # instead of only landing in eventhawk_gui.log.  Previously the GUI logged
    # to file only, which is why some failures looked completely silent.
    if not any(
        isinstance(h, logging.StreamHandler)
        and not isinstance(h, RotatingFileHandler)
        and getattr(h, "stream", None) in (sys.stderr, sys.stdout)
        for h in root.handlers
    ):
        _console = logging.StreamHandler(sys.stderr)
        _console.setLevel(logging.WARNING)
        _console.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root.addHandler(_console)

    # ── Layer 2: startup / shutdown markers ──────────────────────────────
    # Logged at WARNING so they always land in the file regardless of level.
    # Provides pid, Python version, and OS context when reading a crash log.
    _startup_log = logging.getLogger("eventhawk.startup")
    _startup_log.warning(
        "═══ EventHawk starting  pid=%d  python=%s  platform=%s ═══"
        "  [log level: WARNING+; INFO/DEBUG not captured here]",
        os.getpid(),
        sys.version.split()[0],
        platform.platform(),
    )
    _flush_log_handlers()

    def _log_clean_exit() -> None:
        _startup_log.warning(
            "═══ EventHawk clean exit  pid=%d ═══", os.getpid()
        )
        _flush_log_handlers()

    atexit.register(_log_clean_exit)

    # ── Layer 3: faulthandler (hard crashes — SIGSEGV / SIGABRT / etc.) ──
    # faulthandler writes a raw Python traceback to the crash file directly
    # via the OS file descriptor, bypassing Python's exception machinery.
    # This is the only mechanism that survives heap corruption / segfaults.
    try:
        import faulthandler
        # Keep the crash file open for the lifetime of the process so
        # faulthandler always has a valid fd to write to.
        _crash_file = open(crash_path, "a", encoding="utf-8")  # noqa: SIM115
        _crash_file.write(
            f"\n{'=' * 60}\n"
            f"EventHawk  pid={os.getpid()}  python={sys.version.split()[0]}\n"
            f"platform={platform.platform()}\n"
            f"{'=' * 60}\n"
        )
        _crash_file.flush()
        faulthandler.enable(file=_crash_file, all_threads=True)
        atexit.register(_crash_file.close)
    except Exception:
        pass  # non-fatal

    # ── Layer 4: sys.excepthook with explicit flush ───────────────────────
    # Catches exceptions that bubble past Qt's event loop on the main thread.
    # Explicit flush ensures the entry is on disk before any downstream crash.
    def _excepthook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        logging.getLogger("eventhawk.unhandled").critical(
            "Unhandled exception:\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )
        _flush_log_handlers()

    sys.excepthook = _excepthook

    # ── Layer 5: threading.excepthook (Python 3.8+) ───────────────────────
    # sys.excepthook is NOT called for exceptions in non-main threads.
    # This catches failures in QRunnable workers, concurrent.futures
    # callbacks, and any other threading.Thread subclass.
    try:
        def _thread_excepthook(args) -> None:
            if args.exc_type is SystemExit:
                return
            logging.getLogger("eventhawk.thread").critical(
                "Unhandled exception in thread %r:\n%s",
                getattr(args.thread, "name", "?"),
                "".join(traceback.format_exception(
                    args.exc_type, args.exc_value, args.exc_tb,
                )),
            )
            _flush_log_handlers()

        import threading
        threading.excepthook = _thread_excepthook
    except AttributeError:
        pass  # Python < 3.8 — not supported

    # ── Layer 6: sys.unraisablehook (Python 3.8+) ─────────────────────────
    # Called for exceptions that Python cannot propagate: __del__ methods,
    # weakref finalizers, GC callbacks, and daemon-thread teardown.
    try:
        def _unraisable_hook(unraisable) -> None:
            msg = (
                "".join(traceback.format_exception(
                    unraisable.exc_type,
                    unraisable.exc_value,
                    unraisable.exc_tb,
                ))
                if unraisable.exc_tb
                else str(unraisable.exc_value)
            )
            logging.getLogger("eventhawk.unraisable").warning(
                "Unraisable exception in %r:\n%s",
                unraisable.object,
                msg,
            )

        sys.unraisablehook = _unraisable_hook
    except AttributeError:
        pass  # Python < 3.8 — not supported

    # ── Layer 7: stderr tee ───────────────────────────────────────────────
    # PySide6 catches Python exceptions in Qt slots and prints them to stderr
    # via traceback.print_exc() rather than calling sys.excepthook.  When the
    # app is launched without a terminal (e.g. double-click on Windows) stderr
    # goes nowhere and these exceptions vanish completely.
    # A line-buffered tee forwards every stderr line to both the original
    # stderr stream and the WARNING log so slot exceptions are always captured.
    _stderr_log = logging.getLogger("eventhawk.stderr")
    _orig_stderr = sys.stderr

    class _StderrTee:
        """Line-buffered stderr forwarder → original stderr + log file."""

        def __init__(self, original) -> None:
            self._orig = original
            self._buf  = ""

        def write(self, text: str) -> int:
            try:
                self._orig.write(text)
            except Exception:
                pass
            self._buf += text
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                stripped = line.strip()
                if stripped:
                    _stderr_log.warning("[stderr] %s", line)
            return len(text)

        def flush(self) -> None:
            tail = self._buf.strip()
            if tail:
                _stderr_log.warning("[stderr] %s", self._buf.rstrip())
                self._buf = ""
            try:
                self._orig.flush()
            except Exception:
                pass

        # Preserve attributes that external code or faulthandler may probe
        def fileno(self):              return self._orig.fileno()
        def isatty(self) -> bool:      return getattr(self._orig, "isatty", lambda: False)()
        def readable(self) -> bool:    return False
        def writable(self) -> bool:    return True
        def seekable(self) -> bool:    return False

        @property
        def encoding(self) -> str:     return getattr(self._orig, "encoding", "utf-8")
        @property
        def errors(self) -> str:       return getattr(self._orig, "errors",   "replace")

    if _orig_stderr is not None:
        try:
            sys.stderr = _StderrTee(_orig_stderr)
        except Exception:
            pass  # non-fatal — leave stderr unchanged
    else:
        # pythonw.exe / detached-stderr launch model: sys.stderr is None so
        # PySide6 slot-exception tracebacks go nowhere.  Open a dedicated
        # stderr log file so those tracebacks are always captured on disk.
        try:
            _stderr_path = os.path.join(log_dir, "eventhawk_stderr.log")
            _stderr_file = open(_stderr_path, "a", encoding="utf-8")  # noqa: SIM115
            sys.stderr = _StderrTee(_stderr_file)
            atexit.register(_stderr_file.close)
        except Exception:
            pass  # non-fatal

    # ── Layer 8: Qt message handler ───────────────────────────────────────
    # Routes Qt-internal warnings / criticals (null-pointer dereferences,
    # OpenGL errors, widget hierarchy violations, etc.) to the log file.
    try:
        from PySide6.QtCore import qInstallMessageHandler, QtMsgType

        _qt_logger = logging.getLogger("eventhawk.qt")

        def _qt_message_handler(msg_type, _context, message: str) -> None:
            if msg_type == QtMsgType.QtDebugMsg:
                _qt_logger.debug("[Qt] %s", message)
            elif msg_type == QtMsgType.QtInfoMsg:
                _qt_logger.info("[Qt] %s", message)
            elif msg_type == QtMsgType.QtWarningMsg:
                _qt_logger.warning("[Qt] %s", message)
            elif msg_type in (QtMsgType.QtCriticalMsg, QtMsgType.QtFatalMsg):
                _qt_logger.critical("[Qt] %s", message)

        qInstallMessageHandler(_qt_message_handler)
    except Exception:
        pass  # non-fatal — logging still works without this


def launch(initial_paths: list[str] | None = None) -> None:
    """
    Launch the PySide6 GUI. This must be called from the main process
    (after the multiprocessing spawn guard) so child processes spawned
    by ProcessPoolExecutor don't try to open windows.
    """
    _setup_gui_logging()

    # Required for frozen executables (PyInstaller) + ProcessPoolExecutor on Windows
    multiprocessing.freeze_support()

    # Boost GUI process priority so the Qt event loop always wins scheduling
    # against the BELOW_NORMAL worker subprocess.
    try:
        import psutil
        p = psutil.Process()
        if sys.platform == "win32":
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        # On Linux, lowering nice requires root — skip for GUI
    except Exception:
        pass  # psutil not installed — non-fatal

    # ── Windows taskbar icon fix ───────────────────────────────────────────
    # Without this, Windows groups the process under python.exe's icon.
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                "EventHawk.DFIR.App.1"
            )
        except Exception:
            pass

    from PySide6.QtCore import Qt, QCoreApplication
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QIcon, QPixmap

    # High-DPI settings (must be set before QApplication creation)
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_UseHighDpiPixmaps)

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("EventHawk")
    app.setApplicationVersion("1.3")
    app.setOrganizationName("DFIR Tools")

    # ── Set application-level icon (taskbar + title bar) ──────────────────
    _logo = os.path.join(os.path.dirname(__file__), "..", "resources", "images", "eventhawk_logo.png")
    _logo = os.path.normpath(_logo)
    if os.path.isfile(_logo):
        from PySide6.QtGui import QImage, QPainter

        # New PNG already has proper alpha — load directly, no background removal needed.
        _img = QImage(_logo).convertToFormat(QImage.Format.Format_ARGB32)
        _base = QPixmap.fromImage(_img)

        _icon = QIcon()
        for _sz in (16, 24, 32, 48, 64, 128, 256):
            # Scale to 110% target so logo fills more of the square,
            # then center on the canvas — only a tiny sliver is clipped from sides
            _target = int(_sz * 1.3)
            _scaled = _base.scaled(
                _target, _target,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            _canvas = QPixmap(_sz, _sz)
            _canvas.fill(Qt.GlobalColor.transparent)
            _p = QPainter(_canvas)
            _p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
            _p.drawPixmap((_sz - _scaled.width()) // 2, (_sz - _scaled.height()) // 2, _scaled)
            _p.end()
            _icon.addPixmap(_canvas)

        app.setWindowIcon(_icon)

    # Apply dark theme
    from .theme import apply_theme
    apply_theme(app)

    from .main_window import MainWindow
    window = MainWindow(initial_paths=initial_paths or [])
    # Open maximized (expanded) so the multi-pane DFIR layout is usable on first
    # launch; the 1420x860 resize() in MainWindow becomes the un-maximized size.
    window.showMaximized()

    sys.exit(app.exec())
