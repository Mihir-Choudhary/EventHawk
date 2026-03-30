"""
EventHawk — GUI entry point.

Usage:
    py -3 evtx_tool.py gui
    py -3 evtx_tool.py gui D:\\Logs
    py -3 evtx_tool.py gui D:\\Logs\\Security.evtx
"""

from __future__ import annotations

import multiprocessing
import os
import sys


def launch(initial_paths: list[str] | None = None) -> None:
    """
    Launch the PySide6 GUI. This must be called from the main process
    (after the multiprocessing spawn guard) so child processes spawned
    by ProcessPoolExecutor don't try to open windows.
    """
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
    app.setApplicationVersion("1.1")
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
    window.show()

    sys.exit(app.exec())
