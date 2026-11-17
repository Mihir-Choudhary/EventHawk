"""A damaged saved layout never stops EventHawk from starting (Codex PR19-3).

The window geometry and splitter states are read back from QSettings and handed
straight to restoreGeometry / restoreState. A value of the wrong type (a string
where Qt saved bytes: a hand-edited registry value, another version) raised
TypeError out of the MainWindow constructor, so the program could not start
until the setting was removed by hand.

Expected: with each saved value damaged in turn (text, a number, garbage bytes)
the window opens, uses its default layout, and the damaged value is ignored.
Uses a private INI file: the user's own settings are never read or written.
"""
import os
import shutil
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append(bool(cond))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import QByteArray, QSettings
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    tmp = tempfile.mkdtemp(prefix="lay_")
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, tmp)
    import evtx_tool.gui.main_window as mw
    real = mw.MainWindow._persist_layout_enabled
    mw.MainWindow._persist_layout_enabled = staticmethod(lambda: True)
    try:
        for key in ("main_geometry", "main_right_split", "main_bottom_split"):
            for label, bad in (("text", "not a layout"), ("a number", 12345), ("garbage bytes", QByteArray(b"\x00\x01garbage"))):
                st = QSettings("EventHawk", "GUI")
                st.clear()
                st.setValue(key, bad)
                st.sync()
                try:
                    w = mw.MainWindow()
                    ok, err = True, ""
                except Exception as e:
                    w, ok, err = None, False, f"{type(e).__name__}: {e}"
                check(f"{key} = {label}: the window still opens", ok, err[:150])
                if w is not None:
                    w.close()
                    app.processEvents()
    finally:
        mw.MainWindow._persist_layout_enabled = real
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{sum(CHECKS)}/{len(CHECKS)} passed")
    return 0 if all(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
