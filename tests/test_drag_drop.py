"""Dropping .evtx files and folders on the window adds them to the file list.

User (2026-11-01): "Allow dragging and dropping individual .evtx files ...
entire folders (recursively load all .evtx files inside). Both must work
separately and also mixed in one drop. Show a visual drop-zone highlight while
dragging."  Spec R-2/R-3: other items are skipped with a status message
(never silently), a folder with no .evtx anywhere is skipped and said so, a
vanished path is reported, drops during a parse are refused with a message,
and a drop only adds to the list (no auto-parse).  Files here are empty
placeholders made by the test.
"""
import os
import sys
import tempfile

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def main() -> int:
    from PySide6.QtCore import Qt, QMimeData, QUrl, QPointF, QPoint
    from PySide6.QtGui import QDragEnterEvent, QDropEvent, QDragLeaveEvent
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(sys.argv)
    import evtx_tool.gui.main_window as mw

    root = tempfile.mkdtemp(prefix="dnd_")
    a = os.path.join(root, "a.evtx")
    folder = os.path.join(root, "case")
    nested = os.path.join(folder, "host1", "logs")
    empty = os.path.join(root, "empty")
    for d in (nested, empty):
        os.makedirs(d)
    for p in (a, os.path.join(nested, "b.EVTX"), os.path.join(root, "notes.txt"), os.path.join(empty, "x.txt")):
        open(p, "wb").close()
    gone = os.path.join(root, "gone.evtx")

    w = mw.MainWindow()
    w.show(); app.processEvents()

    def listed():
        return [w._file_list.item(i).data(Qt.ItemDataRole.UserRole) for i in range(w._file_list.count())]

    def mime(paths):
        m = QMimeData()
        m.setUrls([QUrl.fromLocalFile(p) for p in paths])
        return m

    keep = []          # QMimeData must outlive the event, or Qt reads freed memory

    def enter(paths):
        keep.append(mime(paths))
        ev = QDragEnterEvent(QPoint(50, 50), Qt.DropAction.CopyAction, keep[-1],
                             Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
        QApplication.sendEvent(w, ev); app.processEvents()
        return ev.isAccepted()

    def drop(paths):
        enter(paths)
        keep.append(mime(paths))
        ev = QDropEvent(QPointF(50, 50), Qt.DropAction.CopyAction, keep[-1],
                        Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)
        QApplication.sendEvent(w, ev); app.processEvents()
        return ev.isAccepted()

    overlay = lambda: getattr(w, "_drop_overlay", None)     # noqa: E731
    check("a drag of an .evtx file is accepted", enter([a]))
    check("...and shows the drop-zone highlight", overlay() is not None and overlay().isVisible())
    QApplication.sendEvent(w, QDragLeaveEvent()); app.processEvents()
    check("leaving hides the highlight", overlay() is not None and not overlay().isVisible())
    check("a drag of only a .txt file is not accepted", not enter([os.path.join(root, "notes.txt")]))
    QApplication.sendEvent(w, QDragLeaveEvent()); app.processEvents()

    drop([a])
    check("dropping one file adds it", listed() == [a], str(listed()))
    check("the highlight is gone after the drop", not overlay().isVisible())
    drop([folder])
    check("dropping a folder adds the folder (parsed recursively later)", listed() == [a, folder], str(listed()))
    w._file_list.clear()
    drop([a, folder, os.path.join(root, "notes.txt"), empty, gone])
    check("a mixed drop adds every file and folder", listed() == [a, folder], str(listed()))
    status = w._lbl_status.text()
    check("the status says what was skipped and why",
          "3" in status and "skipped" in status.lower() and "no .evtx" in status.lower()
          and "not found" in status.lower(), status)
    drop([a, folder])
    check("dropping the same items again adds no duplicates", listed() == [a, folder], str(listed()))

    class _Busy:
        def isRunning(self):
            return True
    w._file_list.clear()
    w._worker = _Busy()
    accepted = drop([a])
    check("during a parse nothing is added", listed() == [], str(listed()))
    check("...and the user is told why", "pars" in w._lbl_status.text().lower(), w._lbl_status.text())
    check("...and the drag is refused", not accepted)
    w._worker = None
    w.close(); app.processEvents()
    import shutil
    shutil.rmtree(root, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
