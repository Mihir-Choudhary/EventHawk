"""Level markers, keyboard shortcuts, Open Recent and the saved window layout.

  A. Level markers: Critical / Error / Audit Failure / Warning cells carry a
     coloured dot, other levels a transparent spacer of the same size (so the
     names line up); the level name is still the cell text, in both models.
  B. Shortcuts: Ctrl+Shift+F, Ctrl+B, Ctrl+\\ and Help > Keyboard Shortcuts
     (Ctrl+/) exist; Ctrl+C in the event table copies the selected event;
     Ctrl+B bookmarks it; the shortcuts list shows every entry.
  C. Open Recent: inputs are remembered newest first, without duplicates and
     capped; a recent path that no longer exists is dropped when picked; the
     user's real list is restored afterwards.
  D. Headless test windows never read or write the user's saved layout or
     recent list.

Synthetic data only.
Run: QT_QPA_PLATFORM=offscreen python tests/test_shortcuts_recent_levels.py
"""
import os
import sys
import tempfile
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
SEC = r"C:\s\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def write_jm_levels(evs, tmp):
    """test_around_pivot.write_jm, keeping each event's own level."""
    import json
    import pyarrow as pa
    import pyarrow.parquet as pq
    from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME, _make_schema, load_arrow_table
    rows = []
    for e in evs:
        t = e["timestamp"]
        rows.append({"record_id": e["record_id"], "event_record_id": e.get("event_record_id"),
                     "event_id": e["event_id"], "level": e.get("level", 4),
                     "level_name": e.get("level_name", "Information"),
                     "timestamp_utc": t.replace("T", " ").replace("Z", "")[:26] if t else None,
                     "channel": e["channel"], "provider": e["provider"], "computer": e["computer"],
                     "source_file": e["source_file"], "event_data_json": json.dumps(e["event_data"])})
    shard = os.path.join(tmp, "s0.parquet")
    pq.write_table(pa.Table.from_pylist(rows, schema=_make_schema()), shard)
    with open(os.path.join(tmp, _MANIFEST_FILENAME), "w", encoding="utf-8") as fh:
        json.dump([shard], fh)
    return load_arrow_table(tmp)


def alpha_at_centre(pm):
    img = pm.toImage()
    return img.pixelColor(img.width() // 2, img.height() // 2).alpha()


def main() -> int:
    from PySide6.QtCore import Qt, QSettings
    from PySide6.QtGui import QShortcut, QKeySequence
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QDialog, QLabel
    app = QApplication.instance() or QApplication([])
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.icons import level_dot
    from evtx_tool.gui.models import COL_LEVEL

    print("=== A. level markers ===")
    for lvl in ("Critical", "Error", "Audit Failure", "Warning"):
        check(f"{lvl}: a visible dot", alpha_at_centre(level_dot(lvl)) > 200)
    for lvl in ("Information", "Verbose", "", None):
        pm = level_dot(lvl)
        check(f"{lvl!r}: a transparent spacer of the same size",
              alpha_at_centre(pm) == 0 and pm.size() == level_dot("Error").size())

    evs = [T.ev(SEC, i + 1, "HOST-A" if i % 2 else "HOST-B", T.T0 + timedelta(seconds=i), 4624)
           for i in range(6)]
    evs[0]["level_name"], evs[1]["level_name"] = "Error", "Information"
    evs[0]["level"], evs[1]["level"] = 2, 4          # Juggernaut derives the name from this
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        m = T.Mode(mw, jm)
        w = mw.MainWindow()
        if jm:
            jm_dir = tempfile.mkdtemp(prefix="levels_")
            m.load(w, evs, table=write_jm_levels(evs, jm_dir), parquet_dir=jm_dir)
        else:
            m.load(w, evs)
        model = w._hw_model if jm else w._event_model
        r_err = next(r for r in range(model.rowCount())
                     if model.index(r, COL_LEVEL).data() == "Error")
        r_inf = next(r for r in range(model.rowCount())
                     if model.index(r, COL_LEVEL).data() == "Information")
        d_err = model.index(r_err, COL_LEVEL).data(Qt.ItemDataRole.DecorationRole)
        d_inf = model.index(r_inf, COL_LEVEL).data(Qt.ItemDataRole.DecorationRole)
        check(f"{tag}: an Error cell has the dot", d_err is not None and alpha_at_centre(d_err) > 200)
        check(f"{tag}: an Information cell has the spacer", d_inf is not None and alpha_at_centre(d_inf) == 0)
        check(f"{tag}: other columns have no decoration",
              model.index(r_err, COL_LEVEL + 1).data(Qt.ItemDataRole.DecorationRole) is None)
        al = model.index(r_err, COL_LEVEL).data(Qt.ItemDataRole.TextAlignmentRole)
        check(f"{tag}: the level column is left-aligned so the dots line up",
              bool(al & Qt.AlignmentFlag.AlignLeft), str(al))
        w.close(); T.pump(100)

    print("\n=== B. shortcuts ===")
    w = mw.MainWindow()
    keys = {sc.key().toString() for sc in w.findChildren(QShortcut)}
    for k in ("Ctrl+Shift+F", "Ctrl+B", "Ctrl+\\", "Ctrl+F"):
        check(f"{k} is bound", k in keys, str(sorted(keys)))
    acts = [a for a in w.menuBar().findChildren(type(w.menuBar().actions()[0]))
            if a.text() == "Keyboard Shortcuts"]
    check("Help > Keyboard Shortcuts exists with Ctrl+/",
          bool(acts) and acts[0].shortcut().toString() == "Ctrl+/")

    shown = {}

    def fake_exec(dlg, *a, **k):
        shown["labels"] = [x.text() for x in dlg.findChildren(QLabel)]
        return 0
    orig = QDialog.exec
    QDialog.exec = fake_exec
    try:
        w._show_shortcuts()
    finally:
        QDialog.exec = orig
    check("the shortcuts list shows every entry",
          all(k in shown.get("labels", []) for k, _ in w.SHORTCUTS), str(shown.get("labels", [])[:6]))

    about = [a for a in w.menuBar().findChildren(type(w.menuBar().actions()[0]))
             if a.text() == "About EventHawk"]
    check("Help > About EventHawk exists", bool(about))

    from PySide6.QtWidgets import QMessageBox
    popped = []
    orig_warn = QMessageBox.warning
    QMessageBox.warning = staticmethod(lambda *a, **k: popped.append(a[1:3]))
    try:
        w._file_list.clear()
        w._on_parse_clicked()
    finally:
        QMessageBox.warning = orig_warn
    check("Parse with nothing queued does not interrupt with a dialog", not popped, str(popped))
    check("...and says what to do in the status bar",
          "Ctrl+O" in w.statusBar().currentMessage(), w.statusBar().currentMessage())

    T.Mode(mw, False).load(w, evs)
    w.resize(1400, 800); w.show(); T.pump(300)
    row = next(r for r in range(w._proxy_model.rowCount())
               if "HOST-A" in str(w._proxy_model.index(r, 4).data()))
    w._table.selectRow(row); T.pump(200)
    QApplication.clipboard().setText("")
    w._table.setFocus(); T.pump(50)
    QTest.keyClick(w._table, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
    T.pump(100)
    check("Ctrl+C in the event table copies the selected event",
          "HOST-A" in QApplication.clipboard().text(), QApplication.clipboard().text()[:80])
    before = len(w._bookmarked_keys)
    w._btn_bookmark_event.setEnabled(True)
    w._shortcut_bookmark(); T.pump(100)
    check("Ctrl+B bookmarks the selected event", len(w._bookmarked_keys) == before + 1,
          f"{before} -> {len(w._bookmarked_keys)}")
    w._shortcut_bookmark(); T.pump(100)
    check("Ctrl+B again removes the bookmark", len(w._bookmarked_keys) == before)

    print("\n=== C/D. Open Recent and saved layout ===")
    st = QSettings("EventHawk", "GUI")
    saved_recent, had_recent = st.value(w._RECENT_KEY), st.contains(w._RECENT_KEY)
    saved_geo, had_geo = st.value("main_geometry"), st.contains("main_geometry")
    tmp = tempfile.mkdtemp(prefix="recent_")
    try:
        st.remove(w._RECENT_KEY)
        a, b = os.path.join(tmp, "a"), os.path.join(tmp, "b")
        os.makedirs(a); os.makedirs(b)
        w._remember_input(a); w._remember_input(b); w._remember_input(a)
        check("newest first, no duplicates", w._recent_inputs() == [a, b], str(w._recent_inputs()))
        for i in range(15):
            w._remember_input(os.path.join(tmp, f"x{i}"))
        check(f"capped at {w._RECENT_MAX}", len(w._recent_inputs()) == w._RECENT_MAX)
        gone = os.path.join(tmp, "x14")            # newest, never created on disk
        n_files = w._file_list.count()
        w._open_recent(gone)
        check("a recent path that is gone is dropped, not queued",
              gone not in w._recent_inputs() and w._file_list.count() == n_files)
        w._open_recent(a)
        check("a recent folder is queued",
              any(w._file_list.item(i).data(Qt.ItemDataRole.UserRole) == a
                  for i in range(w._file_list.count())))
        w._recent_menu.aboutToShow.emit()
        check("the menu lists the recent paths and Clear Recent",
              any(x.text() == "Clear Recent" for x in w._recent_menu.actions()))

        st.remove(w._RECENT_KEY)
        w._add_path(b)
        check("D: an input added on the test platform is not remembered",
              w._recent_inputs() == [], str(w._recent_inputs()))
        geo_before = st.value("main_geometry")
        w._save_layout()
        check("D: the test window does not save its layout",
              st.value("main_geometry") == geo_before)
        check("D: nor restore one", w._restore_layout() is False)
    finally:
        if had_recent:
            st.setValue(w._RECENT_KEY, saved_recent)
        else:
            st.remove(w._RECENT_KEY)
        if had_geo:
            st.setValue("main_geometry", saved_geo)
        st.sync()
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    w.close(); T.pump(100)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
