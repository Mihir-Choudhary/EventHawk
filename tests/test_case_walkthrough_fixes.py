"""Findings from an analyst walkthrough (Defender detections case), fixed.

  F1  An Around tab showed every column at Qt's 100 px default (Timestamp cut
      to "2025-07-20 17:4…"): its model is swapped in while loading.
  F2  The "Filter active" badge stayed on in an Around tab, whose fixed window
      the Advanced Filter does not narrow.
  F3  The Bookmarks table showed raw UTC ISO strings beside the event table's
      display-zone times, in bookmarking order, with full paths.  Now: display
      zone and format, time order, what the event is, short log name; the
      double-click pivot still finds the exact event.
  F5  After a filter change the table stayed wherever the pass left it, so the
      detail pane described an event scrolled out of sight.  The selected event
      is re-selected and centred when it is still in the view.
  F6  The status line kept the last long operation's message; it now says
      what a search did.

Synthetic data, Normal and Juggernaut.
Run: QT_QPA_PLATFORM=offscreen python tests/test_case_walkthrough_fixes.py
"""
import os
import sys
from datetime import timedelta

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(errors="backslashreplace")

import test_around_pivot as T                                       # noqa: E402

CHECKS = []
SEC = r"C:\c\Security.evtx"


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def events(n=400):
    return [T.ev(SEC, i + 1, "HOST", T.T0 + timedelta(seconds=30 * i), 4624 if i % 3 else 4625,
                 data={"TargetUserName": "alice" if i % 2 else "bob"})
            for i in range(n)]


def main() -> int:
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841
    import evtx_tool.gui.main_window as mw
    from evtx_tool.gui.models import apply_tz
    from evtx_tool.core.filters import empty_filter

    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        print(f"\n=== {tag} ===", flush=True)
        evs = events()
        m = T.Mode(mw, jm)
        w = mw.MainWindow()
        m.load(w, evs)
        if jm:
            w._table.setModel(w._hw_model)
            w._hw_model.busy_finished.connect(w._on_hw_filter_busy_finished)
            w._table.selectionModel().selectionChanged.connect(w._on_hw_row_selected)
        w.resize(1400, 800)
        w.show()
        T.pump(400)

        def model():
            return w._active_table.model()

        def settle():
            if jm:
                T.wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
            T.pump(500)

        # F5: select an event far down, filter so it stays, it is centred
        target_row = 301                                    # i = 301 -> alice, 4624
        w._table.selectRow(target_row)
        T.pump(200)
        ev = w._selected_event()
        check(f"{tag}: an event far down is selected", ev is not None and ev["record_id"] == 302,
              str(ev and ev["record_id"]))
        w._table.scrollToTop()
        T.pump(100)
        w._quick_search.setText("alice")
        w._apply_quick_search()
        settle()
        T.pump(300)
        sel = w._table.selectionModel().selectedRows()
        row = sel[0].row() if sel else None
        visible = False
        if row is not None:
            rect = w._table.visualRect(model().index(row, 0))
            visible = w._table.viewport().rect().intersects(rect)
        sel_ev = w._selected_event()
        check(f"{tag}: after the filter the same event is still selected",
              sel_ev is not None and sel_ev["record_id"] == 302, str(sel_ev and sel_ev["record_id"]))
        check(f"{tag}: ...and scrolled into view", visible, f"row {row}")

        # F6: the status says what happened
        T.pump(100)
        check(f"{tag}: the status line says what the search did",
              "Search \u201calice\u201d" in w._lbl_status.text(), w._lbl_status.text())

        # F1 + F2: an Around tab with an Advanced Filter active
        cfg = empty_filter()
        cfg["event_ids"] = [4624]
        w._quick_search.setText("")
        w._apply_quick_search()
        settle()

        class _Dlg:
            def __init__(self, *a, **k): pass
            def exec(self): return mw.QDialog.DialogCode.Accepted
            def get_filter_config(self): return dict(cfg)
        real = mw.FilterDialog
        mw.FilterDialog = _Dlg
        w._on_advanced_filter_clicked()
        mw.FilterDialog = real
        settle()
        check(f"{tag}: the filter badge shows on All Events", not w._lbl_adv_filter_badge.isHidden())
        anchor = evs[100]
        key, st = T.open_tab(w, anchor, timedelta(minutes=5), timedelta(minutes=5), "host", jm)
        T.pump(400)
        tbl = st.table if st is not None else None
        check(f"{tag}: the Around tab opened", tbl is not None)
        if tbl is not None:
            title = w._events_tab_widget.tabText(w._events_tab_widget.indexOf(tbl))
            check(f"{tag}: its title carries the anchor's date and time",
                  apply_tz(anchor["timestamp"])[:19] in title, title)
            check(f"{tag}: the status says what opened",
                  w._lbl_status.text().startswith("Around this event: ±5 min of "), w._lbl_status.text())
            check(f"{tag}: F1 its Timestamp column has its default width, not 100 px",
                  tbl.columnWidth(3) == w._DEFAULT_COL_WIDTHS[3], str(tbl.columnWidth(3)))
            check(f"{tag}: F1 and the # column too", tbl.columnWidth(0) == w._DEFAULT_COL_WIDTHS[0],
                  str(tbl.columnWidth(0)))
            check(f"{tag}: F2 no 'Filter active' badge while the Around tab is in front",
                  w._lbl_adv_filter_badge.isHidden())
            w._events_tab_widget.setCurrentIndex(0)
            T.pump(200)
            check(f"{tag}: F2 ...it is back on All Events", not w._lbl_adv_filter_badge.isHidden())

        # F3: bookmarks table
        w._btn_clear_all_filters.click()
        settle()
        for e in (evs[50], evs[10], evs[30]):                 # bookmarked out of order
            w._bookmark_event(e)
        T.pump(100)
        tb = w._tbl_bookmarks
        heads = [tb.horizontalHeaderItem(c).text() for c in range(tb.columnCount())]
        check(f"{tag}: F3 the table leads with the time and says what each event is",
              heads[:3] == ["Time", "Event ID", "Event"], str(heads))
        times = [tb.item(r, 0).text() for r in range(tb.rowCount())]
        check(f"{tag}: F3 times are in the display zone and format of the event table",
              times[0] == apply_tz(evs[10]["timestamp"]) and "T" not in times[0], str(times))
        check(f"{tag}: F3 in time order", times == sorted(times), str(times))
        check(f"{tag}: F3 the log is a short name, the path its tooltip",
              tb.item(0, 4).text() == "Security" and tb.item(0, 4).toolTip() == SEC, tb.item(0, 4).text())
        check(f"{tag}: F3 no row-number gutter", not tb.verticalHeader().isVisible())
        w._on_bookmark_double_click(tb.model().index(1, 0))       # evs[30]
        settle()
        T.pump(300)
        check(f"{tag}: F3 double-click still shows exactly that event",
              model().rowCount() == 1 and str(model().index(0, 20).data() or "") in ("31", "")
              and w._lbl_count.text().startswith("1 /"), w._lbl_count.text())

        w.close()
        T.pump(150)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'=' * 62}\n{ok}/{len(CHECKS)} checks passed")
    for n_, c, d_ in CHECKS:
        if not c:
            print(f"  FAILED: {n_}  {d_}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
