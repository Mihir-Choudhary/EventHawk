"""Regressions found by the whole-branch review of the "Around this event" work.

1. JM export of a filtered-snapshot around tab exported events the tab does
   not show (the tab's WHERE ran against the full table, not the snapshot).
2. JM chain tab: right-click "Around this event" and the Bookmark button read
   the row from the MAIN model, so they used a different event.  The count
   label raised with a JM chain tab in front.
3. Column popups on around tabs: empty in JM, and applying one filtered the
   main table (JM merged) or could not target the tab (separate mode).
4. Host identity: one setup name renamed to two names (a cloned image) joined
   two machines automatically.
5. Host identity grouping was quadratic in the number of names.
6. Session, Remote Assistance and "filter to this computer" filters reached
   around tabs, whose contents are fixed by the filter question.
"""
import csv
import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication, QDialog                 # noqa: E402

app = QApplication.instance() or QApplication([])
import test_around_pivot as T                                        # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


class _Item:
    """Stands in for a chain-tree QTreeWidgetItem."""
    def __init__(self, ch):
        self._ch = ch

    def data(self, *_a):
        class W:
            pass
        w = W()
        w.data = self._ch
        return w


class _Stop(Exception):
    pass


def jm_export(mw, tmpdir):
    print("\n=== 1. JM export of a snapshot around tab ===", flush=True)
    out = os.path.join(tmpdir, "around_export.csv")
    orig = mw.QFileDialog.getSaveFileName
    mw.QFileDialog.getSaveFileName = staticmethod(lambda *a, **k: (out, "CSV (*.csv)"))
    try:
        m = T.Mode(mw, True)
        w = mw.MainWindow()
        evs = T.dataset()
        m.load(w, evs)
        msgs = []
        w._warn_blocking = lambda *a, **k: msgs.append(a)
        m.quick_filter_main(w, "event_id", "4624")
        key, st = T.open_tab(w, dict(evs[0]), T.FIVE, T.FIVE, "all", True, filtered_from=w._hw_model)
        shown = T.tab_rows(w, st, True)
        w._export_juggernaut()
        T.wait_for(lambda: msgs, 30)
        T.pump(200)
        rows = []
        if os.path.exists(out):
            with open(out, encoding="utf-8-sig") as fh:
                rows = list(csv.DictReader(fh))
        rid = next((c for c in (rows[0] if rows else {}) if "record" in c.lower()), None)
        sf = next((c for c in (rows[0] if rows else {})
                   if "source" in c.lower() and "file" in c.lower()), None)
        got = {(r[sf], int(r[rid])) for r in rows} if rid and sf else set()
        check("exported rows are exactly the tab's rows", got == shown,
              f"tab {len(shown)}, exported {len(rows)}; extra {sorted(got - shown)}")
        T.teardown(w, True, m)
    finally:
        mw.QFileDialog.getSaveFileName = orig


def chain_tab(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== 2. chain tab, {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    evs = T.dataset()
    m.load(w, evs)
    chain = {"rule_name": "probe", "severity": "high", "events": [dict(evs[5]), dict(evs[9])]}
    w._open_chain_events_tab([_Item(chain)])
    key = [k for k in w._file_tabs if k.startswith("__chain__")][-1]
    st = w._file_tabs[key]
    T.pump(50)
    check(f"{tag}: chain tab is the active tab", w._active_file_tab == key, str(w._active_file_tab))
    e0 = st.proxy.get_source_event(0)
    want = (e0["source_file"], e0["record_id"])
    got = {}

    def cap(menu, ev, source):
        got["ev"], got["src"] = ev, source
        raise _Stop

    w._add_around_menu = cap
    pos = st.table.visualRect(st.proxy.index(0, 1)).center()
    try:
        w._on_table_context_menu(pos)
    except _Stop:
        pass
    del w._add_around_menu
    a = got.get("ev") or {}
    check(f"{tag}: right-click anchor is the clicked chain row",
          (a.get("source_file"), a.get("record_id")) == want, f"{a.get('record_id')} vs {want}")
    check(f"{tag}: the filter question asks about the chain tab", got.get("src") is st.proxy,
          type(got.get("src")).__name__)
    st.table.selectRow(0)
    T.pump(50)
    w._on_bookmark_toggle()
    check(f"{tag}: Bookmark on a chain row bookmarks that event", want in w._bookmarked_keys,
          str(w._bookmarked_keys))
    err = None
    try:
        w._on_hw_filter_busy_finished() if jm else w._update_count_label()
    except Exception as exc:          # noqa: BLE001
        err = exc
    check(f"{tag}: count label with a chain tab in front", err is None
          and w._lbl_count.text().startswith("2"), f"{err!r} / {w._lbl_count.text()!r}")
    T.teardown(w, jm, m)


def column_popups(mw, jm, separate=False):
    tag = ("JM" if jm else "Normal") + (" separate" if separate else " merged")
    print(f"\n=== 3. column popups on an around tab, {tag} ===", flush=True)
    calls = []

    class _Stub:
        def __init__(self, *a, **k):
            calls.append(a)

        def exec(self):
            return QDialog.DialogCode.Rejected

        def selected(self):
            return []

    orig = mw._FilterTargetDialog
    mw._FilterTargetDialog = _Stub
    try:
        m = T.Mode(mw, jm)
        w = mw.MainWindow()
        evs = T.dataset()
        m.load(w, evs)
        if separate:
            w._view_mode = "separate"
        _k, st = T.open_tab(w, dict(evs[0]), T.FIVE, T.FIVE, "host", jm)
        seen = {}
        w._show_col_filter_popup = lambda idx, vals: seen.setdefault("v", vals)
        w._on_col_header_clicked(1)                       # Event ID
        T.wait_for(lambda: "v" in seen, 30)
        vals = {str(k): v for k, v in (seen.get("v") or {}).items()}
        check(f"{tag}: Event ID popup counts the tab's own rows", vals == {"4624": 5, "6011": 1},
              str(vals))
        del w._show_col_filter_popup
        main_before = m.main_count(w)
        w._on_col_filter_applied(1, "include", ["6011"])
        ok = T.wait_for(lambda: (st.model.rowCount() if jm else st.proxy.rowCount()) == 1, 20)
        check(f"{tag}: a column filter on the around tab filters it", ok,
              str(st.model.rowCount() if jm else st.proxy.rowCount()))
        T.pump(300)
        check(f"{tag}: ...and not the main table", m.main_count(w) == main_before,
              f"{m.main_count(w)} vs {main_before}")
        check(f"{tag}: ...without asking for file targets", not calls, str(len(calls)))
        if jm and not separate:
            m.clear_main(w)
            # Snapshot of the main table filtered to computer OTHER: one event
            # in the window.  Counting over the full table would give 4624: 9,
            # 6011: 1.
            m.quick_filter_main(w, "computer", "OTHER")
            _k, snap = T.open_tab(w, dict(evs[0]), T.FIVE, T.FIVE, "all", True, filtered_from=w._hw_model)
            seen2 = {}
            w._show_col_filter_popup = lambda idx, vals: seen2.setdefault("v", vals)
            w._on_col_header_clicked(1)
            T.wait_for(lambda: "v" in seen2, 30)
            v2 = {str(k): v for k, v in (seen2.get("v") or {}).items()}
            check("JM: popup on a snapshot tab counts the snapshot", v2 == {"4624": 1}, str(v2))
            del w._show_col_filter_popup
        w._view_mode = "merged"
        T.teardown(w, jm, m)
    finally:
        mw._FilterTargetDialog = orig


def host_identity():
    print("\n=== 4/5. host identity ===", flush=True)
    from evtx_tool.core.host_identity import HostIdentity, NameStat, Rename
    names = [NameStat("CLONE-A", r"C:\a\System.evtx", 5, "2022-01-01T00:00:00.000000Z", "2022-01-02T00:00:00.000000Z"),
             NameStat("CLONE-B", r"C:\b\System.evtx", 5, "2022-01-01T00:00:00.000000Z", "2022-01-02T00:00:00.000000Z")]
    renames = [Rename("TEMPLATE", "CLONE-A", "2022-01-01T00:00:00.000000Z", r"C:\a\System.evtx", 1),
               Rename("TEMPLATE", "CLONE-B", "2022-01-01T00:00:00.000000Z", r"C:\b\System.evtx", 1)]
    hi = HostIdentity.build(names, renames)
    check("one setup name renamed to two names does not join them",
          hi.group_of("CLONE-A").members == ["CLONE-A"], str(hi.group_of("CLONE-A").members))
    sug = hi.suggestions_for("CLONE-A")
    check("...it is offered as a rename suggestion instead",
          any(l.kind == "rename" for l in sug), str([(l.kind, l.a, l.b) for l in sug]))
    two = HostIdentity.build(names[:1] + [NameStat("OLD", r"C:\a\System.evtx", 1, "2022-01-01T00:00:00.000000Z",
                                                   "2022-01-01T00:00:00.000000Z")],
                             [Rename("OLD", "CLONE-A", "2022-01-01T00:00:00.000000Z", r"C:\a\System.evtx", 1)])
    check("a plain rename still joins automatically",
          two.group_of("CLONE-A").members == ["CLONE-A", "OLD"], str(two.group_of("CLONE-A").members))

    import evtx_tool.gui.main_window as mw
    n = 5000
    big = [NameStat(f"H{i}", f"C:\\f{i}.evtx", 3, "2022-01-01T00:00:00.000000Z",
                    "2022-01-01T00:00:00.000000Z") for i in range(n)]
    hi = HostIdentity.build(big, [])
    counts = [{"computer": f"H{i}", "source_file": f"C:\\f{i}.evtx", "n": 3} for i in range(n)]
    t = time.perf_counter()
    rows = mw._ComputerNormalisationDialog._build_rows(counts, hi)
    dt = time.perf_counter() - t
    check("5,000 hosts group in under 1 s", len(rows) == n and dt < 1.0, f"{dt:.2f} s")


def no_global_filters(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== 6. global filters leave around tabs alone, {tag} ===", flush=True)
    m = T.Mode(mw, jm)
    w = mw.MainWindow()
    evs = T.dataset()
    m.load(w, evs)
    _k, st = T.open_tab(w, dict(evs[0]), T.FIVE, T.FIVE, "host", jm)
    rows = lambda: st.model.rowCount() if jm else st.proxy.rowCount()   # noqa: E731
    w._set_ra_session_filter(frozenset({(T.SEC, 5)}), {})
    T.pump(300)
    T.wait_for(lambda: True, 1)
    check(f"{tag}: Remote Assistance filter leaves the around tab", rows() == 6, str(rows()))
    w._apply_computer_norm_filter(["OTHER"])
    T.pump(300)
    check(f"{tag}: 'filter to this computer' leaves the around tab", rows() == 6, str(rows()))
    if not jm:
        w._set_session_filter("0x3e7", {"computer": "WS01"})
        T.pump(100)
        check(f"{tag}: session filter leaves the around tab", rows() == 6, str(rows()))
    T.teardown(w, jm, m)


def main() -> int:
    import tempfile
    import shutil
    import evtx_tool.gui.main_window as mw
    tmp = tempfile.mkdtemp(prefix="review_fix_")
    try:
        jm_export(mw, tmp)
        for jm in (False, True):
            chain_tab(mw, jm)
        for jm in (False, True):
            for sep in (False, True):
                column_popups(mw, jm, sep)
        host_identity()
        for jm in (False, True):
            no_global_filters(mw, jm)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    import multiprocessing as mp
    mp.freeze_support()
    sys.exit(main())
