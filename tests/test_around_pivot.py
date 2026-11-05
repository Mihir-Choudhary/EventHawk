"""'Around this event': a tab of the events near one event, in both modes.

The window is [anchor - before, anchor + after], inclusive, in UTC, to the
microsecond.  "This host" means every Computer name of the anchor's machine
(renames and domain suffix included), never just the exact string -- on the
Win 10 baseline the setup name WIN-VR474TJ38H3 writes 255 events inside a
±5 min window around the rename, and exact-name matching would drop them.

Every block runs in Normal mode and in Juggernaut mode and the two must give
the same rows.  Real data needs EVTX_TEST_LOGS_ONLINE (the "nextron" folder).
"""
import glob
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Tab labels carry "⏱"; a cp1252 pipe must not turn a pass into a crash.
sys.stdout.reconfigure(errors="backslashreplace")

from PySide6.QtWidgets import QApplication, QDialog                # noqa: E402

app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def pump(ms=50):
    end = time.perf_counter() + ms / 1000.0
    while time.perf_counter() < end:
        app.processEvents()
        time.sleep(0.005)


def wait_for(pred, timeout_s=60):
    end = time.perf_counter() + timeout_s
    while time.perf_counter() < end:
        app.processEvents()
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(0.01)
    return False


UTC = timezone.utc
T0 = datetime(2022, 2, 7, 10, 54, 25, 366021, tzinfo=UTC)
US = timedelta(microseconds=1)
FIVE = timedelta(minutes=5)
SYS, SEC, APP = r"C:\c\System.evtx", r"C:\c\Security.evtx", r"C:\c\App.evtx"
BL, OTH = r"C:\c\Blank.evtx", r"C:\c\Other.evtx"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ev(sf, rid, comp, when, eid=4624, provider="Microsoft-Windows-Security-Auditing", data=None):
    # Both IDs, equal as in a log collected whole: record_id is the record
    # header number, event_record_id the XML EventRecordID.
    return {"event_id": eid, "computer": comp, "source_file": sf, "record_id": rid,
            "event_record_id": rid,
            "timestamp": iso(when) if isinstance(when, datetime) else when,
            "provider": provider, "channel": "Security", "level": 4,
            "level_name": "Information", "event_data": data or {}}


def dataset():
    return [
        ev(SYS, 1000, "WS01", T0, 6011, "EventLog", {"Data": {"#text": ["OLD-NAME", "WS01"]}}),
        ev(SEC, 1, "WS01", T0 - FIVE),
        ev(SEC, 2, "WS01", T0 + FIVE),
        ev(SEC, 3, "WS01", T0 - FIVE - US),
        ev(SEC, 4, "WS01", T0 + FIVE + US),
        ev(SEC, 5, "OLD-NAME", T0 - timedelta(seconds=60)),
        ev(SEC, 6, "ws01.corp.local", T0 + timedelta(seconds=30)),
        ev(APP, 10, "WS01", T0 + timedelta(seconds=1)),
        ev(APP, 11, "HOSTX", T0 + timedelta(seconds=2)),
        ev(OTH, 20, "OTHER", T0 + timedelta(seconds=3)),
        ev(BL, 30, "", T0 + timedelta(seconds=10)),
        ev(BL, 31, "", T0 + timedelta(seconds=20)),
        ev(SEC, 7, "WS01", ""),
        ev(OTH, 21, "OTHER", T0 + timedelta(hours=2)),
    ]


HOST = {(SYS, 1000), (SEC, 1), (SEC, 2), (SEC, 5), (SEC, 6), (APP, 10)}
HOST_SUGG = HOST | {(APP, 11)}
ALL = HOST_SUGG | {(OTH, 20), (BL, 30), (BL, 31)}


def write_jm(evs, tmp):
    """A Juggernaut dataset (one Parquet shard + manifest) holding *evs*."""
    import pyarrow as pa
    import pyarrow.parquet as pq
    from evtx_tool.core.heavyweight.engine import _MANIFEST_FILENAME, _make_schema, load_arrow_table
    rows = []
    for e in evs:
        t = e["timestamp"]
        rows.append({"record_id": e["record_id"], "event_record_id": e.get("event_record_id"),
                     "event_id": e["event_id"], "level": 4,
                     "level_name": "Information",
                     "timestamp_utc": t.replace("T", " ").replace("Z", "")[:26] if t else None,
                     "channel": e["channel"], "provider": e["provider"], "computer": e["computer"],
                     "source_file": e["source_file"], "event_data_json": json.dumps(e["event_data"])})
    shard = os.path.join(tmp, "s0.parquet")
    pq.write_table(pa.Table.from_pylist(rows, schema=_make_schema()), shard)
    with open(os.path.join(tmp, _MANIFEST_FILENAME), "w", encoding="utf-8") as fh:
        json.dump([shard], fh)
    return load_arrow_table(tmp)


class Mode:
    """Load a dataset into a MainWindow in Normal or Juggernaut mode."""

    def __init__(self, mw, jm):
        self.mw, self.jm = mw, jm
        self.tmp = None

    def load(self, w, evs=None, table=None, parquet_dir=None):
        w._reset_host_identity()
        if not self.jm:
            w._events = evs
            w._event_model.set_events(evs)
            return
        from evtx_tool.gui.heavyweight_model import ArrowTableModel
        if table is None:
            self.tmp = tempfile.mkdtemp(prefix="around_")
            table, parquet_dir = write_jm(evs, self.tmp), self.tmp
        w._events = []
        w._hw_db_path = parquet_dir
        w._hw_model = ArrowTableModel(table, parquet_dir=parquet_dir, parent=w)
        w._jm_file_models = []
        wait_for(lambda: w._hw_model.rowCount() == len(table), 30)

    def main_count(self, w):
        return w._hw_model.rowCount() if self.jm else w._proxy_model.rowCount()

    def main_source(self, w):
        return w._hw_model if self.jm else w._proxy_model

    def quick_filter_main(self, w, key, value):
        if self.jm:
            w._hw_model.set_quick_filters([{"key": key, "value": value, "include": True}])
            pump(200)
            wait_for(lambda: w._hw_model._filter_thread._q.empty(), 30)
            pump(300)
        else:
            w._proxy_model.set_quick_filters([{"key": key, "value": value, "include": True}])

    def clear_main(self, w):
        if self.jm:
            w._hw_model.clear_quick_filters()
            wait_for(lambda: w._hw_model.rowCount() == len(w._hw_model._full_table), 30)
        else:
            w._proxy_model.clear_quick_filters()


def newest_tab(w):
    keys = [k for k in w._file_tabs if k.startswith("__around__")]
    return (keys[-1], w._file_tabs[keys[-1]]) if keys else (None, None)


def settle(w, key):
    return wait_for(lambda: key not in w._around_anchor_pending, 60)


def tab_rows(w, st, jm):
    if jm:
        t = st.model._display_table
        return set(zip(t["source_file"].to_pylist(), t["record_id"].to_pylist()))
    out = set()
    for r in range(st.proxy.rowCount()):
        e = st.proxy.get_source_event(r)
        out.add((e["source_file"], e["record_id"]))
    return out


def event_at(st, row, jm):
    return st.model.get_event(row) if jm else st.proxy.get_source_event(row)


def selected_key(st, jm):
    rows = st.table.selectionModel().selectedRows()
    if not rows:
        return None
    e = event_at(st, rows[0].row(), jm)
    return (e["source_file"], e["record_id"]) if e else None


def tooltip(w, st):
    return w._events_tab_widget.tabToolTip(w._events_tab_widget.indexOf(st.table))


def open_tab(w, anchor, before, after, scope, jm, filtered_from=None):
    w._open_around_tab(anchor, before, after, scope, filtered_from)
    key, st = newest_tab(w)
    if key is not None:
        settle(w, key)
        pump(50)
    return key, st


def synthetic(mw, jm):
    tag = "JM" if jm else "Normal"
    print(f"\n=== synthetic, {tag} ===", flush=True)
    m = Mode(mw, jm)
    w = mw.MainWindow()
    evs = dataset()
    m.load(w, evs)
    anchor = dict(evs[0])
    rows = {}

    for scope, want in (("host", HOST), ("host+suggested", HOST_SUGG), ("all", ALL)):
        key, st = open_tab(w, anchor, FIVE, FIVE, scope, jm)
        got = tab_rows(w, st, jm) if st else set()
        rows[scope] = got
        check(f"{tag}: ±5 min {scope} gives exactly its events", got == want,
              f"missing {sorted(want - got)}, extra {sorted(got - want)}")
        if scope == "host":
            tip = tooltip(w, st)
            check(f"{tag}: tooltip counts the event without a timestamp",
                  "1 event without a timestamp not included" in tip, tip)
            check(f"{tag}: tooltip names the hosts and why",
                  "OLD-NAME" in tip and "rename" in tip and "domain suffix" in tip, tip)
            check(f"{tag}: tooltip gives the row count", "6 events" in tip, tip)
            check(f"{tag}: the window's event count shows the tab's rows",
                  w._lbl_count.text().startswith("6 events") or w._lbl_count.text().startswith("6 /"),
                  w._lbl_count.text())
            check(f"{tag}: anchor row is selected", selected_key(st, jm) == (SYS, 1000),
                  str(selected_key(st, jm)))
            label = w._events_tab_widget.tabText(w._events_tab_widget.indexOf(st.table))
            check(f"{tag}: label names host, window and anchor time",
                  label.startswith("\u23f1 WS01 ±5 min "), label)

            # Quick filter inside the around tab: only that tab changes.
            before_main = m.main_count(w)
            w._apply_quick_filter("computer", "OLD-NAME", True)
            ok = wait_for(lambda: st.model.rowCount() == 1 if jm else st.proxy.rowCount() == 1, 30)
            check(f"{tag}: a quick filter in the around tab filters it", ok)
            check(f"{tag}: ...and leaves the main table alone", m.main_count(w) == before_main,
                  f"{m.main_count(w)} vs {before_main}")
            w._clear_quick_filters()
            wait_for(lambda: (st.model.rowCount() if jm else st.proxy.rowCount()) == len(HOST), 30)

            # Bookmark from the around tab bookmarks THAT event.
            st.table.selectRow(next(r for r in range(len(HOST))
                                    if (event_at(st, r, jm) or {}).get("record_id") == 6))
            pump(50)
            w._on_bookmark_toggle()
            check(f"{tag}: bookmark toggled in the around tab is that event",
                  (SEC, 6) in w._bookmarked_keys, str(w._bookmarked_keys))
            check(f"{tag}: ...and shows in the Bookmarks list",
                  any(b.get("record_id") == 6 and b.get("source_file") == SEC for b in w._bookmarks))

            # Nested pivot from an around tab's event.
            nested = event_at(st, next(r for r in range(len(HOST))
                                       if (event_at(st, r, jm) or {}).get("record_id") == 5), jm)
            _k, st2 = open_tab(w, nested, timedelta(minutes=1), timedelta(minutes=1), "host", jm)
            got2 = tab_rows(w, st2, jm) if st2 else set()
            check(f"{tag}: nested pivot from an around tab", got2 == {(SEC, 5), (SYS, 1000)}, str(got2))

    # Zero-width window holds the anchor.
    _k, st = open_tab(w, anchor, timedelta(0), timedelta(0), "all", jm)
    check(f"{tag}: zero window shows the anchor", tab_rows(w, st, jm) == {(SYS, 1000)},
          str(tab_rows(w, st, jm)))
    label = w._events_tab_widget.tabText(w._events_tab_widget.indexOf(st.table))
    check(f"{tag}: custom window label", "-0 s/+0 s" in label or "±0 s" in label, label)

    # Chain-tab anchor: a copy of the event dict, found by (file, record id).
    _k, st = open_tab(w, json.loads(json.dumps(anchor)), FIVE, FIVE, "host", jm)
    check(f"{tag}: a copied (chain-tab) anchor is found and selected",
          selected_key(st, jm) == (SYS, 1000), str(selected_key(st, jm)))

    # Blank Computer anchor: this host = blank-Computer events only.
    blank = dict(evs[10])
    _k, st = open_tab(w, blank, FIVE, FIVE, "host", jm)
    check(f"{tag}: blank-Computer anchor shows only blank-Computer events",
          tab_rows(w, st, jm) == {(BL, 30), (BL, 31)}, str(tab_rows(w, st, jm)))

    # Filtered snapshot.
    m.quick_filter_main(w, "event_id", "4624")
    _k, st = open_tab(w, anchor, FIVE, FIVE, "all", jm, filtered_from=m.main_source(w))
    want = ALL - {(SYS, 1000)}
    got = tab_rows(w, st, jm) if st else set()
    check(f"{tag}: snapshot holds exactly the filtered rows in the window", got == want,
          f"missing {sorted(want - got)}, extra {sorted(got - want)}")
    check(f"{tag}: snapshot tooltip says so", "Filtered snapshot" in tooltip(w, st), tooltip(w, st))
    check(f"{tag}: anchor not in the snapshot -> nearest selected, status says so",
          selected_key(st, jm) is not None
          and "nearest event selected" in w._lbl_status.text(),
          f"{selected_key(st, jm)} / {w._lbl_status.text()!r}")
    m.quick_filter_main(w, "event_id", "9999")
    _k, st = open_tab(w, anchor, FIVE, FIVE, "all", jm, filtered_from=m.main_source(w))
    check(f"{tag}: an empty snapshot still opens, saying 0 events and why",
          st is not None and "0 events" in tooltip(w, st), tooltip(w, st) if st else "no tab")
    m.clear_main(w)
    _k, st = open_tab(w, anchor, FIVE, FIVE, "all", jm, filtered_from=m.main_source(w))
    check(f"{tag}: unfiltered snapshot equals all events", tab_rows(w, st, jm) == ALL)

    # DST: Berlin springs forward at 01:00 UTC on 2026-03-29.
    from evtx_tool.gui.models import set_tz_config
    set_tz_config("specific", "Europe/Berlin")
    try:
        d0 = datetime(2026, 3, 29, 1, 30, tzinfo=UTC)
        hour = timedelta(hours=1)
        devs = [ev(SEC, 101, "DST", d0), ev(SEC, 102, "DST", d0 - hour), ev(SEC, 103, "DST", d0 + hour),
                ev(SEC, 104, "DST", d0 - hour - US), ev(SEC, 105, "DST", d0 + hour + US)]
        w2 = mw.MainWindow()
        m2 = Mode(mw, jm)
        m2.load(w2, devs)
        _k, st = open_tab(w2, dict(devs[0]), hour, hour, "all", jm)
        check(f"{tag}: DST window includes by UTC instant",
              tab_rows(w2, st, jm) == {(SEC, 101), (SEC, 102), (SEC, 103)}, str(tab_rows(w2, st, jm)))
        tip = tooltip(w2, st)
        check(f"{tag}: window start shown at +01:00", "2026-03-29 01:30:00.000000 +01:00" in tip, tip)
        check(f"{tag}: window end shown at +02:00", "2026-03-29 04:30:00.000000 +02:00" in tip, tip)
        teardown(w2, jm, m2)
    finally:
        set_tz_config("local")

    teardown(w, jm, m)
    return rows


def teardown(w, jm, m):
    # Arrow-backed around tabs only: a snapshot of a chain tab is built from
    # event dicts and has no filter thread.
    models = [st.model for k, st in w._file_tabs.items()
              if k.startswith("__around__") and hasattr(st.model, "_filter_thread")]
    w._clear_results()
    if jm:
        check("JM: Clear stops every around model's filter thread",
              all(not mdl._filter_thread.isRunning() for mdl in models), str(len(models)))
    w.close()
    if m.tmp:
        shutil.rmtree(m.tmp, ignore_errors=True)


def jm_close_stops_thread(mw):
    print("\n=== JM: closing an around tab stops its thread ===", flush=True)
    m = Mode(mw, True)
    w = mw.MainWindow()
    m.load(w, dataset())
    key, st = open_tab(w, dict(dataset()[0]), FIVE, FIVE, "all", True)
    th = st.model._filter_thread
    w._close_file_tab(key)
    check("JM: closing the tab stops its filter thread", not th.isRunning())
    teardown(w, True, m)


def separate_mode_routing(mw):
    print("\n=== separate mode: a quick filter in an around tab asks nothing ===", flush=True)
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
        w = mw.MainWindow()
        Mode(mw, False).load(w, dataset())
        w._view_mode = "separate"
        _k, st = open_tab(w, dict(dataset()[0]), FIVE, FIVE, "host", False)
        w._apply_quick_filter("computer", "OLD-NAME", True)
        check("separate mode: no file-target question for an around tab", not calls)
        check("separate mode: the around tab is filtered", st.proxy.rowCount() == 1,
              str(st.proxy.rowCount()))
        w._view_mode = "merged"
        w._clear_results()
        w.close()
    finally:
        mw._FilterTargetDialog = orig


def large(mw):
    print("\n=== Normal: ±365 days over 500k events ===", flush=True)
    w = mw.MainWindow()
    n = 500_000
    base = datetime(2022, 1, 1, tzinfo=UTC)
    evs = [ev(SEC, i, f"H{i % 50}", base + timedelta(seconds=i)) for i in range(n)]
    Mode(mw, False).load(w, evs)
    t = time.perf_counter()
    w._open_around_tab(dict(evs[n // 2]), timedelta(days=365), timedelta(days=365), "all", None)
    dt = time.perf_counter() - t
    _k, st = newest_tab(w)
    check("500k events, ±365 days: every event, in under 3 s",
          st is not None and st.proxy.rowCount() == n and dt < 3.0,
          f"{dt:.2f} s, {st.proxy.rowCount() if st else 0} rows")
    w._clear_results()
    w.close()


def real(mw):
    root = os.environ.get("EVTX_TEST_LOGS_ONLINE", "")
    if not root or not os.path.isdir(root):
        print("\nEVTX_TEST_LOGS_ONLINE not set -- real-data block skipped")
        return
    print("\n=== real data: Win 10 rename window ===", flush=True)
    from evtx_tool.core.parser import iter_events
    from evtx_tool.core.time_window import parse_event_ts
    files = [os.path.join(root, "win10-client", "Logs_Client", f) for f in ("Security.evtx", "System.evtx")]
    evs = [e for f in files for e in iter_events(f)]
    anchor = next(e for e in evs if e["event_id"] == 6011
                  and e["timestamp"].startswith("2022-02-07T10:54:25.366021"))
    a = parse_event_ts(anchor["timestamp"])
    inwin = [e for e in evs if (lambda t: t is not None and a - FIVE <= t <= a + FIVE)(
        parse_event_ts(e["timestamp"]))]
    want_setup = sum(1 for e in inwin if e["computer"] == "WIN-VR474TJ38H3")
    check("real: independent count has 255 WIN-VR474TJ38H3 events", want_setup == 255, str(want_setup))
    for jm in (False, True):
        tag = "JM" if jm else "Normal"
        w = mw.MainWindow()
        m = Mode(mw, jm)
        tmp = None
        if jm:
            from evtx_tool.core.heavyweight.engine import HeavyweightEngine, load_arrow_table
            tmp = tempfile.mkdtemp(prefix="around_real_")
            pq = HeavyweightEngine(parquet_dir=tmp).run(files)
            m.load(w, table=load_arrow_table(pq), parquet_dir=pq)
        else:
            m.load(w, evs)
        _k, st = open_tab(w, dict(anchor), FIVE, FIVE, "host", jm)
        n = st.model.rowCount() if jm else st.proxy.rowCount()
        check(f"real {tag}: ±5 min this host = every event in the window", n == len(inwin),
              f"{n} vs {len(inwin)}")
        setup_rows = 0
        for r in range(n):
            e = event_at(st, r, jm) if not jm else None
            if not jm and e["computer"] == "WIN-VR474TJ38H3":
                setup_rows += 1
        if jm:
            setup_rows = st.model._display_table["computer"].to_pylist().count("WIN-VR474TJ38H3")
        check(f"real {tag}: includes the 255 setup-name events", setup_rows == 255, str(setup_rows))
        w._clear_results()
        w.close()
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    import evtx_tool.gui.main_window as mw
    normal = synthetic(mw, False)
    jm = synthetic(mw, True)
    check("Normal and Juggernaut give identical row sets", normal == jm,
          str({k: (sorted(normal[k] ^ jm.get(k, set()))) for k in normal}))
    jm_close_stops_thread(mw)
    separate_mode_routing(mw)
    large(mw)
    real(mw)

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
