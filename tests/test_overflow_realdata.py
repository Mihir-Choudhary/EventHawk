"""End-to-end proof on REAL logs that unsigned 64-bit event values survive.

Synthetic dicts prove the mechanism; they do not prove the app is fixed. This
parses the actual Microsoft-Windows-Bits-Client logs, takes ground truth
straight from Parquet with DuckDB, then runs the REAL
_JMAnalysisMaterializeWorker on a REAL QThread and compares every value.

Ground truth on this corpus: 1,444 fields exceeding signed int64 across 353
records of 4,712 (bandwidthLimit x1404, fileLength x20, bytesTotal x20 --
all 18446744073709551615, BITS's "unlimited").

Both shiboken failure channels are captured, because it uses two:
  * RuntimeWarning "libshiboken: Overflow: ..."   (does NOT raise)
  * OverflowError  "int too big to convert"

Exit code is meaningful: run this as a SUBPROCESS to tell a clean failure from
a segfault (returncode -11).

Run: QT_QPA_PLATFORM=offscreen python tests/test_overflow_realdata.py [LOGS_DIR]
"""
import os, sys, glob, json, tempfile, shutil, warnings, threading, collections

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

INT64_MAX = 9223372036854775807
INT64_MIN = -9223372036854775808
SENTINEL  = 18446744073709551615


def _out_of_range(v):
    return isinstance(v, int) and not isinstance(v, bool) and not (INT64_MIN <= v <= INT64_MAX)


def main() -> int:
    # ── capture BOTH shiboken channels before Qt is touched ──────────────
    shiboken_warnings, hook_errors = [], []
    warnings.simplefilter("always")
    _orig_showwarning = warnings.showwarning
    def _capture(message, category, filename, lineno, file=None, line=None):
        shiboken_warnings.append(f"{category.__name__}: {message}")
    warnings.showwarning = _capture
    # Record AND still print. A collector that swallows tracebacks turns a
    # real failure into a silent early exit -- which is exactly what happened
    # the first time this ran against pre-fix code.
    _orig_excepthook = sys.excepthook
    def _hook(et, ev, tb):
        hook_errors.append(f"{et.__name__}: {ev}")
        _orig_excepthook(et, ev, tb)
    sys.excepthook = _hook
    def _thook(a):
        hook_errors.append(f"[thread] {a.exc_type.__name__}: {a.exc_value}")
        import traceback; traceback.print_exception(a.exc_type, a.exc_value, a.exc_traceback)
    threading.excepthook = _thook

    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt, QEventLoop, QTimer
    app = QApplication.instance() or QApplication([])

    from evtx_tool.core.heavyweight.engine import HeavyweightEngine
    from evtx_tool.gui.main_window import _JMAnalysisMaterializeWorker
    import duckdb

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    LOGS = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("EVTX_TEST_LOGS", "sample_logs")
    files = sorted(glob.glob(os.path.join(LOGS, "*Bits-Client*.evtx")))
    if not files:
        print(f"no BITS logs under {LOGS} — cannot run this proof"); return 0
    print(f"{len(files)} BITS file(s) from {LOGS}")

    tmp = tempfile.mkdtemp(prefix="ovf_real_")
    try:
        pq = HeavyweightEngine(parquet_dir=tmp).run(files)
        shards = json.load(open(os.path.join(pq, "parquet_manifest.json")))
        quoted = "[" + ", ".join(f"'{p}'" for p in shards) + "]"

        # ── ground truth, straight from Parquet, no Qt involved ──────────
        con = duckdb.connect()
        rows = con.execute(
            f"SELECT source_file, record_id, event_data_json "
            f"FROM parquet_scan({quoted})").fetchall()
        con.close()

        # Keyed on (source_file, record_id), NOT record_id alone: this corpus
        # contains copies of the same log, so record_id repeats across files.
        # Keying on it collapsed 1,444 real occurrences into 361 and silently
        # left three quarters of the data unchecked.
        truth = {}                       # (src, rid) -> {field: exact value}
        minus_one_truth = 0              # real -1s already in the logs
        for src, rid, blob in rows:
            if not blob:
                continue
            try:
                d = json.loads(blob)
            except Exception:
                continue
            for k, v in d.items():
                if _out_of_range(v):
                    truth.setdefault((src, rid), {})[k] = v
                elif v == -1:
                    minus_one_truth += 1
        n_truth = sum(len(x) for x in truth.values())
        print(f"{len(rows):,} rows — ground truth: {n_truth} out-of-range field(s) "
              f"in {len(truth)} record(s); {minus_one_truth} genuine -1(s)\n")
        assert n_truth == sum(len(v) for v in truth.values())

        check("the corpus actually contains out-of-range values (test is meaningful)",
              n_truth > 0, f"{n_truth} field(s)")

        # ── run the REAL worker on a REAL thread ─────────────────────────
        worker = _JMAnalysisMaterializeWorker(pq, limit=0)
        delivered, failures = [], []
        worker.finished_ok.connect(lambda evs: delivered.append(evs), Qt.QueuedConnection)
        worker.failed.connect(lambda m: failures.append(m), Qt.QueuedConnection)
        loop = QEventLoop()
        worker.finished.connect(loop.quit)
        QTimer.singleShot(600_000, loop.quit)
        worker.start(); loop.exec()
        for _ in range(50):
            app.processEvents()
        worker.wait(30_000)

        check("the real worker delivered its payload", bool(delivered),
              f"failures={failures[:1]}")
        if not delivered:
            raise SystemExit(_report(res))

        events = delivered[0]
        check("every row was rebuilt", len(events) == len(rows),
              f"{len(events):,} delivered vs {len(rows):,} in Parquet")

        # ── compare EVERY out-of-range value against ground truth ────────
        by_rid = {(e.get("source_file"), e.get("record_id")): e for e in events}
        check("the (source_file, record_id) key is unique across the corpus",
              len(by_rid) == len(events),
              f"{len(by_rid)} keys for {len(events)} events -- a collision would "
              f"leave rows unchecked")
        exact, wrong, missing = 0, [], 0
        for key, fields in truth.items():
            ev = by_rid.get(key)
            if ev is None:
                missing += len(fields); continue
            ed = ev.get("event_data") or {}
            for k, want in fields.items():
                got = ed.get(k)
                if got == want:
                    exact += 1
                else:
                    wrong.append(f"{key} {k}: got {got!r}, want {want!r}")
        check(f"all {n_truth} out-of-range values survived byte-for-byte",
              exact == n_truth and not wrong and not missing,
              (f"exact={exact} wrong={len(wrong)} missing={missing}\n      "
               + "\n      ".join(wrong[:3])) if (wrong or missing) else
              f"{exact}/{n_truth} exact")

        # The specific corruption signature: 2**64-1 arriving as -1.
        delivered_minus_one = sum(
            1 for e in events for v in (e.get("event_data") or {}).values()
            if v == -1 and not isinstance(v, bool))
        check("no -1 was fabricated (count matches the logs exactly)",
              delivered_minus_one == minus_one_truth,
              f"delivered {delivered_minus_one} vs {minus_one_truth} genuinely in the logs")

        sentinels = sum(1 for e in events
                        for v in (e.get("event_data") or {}).values() if v == SENTINEL)
        check(f"the {SENTINEL} sentinel is present in the delivered events",
              sentinels == n_truth, f"{sentinels} found, expected {n_truth}")

        # ── the OTHER QVariant boundary: index.data(UserRole) ────────────
        # A bare dict returned for UserRole is coerced to QVariantMap and
        # raises OverflowError on these very events; EventRef exists to stop
        # that.  Built straight from GROUND TRUTH, not from the worker's
        # output -- comparing the delivered events against themselves is
        # vacuous once they have already been corrupted, which is exactly how
        # this check passed against pre-fix code the first time.
        from evtx_tool.gui import models as _models
        from evtx_tool.gui.models import EventTableModel, EventFilterProxyModel
        EventRef = getattr(_models, "EventRef", None)   # absent on pre-fix code

        ur_events, ur_expect = [], []
        for src, rid, blob in rows:
            fields = truth.get((src, rid))
            if not fields:
                continue
            ur_events.append({
                "record_id": rid, "source_file": src, "event_id": 59,
                "timestamp": "2024-01-01T00:00:00Z", "level_name": "Information",
                "channel": "Bits-Client/Operational", "provider": "BITS",
                "computer": "", "user_id": "", "keywords": "",
                "event_data": json.loads(blob),
            })
            ur_expect.append(fields)
            if len(ur_events) >= 200:
                break

        tm = EventTableModel(); tm.set_events(ur_events)
        px = EventFilterProxyModel(); px.setSourceModel(tm)
        ok_ur, err_ur = 0, []
        for r in range(px.rowCount()):
            try:
                ref = px.index(r, 0).data(Qt.ItemDataRole.UserRole)   # C++ round trip
                ev = ref.event if (EventRef and isinstance(ref, EventRef)) else ref
                ed = (ev or {}).get("event_data") or {}
                bad = {k: (ed.get(k), want) for k, want in ur_expect[r].items()
                       if ed.get(k) != want}
                if bad:
                    err_ur.append(f"row {r}: {bad}")
                else:
                    ok_ur += 1
            except Exception as exc:
                err_ur.append(f"row {r}: {type(exc).__name__}: {exc}")
        check(f"index.data(UserRole) round-trips {len(ur_events)} REAL events "
              f"carrying out-of-range values",
              ur_events and ok_ur == len(ur_events) and not err_ur,
              f"ok={ok_ur}/{len(ur_events)}  " + "; ".join(str(e)[:90] for e in err_ur[:2]))

        # ── neither shiboken channel fired, anywhere in the run ──────────
        app.processEvents()
        overflow_warnings = [w for w in shiboken_warnings
                             if "shiboken" in w.lower() or "overflow" in w.lower()]
        check("no libshiboken overflow WARNING during the whole run",
              not overflow_warnings,
              f"{len(overflow_warnings)} warning(s): {overflow_warnings[:2]}")
        overflow_errors = [e for e in hook_errors if "Overflow" in e or "SystemError" in e]
        check("no OverflowError / SystemError reached any excepthook",
              not overflow_errors,
              f"{len(overflow_errors)}: {overflow_errors[:2]}")
    finally:
        warnings.showwarning = _orig_showwarning
        shutil.rmtree(tmp, ignore_errors=True)

    return _report(res)


def _report(res) -> int:
    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
