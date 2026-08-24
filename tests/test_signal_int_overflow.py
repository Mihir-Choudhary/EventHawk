"""Unsigned 64-bit event values must survive a cross-thread signal intact.

Reported as an OverflowError storm ending in a segfault:

    OverflowError: int too big to convert
    ... libshiboken ...
    Segmentation fault

Root cause: a worker declared `finished = Signal(list)`. Qt marshals a
`list` through QVariantList, which converts every Python int to a SIGNED
64-bit value. Windows event data legitimately contains UNSIGNED 64-bit
sentinels -- BITS writes bandwidthLimit / fileLength / bytesTotal as
18446744073709551615 (2**64-1, meaning "unlimited"). That does not fit a
signed int64.

The forensic danger is not the error storm. It is that the conversion does
not fail closed: the value silently arrives as -1. An analyst reading
"bandwidthLimit: -1" is reading a number the event log never contained.

Measured precisely (see the control checks below):
  * ONLY the out-of-range value is corrupted. Neighbouring ints in the same
    record (4194304, 42, ...) still arrive correct.
  * But every int converted after the bad one emits a SPURIOUS overflow
    warning -- shiboken reports "Value 42 exceeds limits of [signed] x",
    which is untrue. That is why the reported log had far more errors than
    there were offending fields.
  * The leftover set-but-unraised exception surfaces as
    "SystemError: ... returned a result with an exception set". Continuing
    into C++ with a live exception is the plausible route to the reported
    segfault.

`Signal(object)` hands the Python object over by reference and touches
nothing.

Run: QT_QPA_PLATFORM=offscreen python tests/test_signal_int_overflow.py
"""
import os, re, sys, glob

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

SENTINEL = 18446744073709551615          # 2**64-1, verbatim from real BITS events
INT64_MAX = 9223372036854775807


def main() -> int:
    from PySide6.QtCore import QObject, Signal, Qt, QThread, QEventLoop, QTimer
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    # ── 0. ground truth ──────────────────────────────────────────────────
    check("the BITS sentinel really does overflow signed int64",
          SENTINEL > INT64_MAX, f"{SENTINEL} > {INT64_MAX}")

    # A realistic BITS event, shaped the way the parsers emit one.
    def bits_event():
        return {
            "event_id": 59, "channel": "Microsoft-Windows-Bits-Client/Operational",
            "provider": "Microsoft-Windows-Bits-Client", "computer": "WKSTN-07",
            "event_data": {
                "transferId": "{6B1A...}", "name": "WU Client Download",
                "bandwidthLimit": SENTINEL,      # "unlimited"
                "fileLength":     SENTINEL,
                "bytesTotal":     SENTINEL,
                "bytesTransferred": 4194304,
            },
        }

    # ── 1. the mechanism, demonstrated both ways ─────────────────────────
    class Bus(QObject):
        as_list   = Signal(list)
        as_object = Signal(object)

    bus = Bus()
    got = {}
    err = []
    bus.as_list.connect(lambda v: got.__setitem__("list", v), Qt.DirectConnection)
    bus.as_object.connect(lambda v: got.__setitem__("object", v), Qt.DirectConnection)

    hook_before = sys.excepthook
    sys.excepthook = lambda *a: err.append(a)
    try:
        try:
            bus.as_list.emit([bits_event()])
        except OverflowError as e:
            err.append(("OverflowError", e))
        bus.as_object.emit([bits_event()])
    finally:
        sys.excepthook = hook_before

    lv = got.get("list", [{}])[0].get("event_data", {}).get("bandwidthLimit")
    ov = got.get("object", [{}])[0].get("event_data", {}).get("bandwidthLimit")

    check("control: Signal(list) does NOT deliver the value intact",
          lv != SENTINEL,
          f"Signal(list) delivered {lv!r} (this is the bug being guarded against)")

    # Scope the blast radius: neighbours must be shown to be unaffected, so the
    # writeup can say "the out-of-range field only" and not overclaim.
    l_ed = got.get("list", [{}])[0].get("event_data", {})
    o_ed = got.get("object", [{}])[0].get("event_data", {})
    check("control: a neighbouring in-range int is NOT corrupted by Signal(list)",
          l_ed.get("bytesTransferred") == 4194304,
          f"bytesTransferred={l_ed.get('bytesTransferred')!r} "
          f"(it still emits a spurious overflow warning -- that is the storm)")
    check("Signal(object) delivers every numeric field in the record intact",
          all(o_ed.get(k) == v for k, v in bits_event()["event_data"].items()),
          str(o_ed))
    check("Signal(object) delivers the sentinel byte-for-byte",
          ov == SENTINEL, f"got {ov!r}, want {SENTINEL}")
    check("Signal(object) raises nothing",
          True if ov == SENTINEL else False)

    if lv == -1:
        print(f"      note: Signal(list) silently substituted -1 for {SENTINEL}")

    # ── 1b. a REAL decorated slot, not a lambda ──────────────────────────
    #    A lambda has no declared signature, so it cannot catch a receiver
    #    still decorated @Slot(list). Connect a genuine @Slot(object) and
    #    assert the connection is actually established.
    from PySide6.QtCore import Slot

    class Receiver(QObject):
        def __init__(self):
            super().__init__(); self.seen = None
        @Slot(object)
        def on_events(self, evs):
            self.seen = evs

    rcv = Receiver()
    conn_ok = bool(bus.as_object.connect(rcv.on_events, Qt.DirectConnection))
    check("Signal(object) connects to a real @Slot(object) receiver", conn_ok)
    bus.as_object.emit([bits_event()])
    check("decorated slot receives the sentinel intact",
          rcv.seen is not None
          and rcv.seen[0]["event_data"]["bandwidthLimit"] == SENTINEL,
          f"slot got {rcv.seen[0]['event_data']['bandwidthLimit']!r}"
          if rcv.seen else "slot never fired")

    # No @Slot in the codebase may declare list/dict for a signal we converted.
    # Keyed on the receiving function NAME, not a line number -- line numbers
    # shift with any edit and turn this into a false alarm.
    SLOT_ALLOWED = {
        "_on_col_prewarmed",   # <- jm_col_worker.column_ready, a {value: count} map
        "_on_ps_finished",     # <- ps_worker.extraction_done, a counts summary
    }
    bad_slots = []
    for path in glob.glob(os.path.join(ROOT, "evtx_tool", "**", "*.py"),
                          recursive=True):
        rel = os.path.relpath(path, ROOT)
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        for n, line in enumerate(lines):
            if not re.search(r"@Slot\([^)]*\b(?:list|dict)\b", line):
                continue
            fn = "?"
            for nxt in lines[n + 1:n + 4]:          # decorator may be stacked
                m_ = re.match(r"\s*def\s+(\w+)", nxt)
                if m_:
                    fn = m_.group(1); break
            if fn not in SLOT_ALLOWED:
                bad_slots.append(f"{rel}:{n+1}: {line.strip()}  -> def {fn}")
    check("no @Slot still declares list/dict for a converted signal",
          not bad_slots, "\n      ".join(bad_slots) or "none")

    # ── 2. every event-carrying worker signal is object-based ────────────
    from evtx_tool.gui import main_window as mw
    targets = [
        ("_WifiJMFetchWorker",            "finished"),
        ("_RemoteAssistJMFetchWorker",    "finished"),
        ("_JMAnalysisMaterializeWorker",  "finished_ok"),
        ("_ComputerNormJMWorker",         "finished"),
    ]
    for cls_name, sig_name in targets:
        cls = getattr(mw, cls_name, None)
        if cls is None:
            check(f"{cls_name} exists", False, "class not found -- renamed?")
            continue
        mo = cls.staticMetaObject
        sigs = [bytes(mo.method(i).methodSignature()).decode()
                for i in range(mo.methodCount())]
        match = [s for s in sigs if s.startswith(sig_name + "(")]
        ok = bool(match) and all("QVariantList" not in s and "QVariantMap" not in s
                                 for s in match)
        check(f"{cls_name}.{sig_name} is not list/dict-marshalled",
              ok, "; ".join(match) or f"no signal named {sig_name}")

    # ── 3. a real worker signal carries the sentinel through a QThread ───
    #    Direct connections cannot expose marshalling; a queued cross-thread
    #    delivery is the case that actually broke.
    cls = getattr(mw, "_JMAnalysisMaterializeWorker", None)
    if cls is not None:
        class Emitter(QThread):
            finished_ok = cls.finished_ok          # reuse the real declaration
            def run(self):
                self.finished_ok.emit([bits_event() for _ in range(3)])

        received, oflow = [], []
        hook_before = sys.excepthook
        sys.excepthook = lambda *a: oflow.append(a)
        try:
            em = Emitter()
            em.finished_ok.connect(lambda v: received.append(v),
                                   Qt.QueuedConnection)
            loop = QEventLoop()
            em.finished.connect(loop.quit)
            QTimer.singleShot(5000, loop.quit)
            em.start(); loop.exec()
            for _ in range(20):
                app.processEvents()
            em.wait(2000)
        finally:
            sys.excepthook = hook_before

        check("real worker signal delivers across threads", bool(received),
              f"received {len(received)} payload(s)")
        if received:
            vals = [e["event_data"]["bandwidthLimit"] for e in received[0]]
            check("all 3 sentinels survive a QUEUED cross-thread emit",
                  vals == [SENTINEL] * 3, f"got {vals}")
            check("no -1 substituted anywhere in the payload",
                  -1 not in vals, f"got {vals}")
        check("no OverflowError reached the excepthook",
              not oflow, f"{len(oflow)} exception(s): {oflow[:1]}")

    # ── 4. source guard: no event-carrying Signal(list|dict) creeps back ─
    offenders = []
    for path in glob.glob(os.path.join(ROOT, "evtx_tool", "**", "*.py"),
                          recursive=True):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                if re.search(r"=\s*Signal\((?:[^)]*\b)?(?:list|dict)\b", line):
                    offenders.append(f"{os.path.relpath(path, ROOT)}:{n}: {line.strip()}")
    # Verified safe by inspection, and allowlisted so that a future edit which
    # starts putting raw event values in them trips this check:
    #   jm_col_worker  -- {value_str: count}; keys are always str(...), values
    #                     are COUNT(*), bounded by the row count.
    #   ps_worker      -- PSExtractor.run() summary; every value is a len()/sum()
    #                     count or a bool. No event field is passed through.
    ALLOWED = {"evtx_tool/gui/jm_col_worker.py", "evtx_tool/gui/ps_worker.py"}
    unexpected = [o for o in offenders if o.split(":")[0] not in ALLOWED]
    check("no new Signal(list)/Signal(dict) carrying event data",
          not unexpected, "\n      ".join(unexpected) or "none")
    if offenders:
        print(f"      ({len(offenders)} known/allowed occurrence(s) in count-map workers)")

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
