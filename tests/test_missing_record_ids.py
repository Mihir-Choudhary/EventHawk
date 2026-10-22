"""Identify Missing Record IDs must not freeze on a damaged record ID.

The analysis built set(range(lo, hi + 1)) for every file.  One record with a
corrupt, huge EventRecordID -- exactly what damaged evidence produces --
turned that into billions of integers on the GUI thread.  Measured on the
pre-fix build: a single ID of 10**8 froze the window for 18 s; 10**15 never
returned.  The gaps are now computed between consecutive IDs.

The report itself must not change: it is compared, section by section,
against an independent reference over randomised ID sets.
"""
import os
import random
import sys
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtWidgets import QApplication                       # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def reference_missing(ids):
    """Independent reference: every absent ID in [lo, hi], small spans only."""
    s = sorted(set(ids))
    present = set(s)
    return [i for i in range(s[0], s[-1] + 1) if i not in present]


def run(w, mw, events):
    w._events = events
    got = {}

    class FakeDlg:
        def __init__(self, **kw):
            got.update(kw)

        def exec(self):
            pass
    mw._MissingRecordIdDialog = FakeDlg
    w._on_identify_missing_record_ids()
    return got


def main() -> int:
    import evtx_tool.gui.main_window as mw
    w = mw.MainWindow()
    type(w)._active_events = property(lambda self: self._events)

    print("=== 1. the report matches an independent reference ===")
    rng = random.Random(4)
    mismatches = []
    for trial in range(200):
        n = rng.randint(1, 60)
        lo = rng.randint(1, 5000)
        ids = sorted(rng.sample(range(lo, lo + rng.randint(n, 3 * n + 5)), n))
        ids += rng.sample(ids, min(3, len(ids)))          # duplicates too
        got = run(w, mw, [{"record_id": i, "source_file": "a.evtx"} for i in ids])
        want = len(reference_missing(ids))
        sec = got.get("sections", [""])[0]
        miss = reference_missing(ids)
        # every missing ID must lie in one of the printed ranges
        printed = sec.split("</span> ")[-1] if want else ""
        covered = set()
        for part in filter(None, printed.split(", ")):
            a, _, b = part.partition("–")
            covered.update(range(int(a), int(b or a) + 1))
        if got.get("total_missing") != want or (want and covered != set(miss)):
            mismatches.append((ids, got.get("total_missing"), want))
    check("200 random ID sets: counts and ranges equal the reference",
          not mismatches, str(mismatches[:1]))

    got = run(w, mw, [{"record_id": i, "source_file": "a.evtx"} for i in (1, 2, 3, 4)])
    check("a complete sequence reports no gaps",
          got.get("total_missing") == 0
          and "No gaps" in got.get("sections", [""])[0])
    got = run(w, mw, [{"record_id": i, "source_file": f} for i, f in
                      ((1, "a"), (3, "a"), (10, "b"), (11, "b"), (14, "b"))])
    check("files are analysed separately (each has its own ID space)",
          got.get("total_missing") == 3 and got.get("file_count") == 2,
          str(got.get("total_missing")))

    print("\n=== 2. a damaged huge record ID does not freeze the window ===")
    done = threading.Event()

    def watchdog():
        if not done.wait(20):
            print("  FAIL  a record ID of 10**15 is analysed promptly  "
                  "-- still computing after 20 s (hang)", flush=True)
            os._exit(1)
    threading.Thread(target=watchdog, daemon=True).start()
    t0 = time.monotonic()
    got = run(w, mw, [{"record_id": i, "source_file": "Security.evtx"}
                      for i in (1, 2, 3, 5, 10 ** 15)])
    el = time.monotonic() - t0
    done.set()
    check("a record ID of 10**15 is analysed promptly", el < 2.0, f"{el:.2f}s")
    check("...and its gap is counted exactly",
          got.get("total_missing") == 1 + (10 ** 15 - 6),
          f"{got.get('total_missing')}")
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
