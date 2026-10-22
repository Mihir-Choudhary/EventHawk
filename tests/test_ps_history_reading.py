"""PowerShell History must say what it could not read, where it can be seen.

PSWorker streams records from each EVTX straight into the extractor.
pyevtx-rs's records_json() yields an exception OBJECT for a record it cannot
decode; the worker indexed it like a dict, the TypeError escaped the inner
loop, and the rest of that file was abandoned under one log line.  That line,
like every read failure (a file that will not open, a read that stops
part-way), never reached the summary, the output files or the dialog, which
reported "Parse errors: 0".  And the result and failure dialogs, raised when
the background job ends, used plain exec() -- the hidden-modal hazard of
issue #4.

Real-corpus comparison (4 files: PowerShell Admin [empty], Operational,
Windows PowerShell, one unreadable): both builds extract 7,604 PS events /
368 script blocks / 874 sessions with byte-identical script block files; only
the fixed build reports the unreadable file, and opens its dialog on top.
"""
import json
import os
import sys
import tempfile
import types

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import QTimer, Qt                             # noqa: E402
from PySide6.QtWidgets import QApplication, QMessageBox           # noqa: E402

_app = QApplication.instance() or QApplication([])

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def _ps_record(rid):
    data = {"Event": {
        "System": {"Channel": "Microsoft-Windows-PowerShell/Operational",
                   "EventID": 4104, "Computer": "HOST",
                   "TimeCreated": {"#attributes": {"SystemTime": "2026-02-17T20:49:12.000000Z"}}},
        "EventData": {"MessageNumber": 1, "MessageTotal": 1,
                      "ScriptBlockText": f"Write-Output {rid}",
                      "ScriptBlockId": f"00000000-0000-0000-0000-{rid:012d}", "Path": ""},
    }}
    return {"event_record_id": rid, "timestamp": "2026-02-17 20:49:12.000000 UTC",
            "data": json.dumps(data)}


def _fake_evtx(files):
    """A stand-in `evtx` module: *files* maps a path to a list of items to
    yield, where an Exception instance is yielded as-is (as pyevtx-rs does for
    a corrupt record) and the string "RAISE" makes the iterator raise."""
    class PyEvtxParser:
        def __init__(self, path):
            if path not in files:
                raise OSError("failed to read EVTX file header block")
            self._items = files[path]

        def records_json(self):
            for item in self._items:
                if item == "RAISE":
                    raise RuntimeError("Failed to build string cache")
                yield item
    return types.SimpleNamespace(PyEvtxParser=PyEvtxParser)


def run_worker(files, order):
    from evtx_tool.gui.ps_worker import PSWorker
    saved = sys.modules.get("evtx")
    sys.modules["evtx"] = _fake_evtx(files)
    out = tempfile.mkdtemp(prefix="ps_hist_")
    try:
        w = PSWorker(order, out)
        got = {}
        w.extraction_done.connect(lambda s: got.update(summary=s))
        w.extraction_error.connect(lambda tb: got.update(error=tb))
        w.run()                       # synchronously, in this thread
        summary = got.get("summary", {})
        try:
            with open(os.path.join(out, "ps_extraction_summary.txt"), encoding="utf-8") as fh:
                summary_txt = fh.read()
        except OSError:
            summary_txt = ""
        return summary, summary_txt, got.get("error")
    finally:
        if saved is not None:
            sys.modules["evtx"] = saved
        else:
            sys.modules.pop("evtx", None)


def main() -> int:
    print("=== 1. a corrupt record does not abandon the rest of its file ===")
    files = {"a.evtx": [_ps_record(1), RuntimeError("bad record"), _ps_record(3)]}
    s, txt, err = run_worker(files, ["a.evtx"])
    check("no unhandled error", err is None, (err or "")[-200:])
    check("both readable records are scanned", s.get("total_scanned") == 2,
          f"total_scanned={s.get('total_scanned')}")
    check("the skipped record is counted as an error", s.get("parse_errors", 0) >= 1,
          f"parse_errors={s.get('parse_errors')}")
    check("...and named in ps_extraction_summary.txt",
          "1 corrupt record(s) skipped" in txt)

    print("\n=== 2. an unreadable file is reported, not just logged ===")
    files = {"good.evtx": [_ps_record(1)]}
    s, txt, err = run_worker(files, ["good.evtx", "bad.evtx"])
    check("the readable file is still extracted", s.get("total_scanned") == 1)
    check("the unreadable file counts as an error", s.get("parse_errors", 0) >= 1,
          f"parse_errors={s.get('parse_errors')}")
    msgs = " ".join(s.get("error_messages") or [])
    check("the dialog gets the message", "bad.evtx: could not be read" in msgs, msgs[:150])
    check("...and so does ps_extraction_summary.txt", "bad.evtx: could not be read" in txt)

    print("\n=== 3. a read that stops part-way keeps what was read, and says so ===")
    files = {"c.evtx": [_ps_record(1), _ps_record(2), "RAISE", _ps_record(4)]}
    s, txt, err = run_worker(files, ["c.evtx"])
    check("the records before the failure are kept", s.get("total_scanned") == 2)
    check("the early stop is reported with how far it got",
          "c.evtx: could not read past record 2" in txt)

    print("\n=== 4. end-of-job dialogs open on top ===")
    from evtx_tool.gui.main_window import MainWindow
    w = MainWindow()
    seen = []

    def inspect():
        m = _app.activeModalWidget()
        if isinstance(m, QMessageBox):
            seen.append({"title": m.windowTitle(), "icon": m.icon(),
                         "on_top": bool(m.windowFlags() & Qt.WindowType.WindowStaysOnTopHint),
                         "detail": m.detailedText()})
            m.done(0)
    t = QTimer(); t.timeout.connect(inspect); t.start(30)
    w._ps_output_dir = tempfile.gettempdir()
    w._on_ps_finished({"total_ps_events": 1, "script_blocks": 1, "sessions": 0,
                       "partial_blocks": 0, "safety_net": 0, "parse_errors": 1,
                       "error_messages": ["bad.evtx: could not be read (x)"]})
    w._on_ps_error("Traceback: boom")
    t.stop()
    by = {d["title"]: d for d in seen}
    done = by.get("PowerShell History — Complete", {})
    fail = by.get("PowerShell History — Failed", {})
    check("the result dialog is on top", done.get("on_top") is True)
    check("a result with errors is a Warning, not Information",
          done.get("icon") == QMessageBox.Icon.Warning)
    check("the result dialog lists the errors", "bad.evtx" in done.get("detail", ""))
    check("the failure dialog is on top", fail.get("on_top") is True)
    w.close()

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
