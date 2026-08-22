"""One analysis section failing must not take the others down with it.

Reported: "if one of the analysis sections fails, none of them are loaded."
Two causes, both fixed:
  1. anything escaping a component's own try/except aborted the whole worker
     before it ever sent a result, so completed work was thrown away;
  2. the runner drains the PROGRESS queue before the RESULT queue, and an
     "error" message returned immediately -- discarding a result already
     sitting in the result queue.

A partial result must also never be silent: an empty IOC tab has to be
distinguishable from "IOC extraction crashed".

Run: python tests/test_analysis_partial.py
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main() -> int:
    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    import multiprocessing as mp
    from multiprocessing.shared_memory import SharedMemory
    import evtx_tool.analysis.analysis_worker_proc as awp
    from evtx_tool.core._json_compat import fast_dumps

    events = [{
        "record_id": i, "event_id": 4688, "level_name": "Information",
        "timestamp": f"2025-06-10T09:00:{i%60:02d}.000000Z",
        "computer": "HOST-1", "channel": "Security", "provider": "P",
        "source_file": "/l.evtx",
        "event_data": {"NewProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                       "IpAddress": "10.0.0.5", "TargetUserName": "alice"},
    } for i in range(400)]

    def run_worker(break_component: str | None):
        """Run the real worker in-process, optionally breaking one component."""
        raw = fast_dumps(events)
        if isinstance(raw, str):        # fast_dumps may return str or bytes
            raw = raw.encode("utf-8")
        shm = SharedMemory(create=True, size=len(raw))
        shm.buf[:len(raw)] = raw
        progress_q, result_q = mp.Queue(), mp.Queue()
        cancel = mp.Event()
        patched = []
        if break_component == "ioc":
            import evtx_tool.analysis.ioc_extractor as m
            orig = m.extract_iocs
            m.extract_iocs = lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("boom: IOC extractor exploded"))
            patched.append((m, "extract_iocs", orig))
        elif break_component == "correlate":
            import evtx_tool.analysis.correlator as m
            orig = m.correlate
            m.correlate = lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("boom: correlator exploded"))
            patched.append((m, "correlate", orig))
        try:
            awp.run_analysis(shm.name, len(raw), progress_q, result_q, cancel,
                             do_ioc=True, do_correlate=True, do_hayabusa=False)
        finally:
            for mod, attr, orig in patched:
                setattr(mod, attr, orig)
            try:
                shm.close(); shm.unlink()
            except Exception:
                pass
        out = None
        try:
            out = result_q.get(timeout=10)
        except Exception:
            out = None
        msgs = []
        while True:
            try:
                msgs.append(progress_q.get_nowait())
            except Exception:
                break
        return out, msgs

    # ── baseline: nothing broken ─────────────────────────────────────────
    ok_res, _ = run_worker(None)
    check("baseline: worker returns a result", ok_res is not None)
    if ok_res:
        check("baseline: IOCs produced", bool(ok_res.get("iocs")),
              str(type(ok_res.get("iocs"))))
        check("baseline: no component errors recorded",
              not ok_res.get("errors"), str(ok_res.get("errors")))

    # ── IOC extraction blows up ──────────────────────────────────────────
    r, _ = run_worker("ioc")
    check("IOC failure still returns a result", r is not None,
          "worker sent nothing at all")
    if r:
        check("IOC failure does NOT lose correlation output",
              r.get("chains") is not None, str(r.get("chains"))[:60])
        check("IOC failure is reported, not swallowed",
              "IOC Extraction" in (r.get("errors") or {}),
              str(r.get("errors")))
        check("the failure is carried in metadata for the GUI",
              "IOC Extraction" in ((r.get("metadata") or {})
                                   .get("_analysis_errors") or {}),
              str((r.get("metadata") or {}).get("_analysis_errors")))

    # ── correlation blows up ─────────────────────────────────────────────
    r2, _ = run_worker("correlate")
    check("correlation failure still returns a result", r2 is not None)
    if r2:
        check("correlation failure does NOT lose the IOCs",
              bool(r2.get("iocs")), str(type(r2.get("iocs"))))
        check("correlation failure is reported",
              "Correlation" in (r2.get("errors") or {}), str(r2.get("errors")))

    # ── runner: an error message must not discard a queued result ────────
    from evtx_tool.analysis.analysis_runner import AnalysisRunner
    from queue import Empty
    class FakeQ:
        def __init__(self, items): self.items = list(items)
        def get_nowait(self):
            if not self.items: raise Empty()
            return self.items.pop(0)
    r3 = AnalysisRunner.__new__(AnalysisRunner)
    got = {}
    class _S:
        def __init__(self, box, key): self.box, self.key = box, key
        def emit(self, *a): self.box[self.key] = a
    r3.finished = _S(got, "finished"); r3.error = _S(got, "error")
    r3.progress = _S(got, "progress"); r3.component_progress = _S(got, "cprog")
    class _T:
        def stop(self): pass
    r3._poll_timer = _T()
    r3._process = None
    r3._cancel_requested = False
    r3._last_progress_ts = time.monotonic()
    r3._cleanup = lambda: None
    r3._cleanup_shm = lambda: None
    r3._progress_q = FakeQ([{"type": "error", "message": "worker exploded"}])
    r3._result_q = FakeQ([{"type": "result", "iocs": {"ip": [1]},
                           "chains": [{"c": 1}], "metadata": {}}])
    r3._poll()
    check("runner delivers a queued result even when an error arrives first",
          "finished" in got and "error" not in got, str(list(got)))
    if "finished" in got:
        _i, _c, _m = got["finished"]
        check("the delivered partial result keeps both payloads",
              bool(_i) and bool(_c), f"iocs={bool(_i)} chains={bool(_c)}")
        check("the error is attached so the GUI can warn",
              "_analysis_errors" in (_m or {}), str(_m))

    # with NO result queued, an error must still be an error
    r4 = AnalysisRunner.__new__(AnalysisRunner)
    got2 = {}
    r4.finished = _S(got2, "finished"); r4.error = _S(got2, "error")
    r4.progress = _S(got2, "progress"); r4.component_progress = _S(got2, "cprog")
    r4._poll_timer = _T(); r4._process = None; r4._cancel_requested = False
    r4._last_progress_ts = time.monotonic()
    r4._cleanup = lambda: None; r4._cleanup_shm = lambda: None
    r4._progress_q = FakeQ([{"type": "error", "message": "total failure"}])
    r4._result_q = FakeQ([])
    r4._poll()
    check("a total failure with nothing to show is still reported as an error",
          "error" in got2 and "finished" not in got2, str(list(got2)))

    # ── GUI half: a partial result must LOAD and be flagged ─────────────
    # The worker and runner can be perfect and the analyst still be misled if
    # the window quietly renders half an answer.
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication, QMessageBox
    app = QApplication.instance() or QApplication([])
    from evtx_tool.gui.main_window import MainWindow
    w = MainWindow()
    shown = {}
    orig_warn = QMessageBox.warning
    QMessageBox.warning = staticmethod(
        lambda *a, **k: shown.update(msg=a[2] if len(a) > 2 else ""))
    try:
        _iocs = {"ip": [{"value": "10.0.0.5", "count": 3}]}
        _chains = [{"name": "chain-1"}]
        w._on_analysis_finished(
            _iocs, _chains,
            {"_analysis_errors": {"Correlation": "RuntimeError: boom"}})
        app.processEvents()
        check("GUI keeps the IOCs from a partial run", w._iocs == _iocs)
        check("GUI keeps the chains from a partial run", w._chains == _chains)
        check("GUI warns that the run was partial", "msg" in shown)
        check("the warning names the failed component",
              "Correlation" in shown.get("msg", ""), shown.get("msg", "")[:80])
        check("the warning says not to read an empty tab as 'nothing found'",
              "nothing found" in shown.get("msg", ""))
        shown.clear()
        w._on_analysis_finished(_iocs, _chains, {})
        app.processEvents()
        check("a clean run shows no warning", "msg" not in shown, str(shown))
    finally:
        QMessageBox.warning = orig_warn
        w.close()

    # ── a TOTAL failure must stay a failure, not a fake empty success ────
    # If the events never deserialised, no component could have run: inventing
    # an empty result would read as "analysis found nothing".
    import evtx_tool.core._json_compat as _jc
    _shm = SharedMemory(create=True, size=16); _shm.buf[:4] = b"junk"
    _pq, _rq = mp.Queue(), mp.Queue()
    _orig_loads = _jc.fast_loads
    _jc.fast_loads = lambda *a, **k: (_ for _ in ()).throw(ValueError("corrupt"))
    try:
        awp.run_analysis(_shm.name, 4, _pq, _rq, mp.Event(),
                         do_ioc=True, do_correlate=True)
    finally:
        _jc.fast_loads = _orig_loads
        try: _shm.close(); _shm.unlink()
        except Exception: pass
    _res = None
    try: _res = _rq.get(timeout=3)
    except Exception: pass
    _errs = []
    while True:
        try: _errs.append(_pq.get_nowait())
        except Exception: break
    check("total failure is reported as an error",
          any(m.get("type") == "error" for m in _errs), str(len(_errs)))
    check("total failure does not fabricate an empty successful result",
          _res is None, str(_res)[:80])

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
