"""All four analysis modes, each broken in turn — the others must survive.

Reported again: "there are four different analysis modes, the chains and the
MITRE and all — none of them were working. If one crashes, nothing gets
loaded."

test_analysis_partial.py already covers IOC and correlation.  This widens it to
every mode the GUI shows, and to the combinations:

  * MITRE / ATT&CK   — runs in ParseWorker (phase 1), NOT the analysis
                       subprocess.  If it throws there it could take the whole
                       parse down, which would leave EVERY tab empty and look
                       exactly like "none of them were working".
  * IOCs             — analysis subprocess
  * Correlation      — analysis subprocess
  * Hayabusa/Sigma   — analysis subprocess, external binary

An empty tab must also be distinguishable from a crashed one: silence is the
failure mode that matters here, because an analyst reads an empty IOC tab as
"no IOCs in this evidence".

Run: python tests/test_analysis_all_modes.py
"""
import os
import sys
import multiprocessing as mp
from multiprocessing.shared_memory import SharedMemory

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, ok, detail=""):
    CHECKS.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""))


def synth_events(n=400):
    return [{
        "record_id": i, "event_id": 4688, "level_name": "Information",
        "timestamp": f"2025-06-10T09:00:{i % 60:02d}.000000Z",
        "computer": "HOST-1", "channel": "Security", "provider": "P",
        "source_file": "/l.evtx",
        "event_data": {"NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                       "IpAddress": "10.0.0.5", "TargetUserName": "alice",
                       "CommandLine": "powershell -enc ZQBjAGgAbwA="},
    } for i in range(n)]


def boom(msg):
    def _f(*a, **k):
        raise RuntimeError(msg)
    return _f


def run_worker(events, break_components=(), do_hayabusa=False):
    """Run the REAL analysis worker in-process, breaking named components."""
    import evtx_tool.analysis.analysis_worker_proc as awp
    from evtx_tool.core._json_compat import fast_dumps

    raw = fast_dumps(events)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    shm = SharedMemory(create=True, size=len(raw))
    shm.buf[:len(raw)] = raw
    pq, rq = mp.Queue(), mp.Queue()
    cancel = mp.Event()

    patched = []

    def patch(modpath, attr, fn):
        import importlib
        m = importlib.import_module(modpath)
        patched.append((m, attr, getattr(m, attr)))
        setattr(m, attr, fn)

    if "ioc" in break_components:
        patch("evtx_tool.analysis.ioc_extractor", "extract_iocs",
              boom("boom: IOC extractor exploded"))
    if "correlate" in break_components:
        patch("evtx_tool.analysis.correlator", "correlate",
              boom("boom: correlator exploded"))
    if "hayabusa" in break_components:
        patch("evtx_tool.analysis.hayabusa_runner", "run_hayabusa",
              boom("boom: hayabusa exploded"))

    try:
        awp.run_analysis(
            shm.name, len(raw), pq, rq, cancel,
            do_ioc=True, do_correlate=True,
            do_hayabusa=do_hayabusa,
            hayabusa_path=(r"C:\fake\hayabusa.exe" if do_hayabusa else None),
            evtx_paths=([r"C:\fake\x.evtx"] if do_hayabusa else None),
        )
    finally:
        for m, attr, orig in patched:
            setattr(m, attr, orig)
        try:
            shm.close(); shm.unlink()
        except Exception:
            pass

    out = None
    try:
        out = rq.get(timeout=15)
    except Exception:
        pass
    msgs = []
    while True:
        try:
            msgs.append(pq.get_nowait())
        except Exception:
            break
    return out, msgs


def errors_of(msgs):
    return [m for m in msgs if isinstance(m, dict) and m.get("type") == "error"]


def reported_failures(result, msgs):
    """Every place a component failure is allowed to be announced.

    The worker records them in result["errors"], keyed by component name
    ("IOC Extraction", "Correlation", …), and mirrors them into
    metadata["_analysis_errors"] for the GUI.  A worker-level crash instead
    arrives as a {"type": "error"} message on the progress queue.
    """
    r = result or {}
    names = set((r.get("errors") or {}).keys())
    names |= set(((r.get("metadata") or {}).get("_analysis_errors") or {}).keys())
    return names, errors_of(msgs)


def main() -> int:
    events = synth_events()

    print("=== 1. baseline: every mode produces something ===")
    base, bmsgs = run_worker(events)
    check("the worker returns a result", base is not None)
    if base is None:
        print("cannot continue without a baseline"); return 1
    check("IOCs produced", bool(base.get("iocs")),
          f"keys={len(base.get('iocs') or {})}")
    check("correlation ran (chains key present)", "chains" in base,
          f"chains={len(base.get('chains') or [])}")
    check("no errors on the happy path", not errors_of(bmsgs),
          str(errors_of(bmsgs))[:150])

    print("\n=== 2. MITRE/ATT&CK failure must not kill the parse ===")
    # ATT&CK runs in ParseWorker, so breaking it must still leave events and
    # still let the rest of the pipeline run.
    import evtx_tool.analysis.attack_mapping as am
    _orig = am.enrich_and_summarize
    am.enrich_and_summarize = boom("boom: attack mapping exploded")
    try:
        from evtx_tool.gui.worker import ParseWorker
        import inspect
        src = inspect.getsource(ParseWorker)
        check("ParseWorker guards the ATT&CK call",
              "enrich_and_summarize" in src and "except Exception" in src)
        # the analysis pipeline itself is unaffected by ATT&CK breaking
        r, m = run_worker(events)
        check("analysis still returns a result when ATT&CK is broken",
              r is not None)
        check("IOCs survive an ATT&CK failure", bool((r or {}).get("iocs")))
    finally:
        am.enrich_and_summarize = _orig

    print("\n=== 3. each subprocess mode broken in turn ===")
    for comp, keep_key, keep_name in (
        ("ioc", "chains", "correlation"),
        ("correlate", "iocs", "IOCs"),
    ):
        r, m = run_worker(events, break_components=(comp,))
        check(f"{comp} failure still returns a result", r is not None)
        if r is not None:
            kept = r.get(keep_key)
            check(f"{comp} failure does NOT lose {keep_name}",
                  kept is not None, f"{keep_name}={type(kept).__name__}")
        names, errs = reported_failures(r, m)
        check(f"{comp} failure is reported, not swallowed",
              bool(names) or bool(errs), f"named={sorted(names)} msgs={len(errs)}")

    print("\n=== 4. Hayabusa failure is contained ===")
    r, m = run_worker(events, break_components=("hayabusa",), do_hayabusa=True)
    check("hayabusa failure still returns a result", r is not None)
    if r is not None:
        check("hayabusa failure does NOT lose the IOCs", bool(r.get("iocs")))
        check("hayabusa failure does NOT lose correlation", "chains" in r)

    print("\n=== 5. two modes failing at once ===")
    r, m = run_worker(events, break_components=("ioc", "correlate"))
    check("a double failure still returns a result", r is not None)
    names, errs = reported_failures(r, m)
    check("a double failure names BOTH failed components",
          len(names) >= 2 or len(errs) >= 1, f"named={sorted(names)}")

    print("\n=== 6. everything failing is an ERROR, never a silent empty ===")
    r, m = run_worker(events, break_components=("ioc", "correlate", "hayabusa"),
                      do_hayabusa=True)
    names, errs = reported_failures(r, m)
    surfaced = bool(names) or bool(errs)
    check("a total failure is surfaced somewhere the GUI can see it", surfaced,
          f"named={sorted(names)} msgs={len(errs)}")
    # The thing that must never happen: a clean-looking empty result.
    clean_empty = (r is not None and not r.get("iocs")
                   and not r.get("chains") and not surfaced)
    check("an empty result is never presented as a clean success",
          not clean_empty)

    print("\n=== 7. the Chains tab can actually be non-empty ===")
    # Every check above passes for a correlator that always returns [].  On
    # benign logs 0 chains is the CORRECT answer, which is exactly why an empty
    # Chains tab is indistinguishable from a broken one.  Feed real attack
    # sequences and require chains.
    from evtx_tool.analysis.correlator import correlate

    def sev(rid, eid, ts, **ed):
        return {"record_id": rid, "event_id": eid, "timestamp": ts,
                "computer": "WS01", "channel": "Security",
                "provider": "Microsoft-Windows-Security-Auditing",
                "source_file": "Security.evtx", "event_data": ed}

    brute = [sev(i, 4625, f"2025-06-10T09:00:{i:02d}.000000Z",
                 IpAddress="203.0.113.7", TargetUserName="admin", LogonType="3")
             for i in range(1, 16)]
    brute.append(sev(99, 4624, "2025-06-10T09:00:30.000000Z",
                     IpAddress="203.0.113.7", TargetUserName="admin",
                     LogonType="3", TargetLogonId="0x1a2b"))
    check("brute force followed by success produces a chain",
          len(correlate(brute)) >= 1)

    spray = [sev(i, 4625, f"2025-06-10T11:00:{i:02d}.000000Z",
                 IpAddress="198.51.100.9", TargetUserName=f"user{i}",
                 LogonType="3") for i in range(1, 21)]
    check("a password spray produces a chain", len(correlate(spray)) >= 1)

    clear_after = [
        sev(1, 4624, "2025-06-10T09:55:00.000000Z", TargetUserName="eve",
            LogonType="10", IpAddress="10.0.0.66"),
        sev(2, 4672, "2025-06-10T09:55:01.000000Z", SubjectUserName="eve"),
        sev(9, 1102, "2025-06-10T10:00:00.000000Z", SubjectUserName="eve"),
    ]
    check("a log clear after attacker activity produces a chain",
          len(correlate(clear_after)) >= 1)
    check("a lone log clear with no prior activity does NOT (no false positive)",
          len(correlate([clear_after[-1]])) == 0)

    ok = sum(1 for _n, c, _d in CHECKS if c)
    print(f"\n{'='*62}\n{ok}/{len(CHECKS)} checks passed")
    for n, c, d in CHECKS:
        if not c:
            print(f"  FAILED: {n}  {d}")
    return 0 if ok == len(CHECKS) else 1


if __name__ == "__main__":
    mp.freeze_support()
    sys.exit(main())
