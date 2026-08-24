"""A correlation chain must not claim an effect that preceded its cause.

`_ts_delta()` returns `abs((tb - ta).total_seconds())`, so a time window on its
own is direction-blind: "B within 60 s of A" also matches a B that happened 60 s
BEFORE A. Most directional rules therefore pair the window with `_ts_ge(...)`.
Two did not:

  _rule_ps_exec_chain      "Suspicious Process Spawn -> PowerShell Execution"
                           chained a script block up to 60 s BEFORE the spawn.
                           Its `0 <= _ts_delta(...)` guard was dead — abs() is
                           never negative — which is the fingerprint of a signed
                           comparison that got lost.

  _rule_privilege_escalation
                           chained a privilege assignment up to 30 s BEFORE the
                           logon it was attributed to.

This is the same defect class as the RDP session pairing that fabricated
multi-hour spans: two real events, correctly parsed, joined into a relationship
the log does not support. A fabricated attack chain is worse than a missed one —
it is evidence of an intrusion that did not happen in that order.

Run: QT_QPA_PLATFORM=offscreen python tests/test_correlation_causality.py
"""
import os, sys, re, inspect

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SPAWN = {"NewProcessName": r"C:\Windows\System32\powershell.exe",
         "ParentProcessName": r"C:\Windows\System32\wbem\wmiprvse.exe"}


def _ev(rid, eid, ts, computer="HOST1", user="alice", **ed):
    return {"record_id": rid, "event_id": eid, "timestamp": ts,
            "channel": "Security", "computer": computer, "user_id": user,
            "provider": "p", "source_file": "s.evtx",
            "event_data": dict(ed, TargetUserName=user, SubjectUserName=user)}


def main() -> int:
    import evtx_tool.analysis.correlator as C

    res = []
    def check(name, ok, detail=""):
        res.append((name, bool(ok)))
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"\n      {detail}" if detail else ""))

    # ── the helper really is direction-blind (premise of the whole suite) ──
    d1 = C._ts_delta("2025-01-01T00:01:00Z", "2025-01-01T00:00:00Z")
    d2 = C._ts_delta("2025-01-01T00:00:00Z", "2025-01-01T00:01:00Z")
    check("_ts_delta is absolute, so a window alone cannot imply order",
          d1 == d2 == 60.0, f"forward={d2}, backward={d1}")

    # ── rule: suspicious spawn -> PowerShell ──────────────────────────────
    back = [_ev(1, 4104, "2025-01-01T00:00:00Z", ScriptBlockText="x"),
            _ev(2, 4688, "2025-01-01T00:00:30Z", **SPAWN)]
    fwd  = [_ev(1, 4688, "2025-01-01T00:00:00Z", **SPAWN),
            _ev(2, 4104, "2025-01-01T00:00:30Z", ScriptBlockText="x")]
    n_back = len(C._rule_ps_exec_chain(C._EventIndex(back)))
    n_fwd  = len(C._rule_ps_exec_chain(C._EventIndex(fwd)))
    check("ps_exec_chain: does NOT chain a script block that PRECEDED the spawn",
          n_back == 0, f"{n_back} chain(s) — a fabricated causal link")
    check("ps_exec_chain: still chains the genuine forward case",
          n_fwd == 1, f"{n_fwd} chain(s) — the fix must not silence a real detection")

    # ── every directional window is paired with an ordering test ──────────
    src = inspect.getsource(C)
    unguarded = []
    # Only DIRECTIONAL windows need an ordering test. A symmetric one compares
    # two elements of the SAME sorted list (`x[i]` vs `x[j]`, with `j = i + 1`)
    # to cluster N similar events — there ordering is already guaranteed by the
    # loop and an absolute delta is exactly right. Flagging those made this
    # check fail on correct code.
    SAME_LIST = re.compile(r"_ts_delta\(\s*(\w+)\[i\]\[[^]]+\]\s*,\s*\1\[j\]")
    for m in re.finditer(r"_ts_delta\([^)]*\)\s*<=\s*\d+", src):
        if SAME_LIST.match(m.group()):
            continue                      # symmetric clustering, not causal
        window = src[max(0, m.start() - 320): m.end() + 320]
        if "_ts_ge" not in window:
            line = src[:m.start()].count("\n") + 1
            unguarded.append(f"correlator.py:{line}: {m.group()}")
    check("every DIRECTIONAL _ts_delta window sits next to an ordering test",
          not unguarded, "\n      ".join(unguarded))

    # ── the dead `0 <=` guard is gone ─────────────────────────────────────
    check("no dead `0 <= _ts_delta(...)` comparison remains",
          not re.search(r"0\s*<=\s*_ts_delta", src),
          "abs() is never negative — such a test signals a lost signed compare")

    # ── chains must not span hosts unless the rule says so ────────────────
    cross = [_ev(1, 4688, "2025-01-01T00:00:00Z", computer="HOST1", **SPAWN),
             _ev(2, 4104, "2025-01-01T00:00:30Z", computer="HOST2", ScriptBlockText="x")]
    n_cross = len(C._rule_ps_exec_chain(C._EventIndex(cross)))
    check("ps_exec_chain does not join events from DIFFERENT hosts",
          n_cross == 0, f"{n_cross} cross-host chain(s)")

    print("\n" + "=" * 60)
    bad = [n for n, ok in res if not ok]
    print(f"RESULT: {len(res)-len(bad)}/{len(res)} passed")
    for n in bad:
        print("  FAILED:", n)
    sys.stdout.flush()
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
