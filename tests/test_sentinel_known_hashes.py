"""Sentinel compares a binary's hash with the BASELINE's, and the fuse cap never hides a mismatch.

Gemini audit 10-03 (High): analysis started with no known hashes, so the
FIRST svchost.exe of the target (even a trojanized one) became "known" with
no bonus and the genuine one after it was flagged; the baseline never saved
its hashes; the in-baseline cap halved a hash-mismatch score; the
justification never named a hash mismatch.

Expected: the baseline's hashes are saved (signed) and loaded; a baseline
hash scores 0 and a different one 1 every time; the cap does not apply to a
mismatch; the justification says so.  Synthetic artifacts.
"""
import json
import os
import pickle
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_sentinel_meta_signed import META                          # noqa: E402

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def nev(proc, h):
    from sentinel.models import NormalizedEvent, RawEvent
    raw = RawEvent(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), host="H", event_id=1, process_guid="{g}",
                   pid=1, ppid=0, parent_guid="", process_name=proc, process_path="C:\\x\\" + proc,
                   parent_name="services.exe", parent_path="", cmdline=proc, user="u", integrity_level="",
                   image_hash=h)
    return NormalizedEvent(raw=raw, proc_norm=proc, parent_norm="services.exe", cmdline_norm=proc,
                           ancestry_chain=[proc, "services.exe"])


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="skh_"))
    os.environ["LOCALAPPDATA"] = str(base / "profile")
    os.environ.pop("SENTINEL_ARTIFACT_KEY", None)
    from sentinel.baseline import persistence as P
    from sentinel.models import BaselineMeta
    d = base / "b"
    P.save_artifacts(d, BaselineMeta(**META), {}, {}, {}, [nev("svchost.exe", "SHA256=AAAA")])
    kh = P.load_known_hashes(d) if hasattr(P, "load_known_hashes") else None
    check("the baseline's hashes are saved and loaded", kh == {"svchost.exe": {"SHA256=AAAA"}}, str(kh))
    p = d / "known_hashes.json"
    if p.exists():
        p.write_text(json.dumps({"svchost.exe": ["SHA256=FFFF"]}), encoding="utf-8")
    try:
        P.load_known_hashes(d)
        refused = False
    except Exception:
        refused = True
    check("an edited hash file is refused", refused)

    import sentinel.analysis.engine as E
    fn = getattr(E, "hash_signal", None)
    known = {"svchost.exe": {"SHA256=AAAA"}}
    if fn:
        a = fn("svchost.exe", "SHA256=FFFF", known)
        b = fn("svchost.exe", "SHA256=FFFF", known)
        c = fn("svchost.exe", "SHA256=AAAA", known)
        check("a trojanized binary is flagged every time, the baseline's is not", (a, b, c) == (1.0, 1.0, 0.0), str((a, b, c)))
    else:
        check("a trojanized binary is flagged every time, the baseline's is not", False, "no hash_signal")
    cap = getattr(E, "fuse_capped", None)
    check("the in-baseline cap does not apply to a hash mismatch",
          cap is not None and cap(80.0, True, 0.0, 0.0, 1.0, 0.3, 45.0) == 80.0
          and cap(80.0, True, 0.0, 0.0, 0.0, 0.3, 45.0) == 40.0, "")

    from sentinel.report.justification import build_justification
    from sentinel.models import ScoredEvent
    se = ScoredEvent(normalized=nev("svchost.exe", "SHA256=FFFF"), composite=90.0, tier=4)
    se.image_hash_mismatch = True

    class _Trie:
        def most_common_parent(self, p):
            return "services.exe"
    txt = build_justification(se, _Trie())
    check("the justification names the hash mismatch", "hash" in txt.lower(), txt)
    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
