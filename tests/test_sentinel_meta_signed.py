"""Sentinel: the baseline's meta file is covered by the checksums, and a weak key is not used.

Gemini audit 10-01 (Critical): artifact_checksums.json covered only the three
pickles.  baseline_meta.json -- which holds the tier boundaries -- was read
(before any check) and trusted, so editing "suppress_max" to 100 silenced every
Tier 4 alert, and the host name could be changed, without the checksum check
noticing.  SENTINEL_ARTIFACT_KEY="   " gave an EMPTY key, and a 1-byte key was
accepted.

Expected:
- an untouched baseline loads;
- a baseline whose meta file was edited is refused (RuntimeError), as is one
  whose checksum file has no entry for the meta file;
- a blank or short SENTINEL_ARTIFACT_KEY is not used as the key (the stored
  secret is used instead); a 16-byte hex key is used.
Synthetic artifacts only.
"""
import json
import os
import pickle
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond), detail))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


META = {"host": "HOST-A", "start_ts": "2026-01-01T00:00:00", "end_ts": "2026-01-02T00:00:00",
        "stability_score": 0.9, "event_count": 10, "build_ts": "2026-01-03T00:00:00",
        "tier_boundaries": {"suppress_max": 20.0, "aggregate_max": 45.0, "highlight_max": 70.0},
        "baseline_process_dist": {}, "input_file_hashes": {}}


def build(P, d: Path, sign_meta: bool) -> None:
    d.mkdir(parents=True, exist_ok=True)
    (d / P._META_FILE).write_text(json.dumps(META), encoding="utf-8")
    for f in P._PICKLE_FILES:
        (d / f).write_bytes(pickle.dumps({}))
    (d / P._DB_FILE).write_bytes(b"")
    key = P._artifact_key(d)
    names = list(P._PICKLE_FILES) + ([P._META_FILE] if sign_meta else [])
    P._save_checksums(d, {f: P._hmac_file(d / f, key) for f in names})


def loads(P, d: Path):
    try:
        P.load_artifacts(d)
        return None
    except RuntimeError as e:
        return e


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="smeta_"))
    os.environ["LOCALAPPDATA"] = str(base / "profile")
    os.environ.pop("SENTINEL_ARTIFACT_KEY", None)
    from sentinel.baseline import persistence as P

    d = base / "b1"
    build(P, d, sign_meta=True)
    e = loads(P, d)
    check("an untouched baseline loads", e is None, repr(e))

    m = json.loads((d / P._META_FILE).read_text(encoding="utf-8"))
    m["tier_boundaries"]["suppress_max"] = 100.0
    m["host"] = "SPOOFED"
    (d / P._META_FILE).write_text(json.dumps(m), encoding="utf-8")
    e = loads(P, d)
    check("a baseline whose meta file was edited (suppress_max 100, host) is refused", e is not None, repr(e))

    d2 = base / "b2"
    build(P, d2, sign_meta=False)
    e = loads(P, d2)
    check("a checksum file with no entry for the meta file is refused", e is not None, repr(e))

    stored = P._artifact_key(d)
    for label, val in (("blank", "   "), ("1-byte", "ab"), ("15-byte", "ab" * 15)):
        os.environ["SENTINEL_ARTIFACT_KEY"] = val
        try:
            k = P._artifact_key(d)
        finally:
            os.environ.pop("SENTINEL_ARTIFACT_KEY", None)
        check(f"a {label} SENTINEL_ARTIFACT_KEY is not used as the key", k == stored and len(k) >= 16,
              f"len {len(k)}")
    os.environ["SENTINEL_ARTIFACT_KEY"] = "cd" * 16
    try:
        k = P._artifact_key(d)
    finally:
        os.environ.pop("SENTINEL_ARTIFACT_KEY", None)
    check("a 16-byte hex SENTINEL_ARTIFACT_KEY is used", k == bytes.fromhex("cd" * 16))

    n = sum(ok for _, ok, _ in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
