"""Sentinel baseline tamper check cannot be recomputed or skipped (audit SA-6).

The check's key was the SHA-256 of the baseline folder's path, which anyone
can compute, and a baseline file with no stored checksum was accepted with a
log line.  Whoever can write to the baseline folder could therefore edit the
baseline (and so hide activity from the analysis) and make the check pass.
Expected: the key comes from a secret kept in the analyst's own profile, or
from SENTINEL_ARTIFACT_KEY; a missing checksum, a changed file and checksums
made with the old path-derived key are all refused.  Synthetic files only;
the secret is written to a temporary folder, not the real profile.
"""
import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

CHECKS = []


def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  -- {detail}" if detail else ""), flush=True)


def refused(fn, *a):
    try:
        fn(*a)
        return False
    except RuntimeError:
        return True


def main() -> int:
    base = Path(tempfile.mkdtemp(prefix="sbk_"))
    os.environ["LOCALAPPDATA"] = str(base / "profile")
    os.environ.pop("SENTINEL_ARTIFACT_KEY", None)
    from sentinel.baseline import persistence as P
    try:
        d = base / "baseline"
        d.mkdir()
        for f in P._PICKLE_FILES:
            (d / f).write_bytes(b"data of " + f.encode())
        path_key = hashlib.sha256(str(d.resolve()).encode()).digest()
        key = P._artifact_key(d)
        check("the key is not the hash of the folder path", key != path_key and len(key) == 32)
        check("the key is the same on every call", key == P._artifact_key(d))
        other = base / "other"
        other.mkdir()
        check("another baseline folder has another key", P._artifact_key(other) != key)
        check("the secret is kept in the analyst's profile",
              any(p.is_file() for p in (base / "profile").rglob("*")))

        good = {f: P._hmac_file(d / f, key) for f in P._PICKLE_FILES}
        P._save_checksums(d, good)
        check("an untouched baseline is accepted", not refused(P._verify_checksums, d, P._artifact_key(d)))

        P._save_checksums(d, {f: P._hmac_file(d / f, path_key) for f in P._PICKLE_FILES})
        check("checksums made with the path-derived key are refused",
              refused(P._verify_checksums, d, P._artifact_key(d)))

        short = dict(good)
        del short[P._PICKLE_FILES[0]]
        P._save_checksums(d, short)
        check("a file with no stored checksum is refused", refused(P._verify_checksums, d, key))

        P._save_checksums(d, good)
        (d / P._PICKLE_FILES[1]).write_bytes(b"edited")
        check("a changed file is refused", refused(P._verify_checksums, d, key))

        os.environ["SENTINEL_ARTIFACT_KEY"] = "ab" * 32
        check("SENTINEL_ARTIFACT_KEY still sets the key", P._artifact_key(d) == bytes.fromhex("ab" * 32))
    finally:
        os.environ.pop("SENTINEL_ARTIFACT_KEY", None)
        shutil.rmtree(base, ignore_errors=True)
    n = sum(ok for _, ok in CHECKS)
    print(f"{n}/{len(CHECKS)} checks passed")
    return 0 if n == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
