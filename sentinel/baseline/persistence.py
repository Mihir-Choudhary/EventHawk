"""
Artifact persistence — save and load all baseline artifacts.

Artifact layout under a user-chosen directory:
    baseline_meta.json      — BaselineMeta (JSON)
    freq_model.pkl          — FrequencyModel (pickle)
    ancestry_trie.pkl       — AncestryTrie (pickle)
    fuse_filter.pkl         — FuseStore (pickle)
    artifact_checksums.json — HMAC-SHA256 checksums for all pickle files
    baseline.db             — SQLite: full normalized event store (for TED offline)

Security note: pickle files are protected by HMAC-SHA256 checksums stored in
artifact_checksums.json.  The HMAC key is derived from the artifact directory's
absolute path (deterministic, zero-config for local use).  Set the environment
variable SENTINEL_ARTIFACT_KEY to a hex string to use a custom key instead.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import pickle
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.baseline.freq_model import FrequencyModel
    from sentinel.baseline.fuse_store import FuseStore
    from sentinel.baseline.trie import AncestryTrie
    from sentinel.models import BaselineMeta, NormalizedEvent

logger = logging.getLogger(__name__)

_META_FILE       = "baseline_meta.json"
_FREQ_FILE       = "freq_model.pkl"
_TRIE_FILE       = "ancestry_trie.pkl"
_FUSE_FILE       = "fuse_filter.pkl"
_CHECKSUM_FILE   = "artifact_checksums.json"
_DB_FILE         = "baseline.db"

_PICKLE_FILES = (_FREQ_FILE, _TRIE_FILE, _FUSE_FILE)


# ── HMAC helpers ───────────────────────────────────────────────────────────────

_SECRET_FILE = "sentinel_artifact.key"


def _user_secret() -> bytes:
    """The analyst's own secret for baseline checksums, created on first use.

    It is kept in the analyst's profile (%LOCALAPPDATA%\\EventHawk), not in
    the baseline folder: someone who can write to a baseline folder cannot
    read it, so cannot make checksums that pass.
    """
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
    path = Path(base) / "EventHawk" / _SECRET_FILE

    def _read() -> bytes:
        secret = bytes.fromhex(path.read_text(encoding="ascii").strip())
        if len(secret) < 32:
            raise ValueError("secret too short")
        return secret

    try:
        return _read()
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"The baseline checksum secret {path} cannot be read ({exc}). "
                           "Delete it and re-build the baseline.") from exc
    secret = os.urandom(32)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "x", encoding="ascii") as fh:      # "x": never replace one
            fh.write(secret.hex())
    except FileExistsError:
        return _read()                                     # another process made it first
    except OSError as exc:
        raise RuntimeError(f"The baseline checksum secret cannot be stored in {path} ({exc}). "
                           "Set SENTINEL_ARTIFACT_KEY instead.") from exc
    return secret


def _artifact_key(directory: Path) -> bytes:
    """Derive the HMAC key for a given artifact directory.

    Priority:
      1. SENTINEL_ARTIFACT_KEY env var (hex string → bytes)
      2. The analyst's own secret, bound to the canonical directory path

    The key used to be the SHA-256 of the directory path alone.  Anyone can
    compute that, so whoever could write to the folder could change the
    baseline and its checksums together (audit SA-6).
    """
    env_key = os.environ.get("SENTINEL_ARTIFACT_KEY", "")
    if env_key:
        try:
            return bytes.fromhex(env_key)
        except ValueError:
            logger.warning("SENTINEL_ARTIFACT_KEY is not valid hex; falling back to the stored secret")
    return hmac.new(_user_secret(), str(directory.resolve()).encode(), hashlib.sha256).digest()


def _hmac_file(path: Path, key: bytes) -> str:
    """Compute HMAC-SHA256 of a file, returned as a hex string."""
    mac = hmac.new(key, digestmod=hashlib.sha256)
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            mac.update(chunk)
    return mac.hexdigest()


def _save_checksums(directory: Path, checksums: dict[str, str]) -> None:
    path = directory / _CHECKSUM_FILE
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(checksums, fh, indent=2)
    logger.info("Saved artifact checksums → %s", path)


def _verify_checksums(directory: Path, key: bytes) -> None:
    """Verify HMAC checksums of all pickle artifacts.

    Raises RuntimeError if the checksum file is missing or any file fails
    verification (indicating tampering or a different build environment).
    """
    checksum_path = directory / _CHECKSUM_FILE
    if not checksum_path.exists():
        raise RuntimeError(
            f"artifact_checksums.json not found in {directory}. "
            "Baseline artifacts may have been tampered with or were built by an "
            "older Sentinel version. Re-build the baseline to resolve this."
        )

    with open(checksum_path, encoding="utf-8") as fh:
        stored: dict[str, str] = json.load(fh)

    for fname in _PICKLE_FILES:
        fpath = directory / fname
        if not fpath.exists():
            continue
        expected = stored.get(fname)
        if not isinstance(expected, str):
            # Not skipped: removing the entry would switch the check off.
            raise RuntimeError(
                f"No stored checksum for {fname} in {checksum_path.name}. "
                "The baseline may have been tampered with. Re-build the baseline to resolve this."
            )
        actual = _hmac_file(fpath, key)
        if not hmac.compare_digest(actual, expected):
            raise RuntimeError(
                f"Artifact integrity check failed for {fname}. "
                "The file may have been tampered with, or the baseline was built on another "
                "computer or account, in another folder, or by an older EventHawk. "
                "Re-build the baseline to resolve this (or set SENTINEL_ARTIFACT_KEY to the "
                "same value where it is built and where it is used)."
            )
    logger.debug("Artifact integrity verified for %s", directory)


# ── Save ───────────────────────────────────────────────────────────────────────

def save_artifacts(
    directory: Path,
    meta: "BaselineMeta",
    freq_model: "FrequencyModel",
    trie: "AncestryTrie",
    fuse: "FuseStore",
    normalized_events: list["NormalizedEvent"],
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    key = _artifact_key(directory)

    # Meta JSON
    meta_path = directory / _META_FILE
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(asdict(meta), fh, indent=2)
    logger.info("Saved baseline meta → %s", meta_path)

    # FrequencyModel pickle
    freq_path = directory / _FREQ_FILE
    with open(freq_path, "wb") as fh:
        pickle.dump(freq_model, fh, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("Saved freq_model → %s", freq_path)

    # AncestryTrie pickle
    trie_path = directory / _TRIE_FILE
    with open(trie_path, "wb") as fh:
        pickle.dump(trie, fh, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("Saved ancestry_trie → %s", trie_path)

    # FuseStore pickle
    fuse_path = directory / _FUSE_FILE
    with open(fuse_path, "wb") as fh:
        pickle.dump(fuse, fh, protocol=pickle.HIGHEST_PROTOCOL)
    logger.info("Saved fuse_filter → %s", fuse_path)

    # Compute and save HMAC-SHA256 checksums for all pickle files
    checksums = {
        fname: _hmac_file(directory / fname, key)
        for fname in _PICKLE_FILES
    }
    _save_checksums(directory, checksums)

    # SQLite normalized event store
    db_path = directory / _DB_FILE
    _save_to_sqlite(db_path, normalized_events)
    logger.info("Saved baseline SQLite DB → %s", db_path)


def _save_to_sqlite(db_path: Path, events: list["NormalizedEvent"]) -> None:
    con = sqlite3.connect(str(db_path))
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
        # B18: Drop old data on re-build to avoid stale events accumulating
        con.execute("DROP TABLE IF EXISTS baseline_events")
        con.execute("""
            CREATE TABLE IF NOT EXISTS baseline_events (
                id              INTEGER PRIMARY KEY,
                timestamp       TEXT,
                host            TEXT,
                event_id        INTEGER,
                proc_norm       TEXT,
                parent_norm     TEXT,
                cmdline_norm    TEXT,
                proc_raw        TEXT,
                parent_raw      TEXT,
                cmdline_raw     TEXT,
                user            TEXT,
                integrity_level TEXT,
                attck_tags      TEXT,
                flags           TEXT
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_proc ON baseline_events(proc_norm)")
        rows = []
        for ev in events:
            raw = ev.raw
            rows.append((
                raw.timestamp.isoformat() if raw.timestamp else "",
                raw.host,
                raw.event_id,
                ev.proc_norm,
                ev.parent_norm,
                ev.cmdline_norm,
                raw.process_name,
                raw.parent_name,
                raw.cmdline,
                raw.user,
                raw.integrity_level,
                json.dumps(raw.attck_tags),
                json.dumps(list(raw.flags)),
            ))
        con.executemany(
            "INSERT INTO baseline_events VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            rows,
        )
        con.commit()
    finally:
        con.close()


# ── Load ───────────────────────────────────────────────────────────────────────

# ── Restricted unpickler (S1: prevent RCE via crafted baseline) ────────────────

class _RestrictedUnpickler(pickle.Unpickler):
    """Unpickler that only allows Sentinel's own classes.

    Standard pickle.load() will execute arbitrary __reduce__ methods,
    meaning a crafted .pkl file can run any Python code.  This unpickler
    limits deserialization to the specific classes Sentinel actually stores.
    """
    _SAFE_MODULES: dict[str, set[str]] = {
        'sentinel.baseline.freq_model': {'FrequencyModel'},
        'sentinel.baseline.trie': {'AncestryTrie', 'TrieNode'},
        'sentinel.baseline.fuse_store': {'FuseStore', '_XOR8Filter'},
        'collections': {'Counter', 'defaultdict'},
        'builtins': {'set', 'dict', 'list', 'tuple', 'int', 'float', 'str', 'bytes', 'bytearray', 'frozenset'},
    }

    def find_class(self, module: str, name: str) -> type:
        allowed = self._SAFE_MODULES.get(module, set())
        if name in allowed:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(
            f"Forbidden class in pickle: {module}.{name}. "
            "This may indicate a tampered baseline artifact."
        )


def _safe_pickle_load(path: Path) -> object:
    """Load a pickle file using the restricted unpickler."""
    with open(path, "rb") as fh:
        return _RestrictedUnpickler(fh).load()


def load_artifacts(directory: Path) -> tuple[
    "BaselineMeta", "FrequencyModel", "AncestryTrie", "FuseStore"
]:
    from sentinel.models import BaselineMeta, TierBoundaries

    meta_path = directory / _META_FILE
    with open(meta_path, encoding="utf-8") as fh:
        raw = json.load(fh)
    # Reconstruct BaselineMeta from dict (B4: include input_file_hashes)
    meta = BaselineMeta(
        host=raw["host"],
        start_ts=raw["start_ts"],
        end_ts=raw["end_ts"],
        stability_score=raw["stability_score"],
        event_count=raw["event_count"],
        build_ts=raw["build_ts"],
        tier_boundaries=raw["tier_boundaries"],
        baseline_process_dist=raw["baseline_process_dist"],
        input_file_hashes=raw.get("input_file_hashes", {}),
    )

    # Verify checksums before deserializing pickles
    key = _artifact_key(directory)
    _verify_checksums(directory, key)

    # S1: Use restricted unpickler — only allows Sentinel's own classes
    freq_model = _safe_pickle_load(directory / _FREQ_FILE)
    trie = _safe_pickle_load(directory / _TRIE_FILE)
    fuse = _safe_pickle_load(directory / _FUSE_FILE)

    logger.info(
        "Loaded baseline artifacts from %s (%d events, stability=%.2f)",
        directory, meta.event_count, meta.stability_score,
    )
    return meta, freq_model, trie, fuse


def artifacts_exist(directory: Path) -> bool:
    """Return True if all required artifact files exist in directory."""
    for fname in (_META_FILE, _FREQ_FILE, _TRIE_FILE, _FUSE_FILE):
        if not (directory / fname).exists():
            return False
    return True
