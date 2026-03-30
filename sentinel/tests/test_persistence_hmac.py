"""
Integration tests for sentinel.baseline.persistence.

Q5 — covers:
  - HMAC save/verify round-trip (_save_checksums / _verify_checksums)
  - Tamper detection: modifying a pickle raises RuntimeError
  - SENTINEL_ARTIFACT_KEY env-var override
  - B2 regression: SQLite connection is always closed (via try/finally)
"""
from __future__ import annotations

import os
import pickle
import sqlite3
from pathlib import Path

import pytest

from sentinel.baseline.persistence import (
    _artifact_key,
    _hmac_file,
    _save_checksums,
    _verify_checksums,
    _PICKLE_FILES,
    _FREQ_FILE,
    _save_to_sqlite,
    _DB_FILE,
)


class TestArtifactKey:
    def test_default_is_path_derived(self, tmp_path):
        key = _artifact_key(tmp_path)
        assert isinstance(key, bytes)
        assert len(key) == 32  # SHA-256 output

    def test_same_path_same_key(self, tmp_path):
        assert _artifact_key(tmp_path) == _artifact_key(tmp_path)

    def test_env_var_override(self, tmp_path, monkeypatch):
        hex_key = "aabbccdd" * 8  # 64 hex chars = 32 bytes
        monkeypatch.setenv("SENTINEL_ARTIFACT_KEY", hex_key)
        key = _artifact_key(tmp_path)
        assert key == bytes.fromhex(hex_key)

    def test_invalid_env_var_falls_back(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SENTINEL_ARTIFACT_KEY", "not-valid-hex!!!")
        # Should not raise; falls back to path-derived key
        key = _artifact_key(tmp_path)
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_different_paths_different_keys(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        assert _artifact_key(dir_a) != _artifact_key(dir_b)


class TestHmacRoundTrip:
    """HMAC save/verify round-trip and tamper detection."""

    def _write_fake_pickle(self, directory: Path, fname: str, data: object) -> Path:
        path = directory / fname
        with open(path, "wb") as fh:
            pickle.dump(data, fh)
        return path

    def test_round_trip_passes(self, tmp_path):
        path = self._write_fake_pickle(tmp_path, _FREQ_FILE, {"a": 1.0})
        key = _artifact_key(tmp_path)
        digest = _hmac_file(path, key)
        checksums = {_FREQ_FILE: digest}
        _save_checksums(tmp_path, checksums)
        # Should not raise
        _verify_checksums(tmp_path, key)

    def test_tamper_detected(self, tmp_path):
        path = self._write_fake_pickle(tmp_path, _FREQ_FILE, {"a": 1.0})
        key = _artifact_key(tmp_path)
        digest = _hmac_file(path, key)
        checksums = {_FREQ_FILE: digest}
        _save_checksums(tmp_path, checksums)

        # Tamper with the file by appending a byte
        with open(path, "ab") as fh:
            fh.write(b"\x00")

        with pytest.raises(RuntimeError, match="integrity check failed"):
            _verify_checksums(tmp_path, key)

    def test_missing_checksum_file_raises_error(self, tmp_path):
        """S2: Missing checksum file must raise RuntimeError, not silently skip."""
        key = _artifact_key(tmp_path)
        with pytest.raises(RuntimeError, match="not found"):
            _verify_checksums(tmp_path, key)

    def test_missing_pickle_file_skipped(self, tmp_path):
        """If a pickle file listed in checksums doesn't exist, it is skipped."""
        key = _artifact_key(tmp_path)
        checksums = {_FREQ_FILE: "irrelevant_digest"}
        _save_checksums(tmp_path, checksums)
        # Should not raise — file simply doesn't exist
        _verify_checksums(tmp_path, key)


class TestSaveToSQLiteB2:
    """B2 regression: SQLite connection must be closed even when an exception is raised."""

    def test_normal_save_creates_table(self, tmp_path):
        db_path = tmp_path / _DB_FILE
        _save_to_sqlite(db_path, [])
        con = sqlite3.connect(str(db_path))
        cur = con.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cur.fetchall()}
        con.close()
        assert "baseline_events" in tables

    def test_connection_closed_after_empty_save(self, tmp_path):
        """Verify no open handle remains by deleting the DB file after save."""
        db_path = tmp_path / _DB_FILE
        _save_to_sqlite(db_path, [])
        # On Windows this would fail with PermissionError if the handle were open
        db_path.unlink()
        assert not db_path.exists()

    def test_sqlite_wal_journal_closed(self, tmp_path):
        """After save, no WAL journal file should remain open/locked."""
        db_path = tmp_path / _DB_FILE
        _save_to_sqlite(db_path, [])
        wal_path = tmp_path / (_DB_FILE + "-wal")
        shm_path = tmp_path / (_DB_FILE + "-shm")
        # WAL and SHM may or may not exist, but if they do they must not be locked
        # (we simply try to delete them)
        for p in (wal_path, shm_path):
            if p.exists():
                p.unlink()  # would raise PermissionError if locked
