"""
Tests for sentinel.analysis.parser._flatten_event_data and hash_evtx_files.

Covers Q5 — _flatten_event_data for the three JSON shapes python-evtx produces,
plus F11/S5 — hash_evtx_files produces correct SHA-256 digests.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

from sentinel.analysis.parser import _flatten_event_data, hash_evtx_files, _parse_ts, _int


class TestFlattenEventData:
    """_flatten_event_data handles three EventData shapes (Q5)."""

    def test_list_shape(self):
        """List-of-dicts shape: [{#attributes: {Name: k}, #text: v}, ...]"""
        event_data = {
            "Data": [
                {"#attributes": {"Name": "NewProcessName"}, "#text": "C:\\Windows\\cmd.exe"},
                {"#attributes": {"Name": "CommandLine"}, "#text": "cmd.exe /c whoami"},
                {"#attributes": {"Name": "SubjectUserName"}, "#text": "SYSTEM"},
            ]
        }
        result = _flatten_event_data(event_data)
        assert result["NewProcessName"] == "C:\\Windows\\cmd.exe"
        assert result["CommandLine"] == "cmd.exe /c whoami"
        assert result["SubjectUserName"] == "SYSTEM"

    def test_dict_under_data_key(self):
        """Dict-under-Data shape: {Data: {k: v, ...}}"""
        event_data = {
            "Data": {
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "ProcessId": "1234",
                "#attributes": {"ignored": "yes"},
            }
        }
        result = _flatten_event_data(event_data)
        assert result["Image"] == "C:\\Windows\\System32\\powershell.exe"
        assert result["ProcessId"] == "1234"
        # #-prefixed keys are excluded
        assert "#attributes" not in result

    def test_flat_shape(self):
        """Flat shape: {k: v, ...} — no Data key."""
        event_data = {
            "Image": "C:\\Windows\\svchost.exe",
            "ParentImage": "C:\\Windows\\services.exe",
        }
        result = _flatten_event_data(event_data)
        assert result["Image"] == "C:\\Windows\\svchost.exe"
        assert result["ParentImage"] == "C:\\Windows\\services.exe"

    def test_empty_returns_empty_dict(self):
        assert _flatten_event_data({}) == {}
        assert _flatten_event_data(None) == {}

    def test_list_item_missing_text_becomes_empty_string(self):
        """Items with no #text key should map to empty string, not raise."""
        event_data = {
            "Data": [
                {"#attributes": {"Name": "EmptyField"}},  # no #text
            ]
        }
        result = _flatten_event_data(event_data)
        assert result.get("EmptyField") == ""

    def test_list_item_without_name_is_skipped(self):
        """Items where #attributes has no Name are silently skipped."""
        event_data = {
            "Data": [
                {"#text": "orphaned_value"},  # no #attributes
                {"#attributes": {}, "#text": "no_name"},
            ]
        }
        result = _flatten_event_data(event_data)
        assert result == {}

    def test_none_value_becomes_empty_string(self):
        """None #text values are coerced to empty string."""
        event_data = {
            "Data": [
                {"#attributes": {"Name": "NullField"}, "#text": None},
            ]
        }
        result = _flatten_event_data(event_data)
        assert result["NullField"] == ""


class TestIntParser:
    """_int() correctly handles decimal, hex-prefixed, and garbage inputs."""

    def test_decimal_string(self):
        from sentinel.analysis.parser import _int
        assert _int("1234") == 1234

    def test_hex_prefixed_string(self):
        assert _int("0x4D2") == 1234

    def test_zero_string(self):
        assert _int("0") == 0

    def test_garbage_returns_zero(self):
        assert _int("not-a-number") == 0

    def test_none_returns_zero(self):
        assert _int(None) == 0

    def test_decimal_string_not_misread_as_octal(self):
        # "010" in base-0 would be octal 8; in base-10 it's 10
        assert _int("010") == 10


class TestHashEvtxFiles:
    """hash_evtx_files returns correct SHA-256 digests (F11/S5).

    B5: Keys are full resolved paths (not basenames) to prevent collision
    when multiple files from different directories share the same name.
    """

    def test_known_content(self, tmp_path):
        f = tmp_path / "test.evtx"
        content = b"EVTX test content for hashing"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()
        result = hash_evtx_files([f])
        assert result[str(f.resolve())] == expected

    def test_multiple_files(self, tmp_path):
        files = []
        for i in range(3):
            p = tmp_path / f"file{i}.evtx"
            p.write_bytes(f"content {i}".encode())
            files.append(p)
        result = hash_evtx_files(files)
        assert len(result) == 3
        for p in files:
            key = str(p.resolve())
            assert key in result
            assert len(result[key]) == 64  # sha256 hex = 64 chars

    def test_missing_file_returns_error(self, tmp_path):
        missing = tmp_path / "nonexistent.evtx"
        result = hash_evtx_files([missing])
        assert result[str(missing.resolve())] == "ERROR"

    def test_empty_list(self):
        assert hash_evtx_files([]) == {}

    def test_two_files_with_same_content_same_hash(self, tmp_path):
        f1 = tmp_path / "a.evtx"
        f2 = tmp_path / "b.evtx"
        f1.write_bytes(b"identical content")
        f2.write_bytes(b"identical content")
        result = hash_evtx_files([f1, f2])
        assert result[str(f1.resolve())] == result[str(f2.resolve())]

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.evtx"
        f2 = tmp_path / "b.evtx"
        f1.write_bytes(b"content A")
        f2.write_bytes(b"content B")
        result = hash_evtx_files([f1, f2])
        assert result[str(f1.resolve())] != result[str(f2.resolve())]

