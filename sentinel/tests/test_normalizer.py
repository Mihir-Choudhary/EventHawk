"""
Tests for sentinel.analysis.normalizer.

Q5 — specifically validates _USER_PATH_RE substitution (which would have caught B1),
plus all other normalization stages.
"""
from __future__ import annotations

import pytest

from sentinel.analysis.normalizer import normalize_cmdline, normalize_procname


class TestUserPathRegex:
    """_USER_PATH_RE substitution — B1 regression tests."""

    def test_single_backslash_after_userpath(self):
        """B1 fix: After substitution, there should be exactly ONE backslash
        between {USERPATH} and the remaining path, not two."""
        result = normalize_cmdline(r"C:\Users\admin\AppData\foo.exe")
        # Should produce {userpath}appdata\foo.exe — path continues with one backslash
        assert "userpath}" in result
        # No double backslash after USERPATH
        assert "{userpath}\\\\" not in result

    def test_user_path_collapses_different_users_to_same_template(self):
        """Two cmdlines differing only in username should produce identical templates."""
        cmd1 = r"C:\Users\alice\AppData\Local\Temp\payload.exe"
        cmd2 = r"C:\Users\bob\AppData\Local\Temp\payload.exe"
        assert normalize_cmdline(cmd1) == normalize_cmdline(cmd2)

    def test_mixed_case_users_path(self):
        """_USER_PATH_RE is case-insensitive (re.IGNORECASE)."""
        cmd_lower = r"C:\users\alice\downloads\tool.exe"
        cmd_upper = r"C:\USERS\ALICE\DOWNLOADS\TOOL.EXE"
        assert normalize_cmdline(cmd_lower) == normalize_cmdline(cmd_upper)

    def test_non_user_path_not_replaced(self):
        """Paths that don't match C:\\Users\\... pattern are left alone."""
        result = normalize_cmdline(r"C:\Windows\System32\cmd.exe")
        assert "{userpath}" not in result
        assert "system32" in result

    def test_user_path_with_arguments(self):
        """User path in cmdline with trailing arguments is handled correctly."""
        result = normalize_cmdline(r"C:\Users\jdoe\Desktop\evil.exe --flag value")
        assert "{userpath}" in result
        assert "--flag" in result


class TestGuidMasking:
    def test_guid_with_braces_replaced(self):
        cmd = "svchost.exe -k {E3A7B14C-1234-5678-ABCD-123456789ABC}"
        result = normalize_cmdline(cmd)
        assert "{guid}" in result
        assert "E3A7B14C" not in result

    def test_guid_without_braces_replaced(self):
        cmd = "tool.exe E3A7B14C-1234-5678-ABCD-123456789ABC"
        result = normalize_cmdline(cmd)
        assert "{guid}" in result

    def test_non_guid_hex_not_masked(self):
        """Short hex strings that aren't GUIDs should not be masked."""
        result = normalize_cmdline("cmd.exe /c echo DEADBEEF")
        # DEADBEEF is only 8 chars — not a full GUID
        assert "{guid}" not in result


class TestVersionMasking:
    def test_version_string_replaced(self):
        result = normalize_cmdline("python.exe -m pip install requests==2.31.0")
        assert "{ver}" in result
        assert "2.31.0" not in result

    def test_multi_part_version(self):
        result = normalize_cmdline("installer.exe /v 10.0.19045.1")
        assert "{ver}" in result


class TestEntropyMasking:
    def test_high_entropy_token_masked(self):
        """A long high-entropy string (like a base64 blob) should be masked."""
        # 40-char random-looking hex string — high entropy
        result = normalize_cmdline("powershell.exe -enc aGVsbG8gd29ybGQgZm9vYmFyYmF6cXV4")
        assert "{b64}" in result or "{enc}" in result

    def test_normal_english_words_not_masked(self):
        """Normal words have low entropy and should not be masked."""
        result = normalize_cmdline("cmd.exe /c whoami")
        assert "{enc}" not in result
        assert "{hex}" not in result


class TestNormalizeProcname:
    def test_strips_directory(self):
        assert normalize_procname(r"C:\Windows\System32\cmd.exe") == "cmd.exe"

    def test_lowercase(self):
        assert normalize_procname("POWERSHELL.EXE") == "powershell.exe"

    def test_bare_name_unchanged(self):
        assert normalize_procname("notepad.exe") == "notepad.exe"

    def test_empty_string(self):
        assert normalize_procname("") == ""

    def test_unix_path(self):
        assert normalize_procname("/usr/bin/python3") == "python3"

    def test_name_with_spaces(self):
        assert normalize_procname(r"C:\Program Files\App\my app.exe") == "my app.exe"
