"""
Tests for sentinel.baseline.fuse_store.

Key invariant: _triplet_key must be deterministic across Python processes
regardless of PYTHONHASHSEED.  This test verifies that two calls with identical
input always return the same key (regression guard for the hash→SHA-256 fix).
"""
import pytest

from sentinel.baseline.fuse_store import FuseStore, _triplet_key


class TestTripletKeyStability:
    def test_same_inputs_produce_same_key(self):
        k1 = _triplet_key("cmd.exe", "explorer.exe", "cmd /c whoami")
        k2 = _triplet_key("cmd.exe", "explorer.exe", "cmd /c whoami")
        assert k1 == k2

    def test_different_proc_yields_different_key(self):
        k1 = _triplet_key("cmd.exe", "explorer.exe", "cmd /c whoami")
        k2 = _triplet_key("powershell.exe", "explorer.exe", "cmd /c whoami")
        assert k1 != k2

    def test_different_parent_yields_different_key(self):
        k1 = _triplet_key("cmd.exe", "explorer.exe", "cmd /c whoami")
        k2 = _triplet_key("cmd.exe", "svchost.exe", "cmd /c whoami")
        assert k1 != k2

    def test_different_cmdline_yields_different_key(self):
        k1 = _triplet_key("cmd.exe", "explorer.exe", "cmd /c whoami")
        k2 = _triplet_key("cmd.exe", "explorer.exe", "cmd /c ipconfig")
        assert k1 != k2

    def test_key_is_integer(self):
        k = _triplet_key("a", "b", "c")
        assert isinstance(k, int)
        assert k >= 0

    def test_null_byte_separator_prevents_collision(self):
        # "ab" + "c" should differ from "a" + "bc"
        k1 = _triplet_key("ab", "c", "d")
        k2 = _triplet_key("a", "bc", "d")
        assert k1 != k2

    def test_known_stable_value(self):
        """Golden value test — if SHA-256 changes, this will catch it."""
        import hashlib, struct
        digest = hashlib.sha256(
            "cmd.exe\x00explorer.exe\x00cmd /c whoami".encode("utf-8")
        ).digest()
        expected = struct.unpack_from(">Q", digest)[0]
        assert _triplet_key("cmd.exe", "explorer.exe", "cmd /c whoami") == expected


class TestFuseStoreBuildQuery:
    def _make_events(self):
        from unittest.mock import MagicMock
        evs = []
        for cmdline in ["cmd /c whoami", "cmd /c ipconfig"]:
            ev = MagicMock()
            ev.proc_norm = "cmd.exe"
            ev.parent_norm = "explorer.exe"
            ev.cmdline_norm = cmdline
            evs.append(ev)
        return evs

    def test_build_and_contains(self):
        evs = self._make_events()
        store = FuseStore()
        store.build(evs)
        assert store.contains("cmd.exe", "explorer.exe", "cmd /c whoami")
        assert store.contains("cmd.exe", "explorer.exe", "cmd /c ipconfig")

    def test_not_contains_unseen(self):
        evs = self._make_events()
        store = FuseStore()
        store.build(evs)
        # Key not in the filter — should return False (with very high probability)
        assert not store.contains("powershell.exe", "winlogon.exe", "PS encoding stuff")

    def test_empty_store(self):
        store = FuseStore()
        store.build([])
        assert not store.contains("cmd.exe", "explorer.exe", "x")

