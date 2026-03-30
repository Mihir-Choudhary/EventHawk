"""
Tests for sentinel.analysis.scorer.

Verifies composite_score formula, trie_depth_score, and image_hash_bonus.
"""
import pytest
from sentinel.analysis.scorer import composite_score, trie_depth_score, image_hash_bonus


class TestCompositeScore:
    def test_score_in_range(self):
        score = composite_score(10.0, 10.0, 0.5, 0.0, 0.0)
        assert 0.0 <= score <= 100.0

    def test_all_zeros_gives_low_score(self):
        """No anomaly: 0 surprisal components → score closer to 0."""
        score = composite_score(0.0, 0.0, 0.0, 0.0, 0.0)
        assert score < 10.0

    def test_max_surprisal_gives_high_score(self):
        """MAX conditions across all signals → score close to 100."""
        score = composite_score(20.0, 20.0, 1.0, 1.0, 1.0)
        assert score > 80.0

    def test_ppid_flag_increases_score(self):
        """PPID mismatch flag should always raise score."""
        base   = composite_score(5.0, 5.0, 0.3, 0.0, 0.0)
        raised = composite_score(5.0, 5.0, 0.3, 1.0, 0.0)
        assert raised > base

    def test_drift_bonus_increases_score(self):
        """High host drift should increase composite score."""
        no_drift   = composite_score(5.0, 5.0, 0.3, 0.0, 0.0)
        with_drift = composite_score(5.0, 5.0, 0.3, 0.0, 0.9)
        assert with_drift > no_drift

    def test_hash_bonus_increases_score(self):
        """Binary hash mismatch bonus should push score up."""
        no_hash   = composite_score(5.0, 5.0, 0.3, 0.0, 0.0, hash_bonus=0.0)
        with_hash = composite_score(5.0, 5.0, 0.3, 0.0, 0.0, hash_bonus=1.0)
        assert with_hash > no_hash

    def test_score_capped_at_100(self):
        """Score must never exceed 100.0 even with all signals maxed."""
        score = composite_score(20.0, 20.0, 1.0, 1.0, 1.0, hash_bonus=1.0)
        assert score <= 100.0


class TestTrieDepthScore:
    def test_full_match_gives_zero(self):
        """match_depth == chain_len means full baseline match → 0.0 anomaly."""
        assert trie_depth_score(3, 3) == pytest.approx(0.0)

    def test_no_match_gives_one(self):
        """match_depth == 0 means process unseen at root → 1.0 anomaly."""
        assert trie_depth_score(0, 3) == pytest.approx(1.0)

    def test_partial_match(self):
        score = trie_depth_score(2, 4)
        assert 0.0 < score < 1.0

    def test_zero_chain_length_returns_max(self):
        """Empty chain → maximum anomaly."""
        assert trie_depth_score(0, 0) == pytest.approx(1.0)


class TestImageHashBonus:
    def test_no_hash_gives_zero(self):
        assert image_hash_bonus("cmd.exe", "", {}) == 0.0

    def test_no_prior_gives_zero(self):
        """First time seeing process — no comparison possible."""
        assert image_hash_bonus("cmd.exe", "SHA256=AABBCC", {}) == 0.0

    def test_matching_hash_gives_zero(self):
        known = {"cmd.exe": {"SHA256=AABBCC"}}
        assert image_hash_bonus("cmd.exe", "SHA256=AABBCC", known) == 0.0

    def test_mismatching_hash_gives_one(self):
        """Process seen before with different hash → suspicious."""
        known = {"cmd.exe": {"SHA256=KNOWN_GOOD"}}
        assert image_hash_bonus("cmd.exe", "SHA256=DIFFERENT", known) == 1.0

    def test_empty_proc_gives_zero(self):
        known = {"cmd.exe": {"SHA256=KNOWN"}}
        assert image_hash_bonus("", "SHA256=KNOWN", known) == 0.0
