"""
Tests for sentinel.config.

Verifies SentinelConfig defaults, JSON loading, validation, and unknown-key skipping.
"""
import json
import pytest
from pathlib import Path

from sentinel.config import SentinelConfig, load_config


class TestSentinelConfigDefaults:
    def test_default_weights_sum_to_one(self):
        cfg = SentinelConfig()
        total = cfg.weight_cmdline + cfg.weight_lineage + cfg.weight_trie + cfg.weight_ppid
        assert abs(total - 1.0) < 1e-6

    def test_default_max_surprisal(self):
        cfg = SentinelConfig()
        assert cfg.max_surprisal == 20.0

    def test_default_drift_window(self):
        cfg = SentinelConfig()
        assert cfg.drift_window_minutes == 30

    def test_validate_passes_for_defaults(self):
        SentinelConfig().validate()  # must not raise


class TestSentinelConfigValidation:
    def test_weights_not_summing_to_one_raises(self):
        cfg = SentinelConfig(weight_cmdline=0.5, weight_lineage=0.5, weight_trie=0.5, weight_ppid=0.5)
        with pytest.raises(ValueError, match="sum to 1.0"):
            cfg.validate()


class TestLoadConfig:
    def test_load_none_returns_defaults(self):
        cfg = load_config(None)
        assert isinstance(cfg, SentinelConfig)
        assert cfg.max_surprisal == 20.0

    def test_load_missing_file_returns_defaults(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.json")
        assert isinstance(cfg, SentinelConfig)

    def test_load_valid_json(self, tmp_path):
        config_file = tmp_path / "sentinel_config.json"
        data = {
            "max_surprisal": 15.0,
            "weight_cmdline": 0.40,
            "weight_lineage": 0.20,
            "weight_trie":    0.25,
            "weight_ppid":    0.15,
            "drift_window_minutes": 60,
        }
        config_file.write_text(json.dumps(data))
        cfg = load_config(config_file)
        assert cfg.max_surprisal == 15.0
        assert cfg.drift_window_minutes == 60

    def test_unknown_keys_ignored(self, tmp_path):
        config_file = tmp_path / "sentinel_config.json"
        data = {"unknown_future_param": 99, "max_surprisal": 18.0}
        config_file.write_text(json.dumps(data))
        cfg = load_config(config_file)
        assert cfg.max_surprisal == 18.0

    def test_invalid_json_raises(self, tmp_path):
        config_file = tmp_path / "bad.json"
        config_file.write_text("{not valid json}")
        with pytest.raises(ValueError, match="Invalid JSON"):
            load_config(config_file)
