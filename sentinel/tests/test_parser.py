"""
Tests for sentinel.analysis.parser._parse_ts.

Verifies UTC-aware datetime parsing and fractional second preservation.
"""
import pytest
from datetime import datetime, timezone

from sentinel.analysis.parser import _parse_ts


class TestParseTs:
    def test_z_suffix_parsed_as_utc(self):
        dt = _parse_ts("2024-01-15T14:30:45.123456Z")
        assert dt.tzinfo is not None
        assert dt.tzinfo == timezone.utc

    def test_fractional_seconds_preserved(self):
        dt = _parse_ts("2024-01-15T14:30:45.123456Z")
        assert dt.microsecond == 123456

    def test_milliseconds_preserved(self):
        dt = _parse_ts("2024-01-15T14:30:45.123Z")
        assert dt.microsecond == 123000

    def test_no_fraction_works(self):
        dt = _parse_ts("2024-01-15T14:30:45Z")
        assert dt.second == 45
        assert dt.microsecond == 0
        assert dt.tzinfo == timezone.utc

    def test_no_timezone_assumes_utc(self):
        """Timestamps without tz info should be treated as UTC."""
        dt = _parse_ts("2024-01-15T14:30:45.000")
        assert dt.tzinfo == timezone.utc

    def test_positive_offset(self):
        dt = _parse_ts("2024-01-15T14:30:45+05:30")
        assert dt.tzinfo is not None

    def test_invalid_returns_utc_min(self):
        """Malformed timestamp should return datetime.min with UTC tzinfo."""
        dt = _parse_ts("not-a-timestamp")
        assert dt.tzinfo == timezone.utc
        assert dt == datetime.min.replace(tzinfo=timezone.utc)

    def test_ordering_preserved_for_subsecond(self):
        """Sub-second precision must allow correct ordering."""
        dt1 = _parse_ts("2024-01-15T14:30:45.001Z")
        dt2 = _parse_ts("2024-01-15T14:30:45.002Z")
        assert dt1 < dt2

    def test_t_separator_accepted(self):
        dt = _parse_ts("2024-06-01T00:00:00.000000Z")
        assert dt.year == 2024
        assert dt.month == 6
