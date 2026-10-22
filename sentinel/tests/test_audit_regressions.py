"""
Regression tests for defects found auditing Sentinel against a real
Security.evtx (117 process-creation events).

Each test names the failure it guards against; all of them failed, or could
not run, before the fix.
"""
import copy
import logging
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import sentinel.analysis.parser as parser_mod
from sentinel.analysis.parser import _parse_record, _parse_single_evtx, _parse_ts
from sentinel.analysis.scorer import composite_score
from sentinel.baseline.trie import AncestryTrie
from sentinel.config import load_config
from sentinel.models import RawEvent, TierBoundaries

REPO = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 2, 11, 13, 39, 14, tzinfo=timezone.utc)


# ── Timestamps: every event used to land in the year 0001 ───────────────────

def _event_4688(system_time="2026-02-17T20:49:12.724603Z", eid=4688):
    return {"Event": {
        "System": {"EventID": eid, "Computer": "HOST",
                   "TimeCreated": {"#attributes": {"SystemTime": system_time}}},
        "EventData": {"NewProcessName": r"C:\Windows\System32\cmd.exe",
                      "ParentProcessName": r"C:\Windows\explorer.exe",
                      "NewProcessId": "0x10", "ProcessId": "0x4",
                      "CommandLine": "cmd.exe /c dir"},
    }}


class TestTimestamps:
    def test_record_level_utc_suffix_parses(self):
        # pyevtx-rs formats the record-level timestamp with a trailing " UTC".
        dt = _parse_ts("2026-02-17T20:49:12.7246031Z UTC")
        assert (dt.year, dt.month, dt.day, dt.hour) == (2026, 2, 17, 20)

    def test_systemtime_preferred_over_record_timestamp(self):
        ev = _parse_record(_event_4688(), "1999-01-01T00:00:00Z UTC")
        assert ev.timestamp == datetime(2026, 2, 17, 20, 49, 12, 724603, tzinfo=timezone.utc)

    def test_falls_back_to_record_timestamp(self):
        data = _event_4688()
        del data["Event"]["System"]["TimeCreated"]
        ev = _parse_record(data, "2026-02-17T20:49:12.7246031Z UTC")
        assert ev.timestamp.year == 2026


# ── Tier boundaries: collapsed calibration made a boot event Tier 4 ─────────

class TestTierBoundaries:
    W = load_config(None).drift_bonus_weight

    def test_collapsed_calibration_gets_working_bands(self):
        b = TierBoundaries(3.5, 3.5, 3.5).for_scoring(self.W)
        assert b.suppress_max < b.aggregate_max < b.highlight_max
        assert (b.aggregate_max, b.highlight_max) == (45.0, 70.0)

    def test_suppression_is_not_floored(self):
        # A fixed floor of 20 would suppress an unseen command line of a
        # known process, measured at 11.1 on the real baseline.
        b = TierBoundaries(3.5, 3.5, 3.5).for_scoring(self.W)
        assert b.classify(11.1) >= 2

    @pytest.mark.parametrize("s_cmd,s_lin,trie", [
        (0.0, 2.766, 0.0), (0.0, 1.585, 0.333), (4.0, 6.0, 0.5), (0.0, 0.0, 0.0),
        (20.0, 20.0, 1.0),
    ])
    def test_drift_alone_cannot_lift_a_baseline_level_event(self, s_cmd, s_lin, trie):
        calibrated = composite_score(s_cmd, s_lin, trie, 0.0, 0.0)
        b = TierBoundaries(calibrated, calibrated, calibrated).for_scoring(self.W)
        worst = composite_score(s_cmd, s_lin, trie, 0.0, 1.0)
        assert b.classify(worst) == 1

    def test_noisy_calibration_stays_monotonic(self):
        b = TierBoundaries(60.0, 60.0, 60.0).for_scoring(self.W)
        assert b.suppress_max <= b.aggregate_max <= b.highlight_max
        assert b.suppress_max >= 60.0


# ── Ancestry trie: baseline chains were shallower than analysis chains ──────

class TestTrieQueryScored:
    def _trie(self, *chains):
        t = AncestryTrie()
        for c in chains:
            t.insert(c)
        return t

    def test_unrecorded_deeper_level_is_not_a_miss(self):
        t = self._trie(["lsass.exe", "wininit.exe"])
        assert t.query_scored(["lsass.exe", "wininit.exe", "smss.exe"]) == (2, 2)

    def test_recorded_deeper_mismatch_still_counts(self):
        t = self._trie(["lsass.exe", "wininit.exe", "smss.exe"])
        assert t.query_scored(["lsass.exe", "wininit.exe", "evil.exe"]) == (2, 3)

    def test_unseen_process_is_full_miss(self):
        t = self._trie(["lsass.exe", "wininit.exe"])
        assert t.query_scored(["mimikatz.exe", "winword.exe"]) == (0, 2)

    def test_unseen_parent_is_a_miss(self):
        t = self._trie(["lsass.exe", "wininit.exe"])
        assert t.query_scored(["lsass.exe", "winword.exe"]) == (1, 2)


# ── End to end: baseline-identical activity must be suppressed ──────────────

def _raw(ts, eid, pid, ppid, name, parent, cmd):
    return RawEvent(timestamp=ts, host="HOST", event_id=eid, process_guid="",
                    pid=pid, ppid=ppid, parent_guid="",
                    process_name=name, process_path="C:\\Windows\\System32\\" + name,
                    parent_name=parent, parent_path="C:\\Windows\\System32\\" + parent,
                    cmdline=cmd, user="SYSTEM", integrity_level="System", image_hash="")


def _boots(n=6):
    """n boots: smss -> wininit -> {lsass, services}, plus autochk, terminations."""
    evs = []
    for i in range(n):
        t = T0 + timedelta(days=i)
        base = 0x1000 * (i + 1)
        evs += [
            _raw(t, 4688, base + 1, 4, "smss.exe", "System", r"\SystemRoot\System32\smss.exe"),
            _raw(t + timedelta(seconds=1), 4688, base + 2, base + 1, "autochk.exe", "smss.exe", "autochk *"),
            _raw(t + timedelta(seconds=2), 4689, base + 2, 0, "autochk.exe", "", ""),
            _raw(t + timedelta(seconds=3), 4688, base + 3, base + 1, "wininit.exe", "smss.exe", "wininit.exe"),
            _raw(t + timedelta(seconds=4), 4688, base + 4, base + 3, "lsass.exe", "wininit.exe", r"C:\Windows\system32\lsass.exe"),
            _raw(t + timedelta(seconds=5), 4688, base + 5, base + 3, "services.exe", "wininit.exe", r"C:\Windows\system32\services.exe"),
        ]
    return evs


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    """Run the real build + analysis over synthetic events (no EVTX needed)."""
    from sentinel.analysis.engine import run_analysis
    from sentinel.baseline.builder import build_baseline

    def run(baseline_events, target_events):
        fake = tmp_path / "x.evtx"
        fake.write_bytes(b"not parsed")
        feed = {"events": baseline_events}
        monkeypatch.setattr(parser_mod, "parse_evtx_files",
                            lambda paths, progress_cb=None: copy.deepcopy(feed["events"]))
        build_baseline([fake], tmp_path / "base")
        feed["events"] = target_events
        return run_analysis([fake], tmp_path / "base")
    return run


class TestEndToEnd:
    def test_baseline_identical_activity_is_tier1(self, pipeline):
        scored, metrics = pipeline(_boots(), _boots())
        assert scored and all(s.tier == 1 for s in scored), \
            [(s.raw.process_name, s.composite, s.tier) for s in scored if s.tier != 1]

    def test_baseline_records_full_lineage(self, pipeline):
        scored, _ = pipeline(_boots(), _boots())
        lsass = next(s for s in scored if s.raw.process_name == "lsass.exe")
        assert lsass.normalized.ancestry_chain == ["lsass.exe", "wininit.exe", "smss.exe"]
        assert lsass.trie_depth_score == 0.0

    def test_novel_process_is_not_suppressed(self, pipeline):
        target = _boots()
        t = target[-1].timestamp + timedelta(seconds=1)
        target.append(_raw(t, 4688, 0xBEEF, target[-1].pid, "mimikatz.exe",
                           "services.exe", "mimikatz.exe sekurlsa::logonpasswords"))
        scored, _ = pipeline(_boots(), target)
        nov = next(s for s in scored if s.raw.process_name == "mimikatz.exe")
        assert nov.tier == 4
        assert all(s.tier == 1 for s in scored if s is not nov)

    def test_effective_boundaries_are_reported(self, pipeline):
        _, metrics = pipeline(_boots(), _boots())
        b = metrics["tier_boundaries"]
        assert b["suppress_max"] < b["aggregate_max"] < b["highlight_max"]

    def test_empty_input_keeps_file_hashes(self, pipeline):
        scored, metrics = pipeline(_boots(), [])
        assert scored == []
        assert len(metrics["input_file_hashes"]) == 1
        assert all(len(h) == 64 for h in metrics["input_file_hashes"].values())


# ── Skipped records used to vanish without a trace ──────────────────────────

class _FakeEvtx:
    def __init__(self, records):
        self._records = records

    def PyEvtxParser(self, _path):  # noqa: N802 -- mirrors the evtx API
        records = self._records

        class _P:
            def records_json(self):
                return iter(records)
        return _P()


def test_serial_parse_reports_skipped_records(caplog):
    import json
    good = {"data": json.dumps(_event_4688()), "timestamp": ""}
    records = [RuntimeError("bad chunk"), {"data": "{not json", "timestamp": ""},
               {"data": "x" * 1_100_000, "timestamp": ""}, good]
    with caplog.at_level(logging.WARNING, logger="sentinel.analysis.parser"):
        seen, matched, events = _parse_single_evtx(Path("s.evtx"), _FakeEvtx(records))
    assert matched == 1 and len(events) == 1
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "skipped 1 corrupt, 1 oversized (>1 MB) and 1 unparseable" in msg


def test_parallel_parse_bad_record_does_not_drop_rest_of_file(monkeypatch, caplog):
    bad = _event_4688()
    bad["Event"]["System"]["EventID"] = {"#text": "not-a-number"}
    good = _event_4688()

    def worker(path_str):
        return 2, 2, [{"data": bad, "ts_raw": ""}, {"data": good, "ts_raw": ""}], \
            parser_mod._new_skips()

    monkeypatch.setattr(parser_mod, "ProcessPoolExecutor", ThreadPoolExecutor)
    monkeypatch.setattr(parser_mod, "_parse_path_worker", worker)
    with caplog.at_level(logging.WARNING, logger="sentinel.analysis.parser"):
        events = parser_mod.parse_evtx_files_parallel([Path("a.evtx"), Path("b.evtx")])
    assert len(events) == 2                       # the good record of each file
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "Worker failed" not in msg
    assert "1 unparseable" in msg


def test_parallel_open_failure_is_reported(monkeypatch, caplog):
    # Logged inside the pool worker it stayed in that process, unseen.
    def worker(path_str):
        skips = parser_mod._new_skips()
        skips["open_error"] = "bad header"
        return 0, 0, [], skips

    monkeypatch.setattr(parser_mod, "ProcessPoolExecutor", ThreadPoolExecutor)
    monkeypatch.setattr(parser_mod, "_parse_path_worker", worker)
    with caplog.at_level(logging.WARNING, logger="sentinel.analysis.parser"):
        parser_mod.parse_evtx_files_parallel([Path("a.evtx"), Path("b.evtx")])
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "Could not read a.evtx: bad header" in msg
    assert "Could not read b.evtx: bad header" in msg


def test_broken_pool_falls_back_to_in_process_reading(monkeypatch, caplog):
    # A broken pool fails each future; the analysis used to "complete" with 0.
    from concurrent.futures.process import BrokenProcessPool

    def worker(path_str):
        raise BrokenProcessPool("pool died")

    one = _parse_record(_event_4688(), "")
    monkeypatch.setattr(parser_mod, "ProcessPoolExecutor", ThreadPoolExecutor)
    monkeypatch.setattr(parser_mod, "_parse_path_worker", worker)
    monkeypatch.setattr(parser_mod, "_parse_single_evtx",
                        lambda path, mod: (1, 1, [copy.deepcopy(one)]))
    with caplog.at_level(logging.WARNING, logger="sentinel.analysis.parser"):
        events = parser_mod.parse_evtx_files_parallel([Path("a.evtx"), Path("b.evtx")])
    assert len(events) == 2
    assert "reading it in-process instead" in " ".join(r.getMessage() for r in caplog.records)


def test_serial_read_error_keeps_events_already_read(caplog):
    import json

    class _Stops:
        def PyEvtxParser(self, _path):  # noqa: N802
            class _P:
                def records_json(self):
                    yield {"data": json.dumps(_event_4688()), "timestamp": ""}
                    raise RuntimeError("Failed to build string cache")
            return _P()

    with caplog.at_level(logging.WARNING, logger="sentinel.analysis.parser"):
        seen, matched, events = _parse_single_evtx(Path("s.evtx"), _Stops())
    assert len(events) == 1                 # used to be discarded with the error
    msg = " ".join(r.getMessage() for r in caplog.records)
    assert "Could not read s.evtx" in msg and "stopped after 1 record(s)" in msg


def test_gui_forwards_this_threads_warnings_only():
    import threading
    pytest.importorskip("PySide6")
    from sentinel.gui.widgets import forward_warnings

    got = []
    log = logging.getLogger("sentinel.analysis.parser")
    with forward_warnings(got.append):
        log.warning("x.evtx: skipped 3 corrupt")
        log.info("progress chatter")
        t = threading.Thread(target=lambda: log.warning("other tab's job"))
        t.start()
        t.join()
    log.warning("after the job")
    assert got == ["WARNING: x.evtx: skipped 3 corrupt"]


# ── Packaging ───────────────────────────────────────────────────────────────

def test_requirements_name_the_library_sentinel_imports():
    reqs = [ln.split("#")[0].strip()
            for ln in (REPO / "sentinel" / "requirements.txt").read_text(encoding="utf-8").splitlines()]
    names = {r.split(">")[0].split("=")[0].strip().lower() for r in reqs if r}
    assert "evtx" in names            # pyevtx-rs, imported as `evtx`
    assert "python-evtx" not in names  # a different library with no PyEvtxParser


@pytest.mark.skipif(shutil.which("git") is None or not (REPO / ".git").exists(),
                    reason="needs a git checkout")
def test_baseline_source_package_is_not_gitignored():
    # An unanchored "baseline/" rule kept sentinel/baseline/ (10 import sites)
    # out of the repository: a clean checkout could not build or analyse.
    for f in ("__init__.py", "builder.py", "trie.py", "persistence.py"):
        r = subprocess.run(["git", "check-ignore", "-q", f"sentinel/baseline/{f}"],
                           cwd=REPO, capture_output=True)
        assert r.returncode == 1, f"sentinel/baseline/{f} is ignored by .gitignore"
