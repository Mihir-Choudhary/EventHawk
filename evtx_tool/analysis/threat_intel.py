"""
Threat Intelligence Checker for IOC entries.

Supports two modes:
  1. Offline — user imports a local file (CSV / TXT / STIX 2.1 JSON)
  2. VirusTotal API v3 — checks hashes, IPs, and domains with rate limiting

Public API
----------
ThreatIntelChecker
    .load_offline(filepath) -> int
    .check_offline(ioc_type, value) -> dict | None
    .check_virustotal(ioc_type, value) -> dict
    .enrich_iocs(iocs, mode, ioc_types, progress_fn) -> None

VirusTotal free tier limits (enforced by _RateLimiter):
    4 requests per minute
    500 requests per day (tracked in-session, warns but does not hard-block)
"""

from __future__ import annotations

import csv
import json
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Callable

# ── Rate limiter ──────────────────────────────────────────────────────────────

class _RateLimiter:
    """
    Enforces at most `max_per_minute` calls in any 60-second window.
    Thread-safe for single-threaded use (dialog runs in GUI thread).
    """

    def __init__(self, max_per_minute: int = 4) -> None:
        self._max   = max_per_minute
        self._times: deque[float] = deque()

    def acquire(self) -> None:
        """Block until a request slot is available."""
        now = time.monotonic()
        # Drop timestamps older than 60 seconds
        while self._times and now - self._times[0] > 60.0:
            self._times.popleft()
        if len(self._times) >= self._max:
            # Wait until the oldest slot is 60+ seconds old
            sleep_for = 61.0 - (now - self._times[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
            # Re-drop after sleeping
            now = time.monotonic()
            while self._times and now - self._times[0] > 60.0:
                self._times.popleft()
        self._times.append(time.monotonic())


# ── VT API endpoint builders ──────────────────────────────────────────────────

_VT_BASE = "https://www.virustotal.com/api/v3"

def _vt_url_for(ioc_type: str, value: str) -> str | None:
    if ioc_type in ("md5", "sha1", "sha256"):
        return f"{_VT_BASE}/files/{value}"
    if ioc_type == "ipv4":
        return f"{_VT_BASE}/ip_addresses/{value}"
    if ioc_type == "ipv6":
        return f"{_VT_BASE}/ip_addresses/{value}"
    if ioc_type == "domains":
        return f"{_VT_BASE}/domains/{value}"
    if ioc_type == "urls":
        import base64
        encoded = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"{_VT_BASE}/urls/{encoded}"
    return None


def _vt_parse_response(data: dict) -> dict:
    """Extract a normalized result from a VT API v3 response body."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) if stats else 0

    positives = malicious + suspicious
    if malicious >= 3:
        verdict = "malicious"
    elif suspicious >= 3:
        verdict = "suspicious"
    elif positives > 0:
        verdict = "potentially_malicious"
    else:
        verdict = "clean"

    ioc_id    = data.get("data", {}).get("id", "")
    link      = f"https://www.virustotal.com/gui/file/{ioc_id}" if ioc_id else ""

    return {
        "positives": positives,
        "total":     total,
        "verdict":   verdict,
        "permalink": link,
        "source":    "virustotal",
    }


# ── Offline data loaders ──────────────────────────────────────────────────────

def _load_csv(filepath: str) -> dict[str, dict[str, str]]:
    """
    Load a CSV file.  Accepted formats:
      - type,value,verdict[,note]     (3+ columns)
      - value,verdict                 (2 columns — type guessed from value)
      - hash                          (1 column — treated as malicious hash)
    Returns dict: {ioc_type: {value: verdict_str}}
    """
    result: dict[str, dict[str, str]] = {}

    def _add(ioc_type: str, val: str, verdict: str) -> None:
        result.setdefault(ioc_type, {})[val.lower()] = verdict

    def _guess_type(val: str) -> str:
        v = val.strip()
        if len(v) == 64:
            return "sha256"
        if len(v) == 40:
            return "sha1"
        if len(v) == 32:
            return "md5"
        if "." in v and not v.startswith("http"):
            return "domains"
        if v.startswith("http"):
            return "urls"
        import re
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', v):
            return "ipv4"
        return "unknown"

    with open(filepath, newline="", encoding="utf-8-sig") as fh:
        sample = fh.read(512)
        fh.seek(0)
        has_header = csv.Sniffer().has_header(sample) if sample else False
        reader = csv.reader(fh)
        if has_header:
            next(reader, None)
        for row in reader:
            row = [c.strip() for c in row]
            if not row:
                continue
            if len(row) >= 3:
                _add(row[0].lower(), row[1], row[2])
            elif len(row) == 2:
                ioc_type = _guess_type(row[0])
                _add(ioc_type, row[0], row[1])
            elif len(row) == 1 and row[0]:
                ioc_type = _guess_type(row[0])
                _add(ioc_type, row[0], "malicious")

    return result


def _load_txt(filepath: str) -> dict[str, dict[str, str]]:
    """
    Load a TXT file — one IOC value per line (treated as malicious).
    Lines starting with # are comments.
    """
    result: dict[str, dict[str, str]] = {}
    import re
    ip_re = re.compile(r'^\d+\.\d+\.\d+\.\d+$')

    with open(filepath, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if len(line) == 64:
                ioc_type = "sha256"
            elif len(line) == 40:
                ioc_type = "sha1"
            elif len(line) == 32:
                ioc_type = "md5"
            elif ip_re.match(line):
                ioc_type = "ipv4"
            elif line.startswith("http"):
                ioc_type = "urls"
            elif "." in line:
                ioc_type = "domains"
            else:
                ioc_type = "unknown"
            result.setdefault(ioc_type, {})[line.lower()] = "malicious"

    return result


def _load_stix(filepath: str) -> dict[str, dict[str, str]]:
    """
    Load a STIX 2.1 bundle JSON.  Extracts indicator objects and maps
    pattern types to IOC types.
    """
    result: dict[str, dict[str, str]] = {}

    _PATTERN_MAP = {
        "ipv4-addr":    "ipv4",
        "ipv6-addr":    "ipv6",
        "domain-name":  "domains",
        "url":          "urls",
        "file:hashes.'MD5'":    "md5",
        "file:hashes.'SHA-1'":  "sha1",
        "file:hashes.'SHA-256'": "sha256",
    }
    import re as _re
    _val_re = _re.compile(r"=\s*'([^']+)'")

    with open(filepath, encoding="utf-8") as fh:
        data = json.load(fh)

    objects = data.get("objects", [])
    for obj in objects:
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        labels  = obj.get("labels", [])
        verdict = "malicious" if any("malicious" in l for l in labels) else "suspicious"
        # Try to parse value from pattern string
        m = _val_re.search(pattern)
        if not m:
            continue
        val = m.group(1).strip()
        # Determine type from pattern prefix
        for prefix, ioc_type in _PATTERN_MAP.items():
            if prefix in pattern:
                result.setdefault(ioc_type, {})[val.lower()] = verdict
                break

    return result


# ── Main class ────────────────────────────────────────────────────────────────

class ThreatIntelChecker:
    """
    Threat intelligence enrichment for extracted IOC entries.

    Usage
    -----
    checker = ThreatIntelChecker()
    checker.load_offline("known_bad.csv")          # offline mode
    checker.enrich_iocs(iocs, mode="offline", ...)

    checker2 = ThreatIntelChecker(api_key="YOUR_VT_KEY")
    checker2.enrich_iocs(iocs, mode="virustotal", ioc_types=["sha256", "ipv4"])
    """

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key  = api_key or ""
        self._offline: dict[str, dict[str, str]] = {}  # {ioc_type: {value: verdict}}
        self._limiter  = _RateLimiter(max_per_minute=4)
        self.daily_count = 0         # Track in-session daily usage (VT free: 500/day)
        self.daily_limit = 500

    # ── Offline methods ───────────────────────────────────────────────────────

    def load_offline(self, filepath: str) -> int:
        """
        Load a known-bad IOC file.  Supports CSV, TXT, and STIX 2.1 JSON.

        Returns the count of loaded IOC entries.
        """
        ext = filepath.rsplit(".", 1)[-1].lower()
        if ext == "csv":
            loaded = _load_csv(filepath)
        elif ext == "json":
            loaded = _load_stix(filepath)
        else:
            loaded = _load_txt(filepath)

        total = 0
        for ioc_type, entries in loaded.items():
            self._offline.setdefault(ioc_type, {}).update(entries)
            total += len(entries)
        return total

    def check_offline(self, ioc_type: str, value: str) -> dict | None:
        """
        Check a single IOC value against loaded offline data.

        Returns {"verdict": str, "source": "offline"} or None if not found.
        """
        bucket = self._offline.get(ioc_type, {})
        verdict = bucket.get(value.lower())
        if verdict:
            return {"verdict": verdict, "source": "offline", "positives": None, "total": None, "permalink": ""}
        return None

    def offline_count(self) -> int:
        """Total number of loaded offline indicators."""
        return sum(len(v) for v in self._offline.values())

    # ── VirusTotal methods ────────────────────────────────────────────────────

    def check_virustotal(self, ioc_type: str, value: str) -> dict:
        """
        Check a single IOC value against VirusTotal API v3.

        Rate-limits to 4 req/min.  Raises ValueError if no API key set.
        Raises urllib.error.HTTPError on API errors.

        Returns: {positives, total, verdict, permalink, source}
        """
        if not self._api_key:
            raise ValueError("No VirusTotal API key set")

        url = _vt_url_for(ioc_type, value)
        if url is None:
            return {"verdict": "unsupported", "positives": 0, "total": 0,
                    "permalink": "", "source": "virustotal"}

        self._limiter.acquire()

        req = urllib.request.Request(
            url,
            headers={"x-apikey": self._api_key, "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"verdict": "not_found", "positives": 0, "total": 0,
                        "permalink": "", "source": "virustotal"}
            raise

        self.daily_count += 1
        return _vt_parse_response(data)

    # ── Bulk enrichment ───────────────────────────────────────────────────────

    def enrich_iocs(
        self,
        iocs: dict,
        mode: str,
        ioc_types: list[str],
        progress_fn: Callable[[int, int, str], None] | None = None,
        cancel_fn:   Callable[[], bool]                 | None = None,
    ) -> None:
        """
        Enrich all IOC entries in-place by setting the 'threat_intel' field.

        Parameters
        ----------
        iocs       : dict   The full IOC dict from extract_iocs.
        mode       : str    "offline" or "virustotal"
        ioc_types  : list[str]  Which IOC types to check.
        progress_fn: callable(checked, total, current_value) — progress callback.
        cancel_fn  : callable() -> bool — return True to abort.
        """
        _SKIP = {"summary", "correlation"}

        # Collect all (ioc_type, entry) tuples to check
        work: list[tuple[str, dict]] = []
        for ioc_type in ioc_types:
            if ioc_type in _SKIP:
                continue
            entries = iocs.get(ioc_type) or []
            for entry in entries:
                if isinstance(entry, dict) and entry.get("value"):
                    work.append((ioc_type, entry))

        total = len(work)
        for idx, (ioc_type, entry) in enumerate(work):
            if cancel_fn and cancel_fn():
                break

            value = entry["value"]

            if progress_fn:
                progress_fn(idx, total, value)

            try:
                if mode == "offline":
                    result = self.check_offline(ioc_type, value)
                elif mode == "virustotal":
                    if self.daily_count >= self.daily_limit:
                        # Soft limit — annotate remaining as skipped
                        entry["threat_intel"] = {
                            "verdict": "daily_limit_reached",
                            "source": "virustotal",
                            "positives": None, "total": None, "permalink": "",
                        }
                        continue
                    result = self.check_virustotal(ioc_type, value)
                else:
                    result = None

                if result:
                    entry["threat_intel"] = result
                    # If known-bad offline, also boost score to 95
                    if result.get("verdict") in ("malicious", "suspicious"):
                        entry["score"] = 95
                        entry["score_reasons"] = [
                            f"Threat intel match — {result.get('verdict', 'malicious')} "
                            f"({result.get('source', 'offline')})"
                        ]

            except Exception as exc:
                entry["threat_intel"] = {
                    "verdict": "error",
                    "source":  mode,
                    "error":   str(exc),
                    "positives": None, "total": None, "permalink": "",
                }

        if progress_fn:
            progress_fn(total, total, "")
