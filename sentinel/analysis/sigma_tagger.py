"""
Sigma pre-tagging (optional).

Tags RawEvents with MITRE ATT&CK technique IDs using pySigma community rules.
Must run BEFORE normalization so raw payloads (e.g., encoded PowerShell commands)
are visible to Sigma rule patterns.

Evaluation strategy:
  - Keyword fallback: Sigma rule title words matched against CommandLine field.
    This is a heuristic — not full Sigma backend evaluation — but is useful for
    ATT&CK technique enrichment when no platform-specific backend is configured.

The active mode is logged at INFO level so analysts know which path is taken.

NOTE: pySigma backends are platform-specific (Splunk, Elasticsearch, etc.).
There is no generic "Python" backend on PyPI.  If a platform-specific backend
is needed in the future, implement a custom compilation step here.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models import RawEvent

logger = logging.getLogger(__name__)


class SigmaTagger:
    """
    Loads Sigma rules from a directory and evaluates them against RawEvents.
    Rules are pre-compiled once at construction time.
    """

    def __init__(self, rules_dir: Path) -> None:
        self._rules: list[tuple] = []  # list of (_KeywordPredicate, list[str]) pairs
        self._mode: str = "none"
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: Path) -> None:
        try:
            from sigma.collection import SigmaCollection
        except ImportError:
            logger.warning(
                "pySigma not installed. Sigma pre-tagging disabled. "
                "Install with: pip install pySigma"
            )
            return

        yml_files = list(rules_dir.rglob("*.yml"))
        if not yml_files:
            logger.warning("No Sigma rule files found in %s", rules_dir)
            return

        # S4: Pre-validate YAML to prevent code execution via crafted tags
        # (e.g. !!python/object). pySigma uses PyYAML internally which can
        # deserialize arbitrary Python objects from untrusted YAML.
        try:
            import yaml
            safe_files = []
            for f in yml_files:
                try:
                    with open(f, encoding="utf-8") as fh:
                        yaml.safe_load(fh)
                    safe_files.append(f)
                except yaml.YAMLError as ye:
                    logger.warning("Skipping unsafe/invalid YAML: %s (%s)", f.name, ye)
            yml_files = safe_files
        except ImportError:
            logger.debug("PyYAML not available for pre-validation; proceeding with pySigma directly")

        if not yml_files:
            logger.warning("No valid Sigma rule files found after YAML validation")
            return

        logger.info("Loading %d Sigma rule files from %s", len(yml_files), rules_dir)

        try:
            collection = SigmaCollection.load_ruleset(yml_files)
            self._build_keyword_fallback(collection)
            logger.info(
                "Sigma: compiled %d rules via keyword matching (heuristic — "
                "ATT&CK tags are best-effort, not authoritative)",
                len(self._rules),
            )
            self._mode = "keyword"
        except Exception as exc:
            logger.warning("Failed to load Sigma rules: %s", exc)

    def _build_keyword_fallback(self, collection) -> None:
        """Build keyword matchers from Sigma rule titles and detection fields."""
        for rule in collection.rules:
            tags = [str(t) for t in (rule.tags or [])]
            technique_ids = [
                t.replace('attack.', '').upper()
                for t in tags
                if t.startswith('attack.t')
            ]
            if not technique_ids:
                continue
            # Extract detection keywords from rule title as a rough heuristic
            keywords = rule.title.lower().split() if rule.title else []
            if keywords:
                self._rules.append((_KeywordPredicate(keywords), technique_ids))

    def tag(self, ev: "RawEvent") -> list[str]:
        """
        Return list of MITRE technique IDs that match this event.
        Empty list if no rules match or Sigma is unavailable.
        """
        if not self._rules:
            return []

        matched: set[str] = set()
        event_dict = _event_to_dict(ev)

        for pred, technique_ids in self._rules:
            try:
                if pred(event_dict):
                    matched.update(technique_ids)
            except Exception:
                pass

        return sorted(matched)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def mode(self) -> str:
        """'keyword' or 'none'."""
        return self._mode


class _KeywordPredicate:
    """Fallback: matches if at least 2 meaningful keywords appear in the cmdline.

    B10: Requires multiple keyword matches and filters out short/common words
    that would match almost every event (e.g. 'new', 'command', 'process').
    """

    _STOPWORDS = frozenset({
        'a', 'an', 'and', 'by', 'for', 'from', 'in', 'is', 'it', 'of', 'on',
        'or', 'the', 'to', 'via', 'with', 'new', 'use', 'using',
        'command', 'process', 'execution', 'creation', 'service',
        'detection', 'suspicious', 'possible', 'potential', 'generic',
        'file', 'event', 'system', 'windows', 'line', 'based',
    })
    _MIN_KEYWORD_LEN = 4

    def __init__(self, keywords: list[str]) -> None:
        self.keywords = [
            kw for kw in keywords
            if len(kw) >= self._MIN_KEYWORD_LEN and kw not in self._STOPWORDS
        ]
        # B21: Require at least 1 keyword match, cap at 2 for larger sets.
        # max(2, ...) silenced all rules with < 2 viable keywords.
        self._min_matches = max(1, min(2, len(self.keywords)))

    def __call__(self, event_dict: dict) -> bool:
        if not self.keywords:
            return False
        cmdline = (event_dict.get('CommandLine') or '').lower()
        hits = sum(1 for kw in self.keywords if kw in cmdline)
        return hits >= self._min_matches


def _event_to_dict(ev: "RawEvent") -> dict:
    """Convert RawEvent to a dict suitable for Sigma rule evaluation."""
    return {
        'EventID':           str(ev.event_id),
        'Image':             ev.process_path,
        'ParentImage':       ev.parent_path,
        'CommandLine':       ev.cmdline,
        'ParentCommandLine': '',
        'User':              ev.user,
        'IntegrityLevel':    ev.integrity_level,
        'ProcessGuid':       ev.process_guid,
        'ParentProcessGuid': ev.parent_guid,
        'Hashes':            ev.image_hash,
        'Computer':          ev.host,
    }
