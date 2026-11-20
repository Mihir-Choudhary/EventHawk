"""
Sigma pre-tagging: real Sigma rule matching on Sentinel's process-creation events.

pySigma reads the rules (modifiers such as contains / endswith / all / windash /
base64 are applied by pySigma when it parses them).  This module evaluates the
parsed condition tree itself against the fields Sentinel keeps for each event,
and tags the event with the ATT&CK technique IDs of every rule that matches.

Forensic rules:
  * A rule is applied only to the events it is written for: logsource category
    ``process_creation`` (Sysmon 1, Security 4688).  Other rules are counted as
    not applicable, never run against the wrong events.
  * Sentinel does not keep every field of an event (no ParentCommandLine,
    OriginalFileName, ...).  A test on a field Sentinel lacks is *unknown*, and
    the condition is evaluated in three-valued logic: an event is tagged only
    when the rule is TRUE.  "not <unknown>" stays unknown, so a missing field
    can never make a "not filter" pass and tag an event falsely.
  * Security 4688 carries the creator's account name, not Sysmon's
    DOMAIN\\user, and its integrity level as a SID: there User only proves a
    match (a miss is unknown) and IntegrityLevel/Hashes are unknown.
  * Rules pySigma cannot parse, or that use something this matcher does not
    evaluate (placeholders, query expressions, ...), are skipped and counted
    by reason -- never approximated.

The counts are in ``SigmaTagger.status`` for the caller to show.
"""
from __future__ import annotations

import ipaddress
import logging
import re
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from sentinel.models import RawEvent

logger = logging.getLogger(__name__)

_PROCESS_CREATE_IDS = (1, 4688)
_LEAF_CACHE_MAX = 4096


class SigmaUnavailable(RuntimeError):
    """Sigma rules were asked for but cannot be applied (pySigma missing)."""


class _Unsupported(Exception):
    """The rule uses something this matcher does not evaluate."""


# ── three-valued logic: True / False / None (unknown) ─────────────────────────

def _and(results) -> bool | None:
    unknown = False
    for r in results:
        if r is False:
            return False
        if r is None:
            unknown = True
    return None if unknown else True


def _or(results) -> bool | None:
    unknown = False
    for r in results:
        if r is True:
            return True
        if r is None:
            unknown = True
    return None if unknown else False


# ── the fields Sentinel has, per event ────────────────────────────────────────
# name -> (value, exact).  exact=False: a match proves the rule's test, a miss
# does not (the log holds a different form of the value).

def event_fields(ev: "RawEvent") -> dict[str, tuple[str, bool]]:
    f: dict[str, tuple[str, bool]] = {}
    if ev.host:
        f["Computer"] = (ev.host, True)
    f["EventID"] = (str(ev.event_id), True)
    if ev.event_id == 1:                       # Sysmon: the fields Sigma names
        f.update({
            "Image":             (ev.process_path, True),
            "ParentImage":       (ev.parent_path, True),
            "CommandLine":       (ev.cmdline, True),
            "User":              (ev.user, True),
            "IntegrityLevel":    (ev.integrity_level, True),
            "Hashes":            (ev.image_hash, True),
            "ProcessGuid":       (ev.process_guid, True),
            "ParentProcessGuid": (ev.parent_guid, True),
            "ProcessId":         (str(ev.pid), True),
            "ParentProcessId":   (str(ev.ppid), True),
        })
    elif ev.event_id == 4688:                  # Security: Sigma's field mapping
        for name in ("Image", "NewProcessName"):
            f[name] = (ev.process_path, True)
        for name in ("ParentImage", "ParentProcessName"):
            f[name] = (ev.parent_path, True)
        # Empty when command-line auditing is off: unknown, not "".
        if ev.cmdline:
            f["CommandLine"] = (ev.cmdline, True)
        if ev.user:
            f["SubjectUserName"] = (ev.user, True)
            f["User"] = (ev.user, False)
    return f


def _lookup(fields: dict, name: str):
    if name in fields:
        return fields[name]
    low = name.lower()
    for k, v in fields.items():
        if k.lower() == low:
            return v
    return None


# ── compiling the parsed condition tree into evaluators ───────────────────────

def _string_regex(s, cased: bool, anywhere: bool = False) -> re.Pattern:
    """Whole-value match; anywhere=True for keywords (found in the text)."""
    from sigma.types import SpecialChars
    out = []
    for part in s.s:
        if isinstance(part, str):
            out.append(re.escape(part))
        elif part == SpecialChars.WILDCARD_MULTI:
            out.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            out.append(".")
        else:
            raise _Unsupported("placeholder")
    flags = re.DOTALL if cased else re.DOTALL | re.IGNORECASE
    body = "".join(out)
    return re.compile(".*" + body if anywhere else body + r"\Z", flags)


def _regex_text(rx) -> str:
    orig = getattr(rx.regexp, "original", None)
    if isinstance(orig, str):
        return orig
    from sigma.types import SpecialChars
    parts = []
    for part in rx.regexp.s:
        if isinstance(part, str):
            parts.append(part)
        elif part == SpecialChars.WILDCARD_MULTI:
            parts.append("*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append("?")
        else:
            raise _Unsupported("placeholder")
    return "".join(parts)


def _to_int(text: str) -> int | None:
    t = text.strip()
    try:
        return int(t, 16) if t.lower().startswith("0x") else int(t)
    except ValueError:
        return None


def _value_test(value, anywhere: bool = False) -> Callable[[str, dict], bool]:
    """A test of one field value (str) -> bool; may need the other fields."""
    import sigma.types as T

    if isinstance(value, T.SigmaExpansion):
        tests = [_value_test(v, anywhere) for v in value.values]
        return lambda s, f: any(t(s, f) for t in tests)
    if isinstance(value, T.SigmaString):       # SigmaCasedString included
        rx = _string_regex(value, isinstance(value, T.SigmaCasedString), anywhere)
        return lambda s, f: rx.match(s) is not None
    if isinstance(value, T.SigmaRegularExpression):
        fl = 0
        for flag in value.flags or ():
            fl |= {T.SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
                   T.SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
                   T.SigmaRegularExpressionFlag.DOTALL: re.DOTALL}[flag]
        try:
            rx = re.compile(_regex_text(value), fl)
        except re.error as exc:
            raise _Unsupported(f"regular expression Python cannot compile ({exc})")
        return lambda s, f: rx.search(s) is not None
    if isinstance(value, T.SigmaNumber):
        n = value.number
        return lambda s, f: _to_int(s) == n if _to_int(s) is not None else s.strip().lower() == str(n).lower()
    if isinstance(value, T.SigmaCompareExpression):
        n, op = value.number.number, value.op
        ops = {T.CompareOperators.LT: lambda a: a < n, T.CompareOperators.LTE: lambda a: a <= n,
               T.CompareOperators.GT: lambda a: a > n, T.CompareOperators.GTE: lambda a: a >= n,
               T.CompareOperators.NEQ: lambda a: a != n}
        cmp = ops[op]
        return lambda s, f: (lambda i: i is not None and cmp(i))(_to_int(s))
    if isinstance(value, T.SigmaBool):
        want = "true" if value.boolean else "false"
        return lambda s, f: s.strip().lower() == want
    if isinstance(value, T.SigmaCIDRExpression):
        net = value.network

        def _cidr(s, f):
            try:
                return ipaddress.ip_address(s.strip()) in net
            except ValueError:
                return False
        return _cidr
    raise _Unsupported(type(value).__name__)


def _compile(node) -> Callable[[dict], bool | None]:
    import sigma.conditions as C
    import sigma.types as T

    if isinstance(node, C.ConditionAND):
        kids = [_compile(a) for a in node.args]
        return lambda f: _and(k(f) for k in kids)
    if isinstance(node, C.ConditionOR):
        kids = [_compile(a) for a in node.args]
        return lambda f: _or(k(f) for k in kids)
    if isinstance(node, C.ConditionNOT):
        kid = _compile(node.args[0])

        def _not(f):
            r = kid(f)
            return None if r is None else not r
        return _not

    if isinstance(node, C.ConditionFieldEqualsValueExpression):
        name, value = node.field, node.value
        if isinstance(value, T.SigmaNull):
            def _null(f):
                got = _lookup(f, name)
                if got is None:
                    return None
                return True if got[0] == "" else (False if got[1] else None)
            return _null
        if isinstance(value, T.SigmaExists):
            def _exists(f):
                got = _lookup(f, name)
                if got is None:
                    return None
                return value.exists if got[1] else (True if value.exists else None)
            return _exists
        if isinstance(value, T.SigmaFieldReference):
            other = value.field

            def _ref(f):
                a, b = _lookup(f, name), _lookup(f, other)
                if a is None or b is None:
                    return None
                if a[0].lower() == b[0].lower():
                    return True
                return False if (a[1] and b[1]) else None
            return _ref
        test = _value_test(value)
        cache: dict[str, bool] = {}

        def _field(f):
            got = _lookup(f, name)
            if got is None:
                return None
            s, exact = got
            r = cache.get(s)
            if r is None:
                if len(cache) >= _LEAF_CACHE_MAX:
                    cache.clear()
                r = cache[s] = bool(test(s, f))
            return True if r else (False if exact else None)
        return _field

    if isinstance(node, C.ConditionValueExpression):
        # A keyword: anywhere in the event.  Sentinel keeps only some of the
        # event's fields, so a miss is unknown, never "no match".
        test = _value_test(node.value, anywhere=True)

        def _keyword(f):
            return True if any(test(v, f) for v, _ in f.values() if v) else None
        return _keyword

    raise _Unsupported(type(node).__name__)


# ── a fast necessary condition per rule ───────────────────────────────────────
# _needs(node) -> list of (field, text) alternatives, or None.  The node can be
# TRUE only if at least one text occurs (lower case) in its field's value
# ("*" = any field, for keywords).  Only a TRUE rule tags, so skipping a rule
# whose texts are all absent changes no result; it only saves the evaluation.

def _string_needs(value) -> list[str] | None:
    import sigma.types as T
    if isinstance(value, T.SigmaExpansion):
        alts = [_string_needs(v) for v in value.values]
        return None if any(a is None for a in alts) else [t for a in alts for t in a]
    if isinstance(value, T.SigmaString):
        parts = [p for p in value.s if isinstance(p, str)]
        longest = max(parts, key=len, default="")
        return [longest.lower()] if len(longest) >= 3 else None
    return None


def _needs(node):
    import sigma.conditions as C
    if isinstance(node, C.ConditionAND):
        best = None
        for a in node.args:
            n = _needs(a)
            if n is not None and (best is None or min(map(len, (t for _, t in n)))
                                  > min(map(len, (t for _, t in best)))):
                best = n
        return best
    if isinstance(node, C.ConditionOR):
        alts = [_needs(a) for a in node.args]
        return None if any(a is None for a in alts) else [x for a in alts for x in a]
    if isinstance(node, C.ConditionFieldEqualsValueExpression):
        texts = _string_needs(node.value)
        return None if texts is None else [(node.field, t) for t in texts]
    if isinstance(node, C.ConditionValueExpression):
        texts = _string_needs(node.value)
        return None if texts is None else [("*", t) for t in texts]
    return None                                 # NOT, null, exists, regex, ...


def _candidates(index: dict, fields: dict) -> set[int]:
    """Rules whose needed text occurs: index = {field: [(text, rule_ids), ...]}.

    Python's case-insensitive regex equates some non-ASCII letters with ASCII
    ones (long s, Kelvin sign) that str.lower() does not: a value that is not
    plain ASCII makes every rule on that field a candidate, so this never
    skips a rule the evaluator would match (look-alike letters are an evasion
    trick)."""
    out: set[int] = set()
    for name, entries in index.items():
        if name == "*":
            vals = [v for v, _ in fields.values() if v]
            if any(not v.isascii() for v in vals):
                for _t, ids in entries:
                    out.update(ids)
                continue
            low = "\n".join(v.lower() for v in vals)
        else:
            got = _lookup(fields, name)
            if got is None or not got[0]:
                continue
            low = got[0].lower()
            if not low.isascii():
                for _t, ids in entries:
                    out.update(ids)
                continue
        for text, ids in entries:
            if text in low:
                out.update(ids)
    return out


# ── the tagger ─────────────────────────────────────────────────────────────────

class SigmaTagger:
    """
    Tag process-creation RawEvents with the ATT&CK technique IDs of the Sigma
    rules that match them.  Raises SigmaUnavailable when pySigma is missing:
    rules the analyst chose are never skipped silently.
    """

    def __init__(self, rules_dir: Path) -> None:
        # (title, technique_ids, evaluator, needs-or-None)
        self._rules: list[tuple] = []
        self._mode: str = "none"
        self.status: dict = {
            "rules_dir": str(rules_dir), "rule_files": 0, "rules_read": 0,
            "rules_applied": 0, "skipped": {}, "events_checked": 0,
            "events_tagged": 0,
        }
        self._load_rules(Path(rules_dir))

    def _load_rules(self, rules_dir: Path) -> None:
        try:
            from sigma.collection import SigmaCollection
        except ImportError as exc:
            raise SigmaUnavailable(
                "Sigma rules were selected but cannot be applied: pySigma is not "
                f"installed ({exc}).") from exc

        yml_files = sorted(set(rules_dir.rglob("*.yml")) | set(rules_dir.rglob("*.yaml")))
        skipped: Counter = Counter()
        self.status["rule_files"] = len(yml_files)
        if not yml_files:
            logger.warning("No Sigma rule files found in %s", rules_dir)

        # S4: refuse YAML that is not plain data before pySigma reads it.
        import yaml
        safe_files = []
        for fpath in yml_files:
            try:
                with open(fpath, encoding="utf-8") as fh:
                    list(yaml.safe_load_all(fh))
                safe_files.append(fpath)
            except (yaml.YAMLError, UnicodeDecodeError, OSError) as ye:
                skipped["file not readable as plain YAML"] += 1
                logger.warning("Skipping Sigma file %s: %s", fpath.name, ye)

        rules = []
        for fpath in safe_files:
            try:
                coll = SigmaCollection.load_ruleset([fpath], collect_errors=True)
            except Exception as exc:                       # noqa: BLE001
                skipped["rule pySigma cannot read"] += 1
                logger.warning("Skipping Sigma file %s: %s", fpath.name, exc)
                continue
            if coll.errors and not coll.rules:
                skipped["rule pySigma cannot read"] += 1
                logger.warning("Skipping Sigma file %s: %s", fpath.name, coll.errors[0])
            rules.extend(coll.rules)
        self.status["rules_read"] = len(rules)

        for rule in rules:
            title = rule.title or str(getattr(rule, "id", "") or "untitled")
            if getattr(rule, "errors", None):
                skipped["rule pySigma cannot read"] += 1
                logger.warning("Skipping Sigma rule %r: %s", title, rule.errors[0])
                continue
            ls = rule.logsource
            if (ls.category or "") != "process_creation" or (ls.product or "windows") != "windows":
                skipped["not a Windows process_creation rule"] += 1
                continue
            techniques = sorted({
                str(t).lower().replace("attack.", "", 1).upper()
                for t in (rule.tags or [])
                if str(t).lower().startswith("attack.t")
            })
            if not techniques:
                skipped["no ATT&CK technique tag"] += 1
                continue
            try:
                trees = [c.parsed for c in rule.detection.parsed_condition]
                evals = [_compile(tree) for tree in trees]
                alts = [_needs(tree) for tree in trees]
                needs = None if any(a is None for a in alts) else [x for a in alts for x in a]
            except _Unsupported as exc:
                skipped[f"uses {exc}"] += 1
                logger.info("Sigma rule %r not applied: uses %s", title, exc)
                continue
            except Exception as exc:                       # noqa: BLE001
                skipped["rule pySigma cannot read"] += 1
                logger.warning("Skipping Sigma rule %r: %s", title, exc)
                continue
            ev_fn = evals[0] if len(evals) == 1 else (lambda f, _e=evals: _or(e(f) for e in _e))
            self._rules.append((title, techniques, ev_fn, needs))

        # Rules indexed by the text they need; the rest are always evaluated.
        by: dict[str, dict[str, list[int]]] = {}
        self._always: list[int] = []
        for i, (_t, _tech, _fn, needs) in enumerate(self._rules):
            if needs is None:
                self._always.append(i)
                continue
            for name, text in needs:
                by.setdefault(name, {}).setdefault(text, []).append(i)
        self._index = {name: list(texts.items()) for name, texts in by.items()}

        self.status["rules_applied"] = len(self._rules)
        self.status["skipped"] = dict(skipped)
        self._mode = "sigma"
        logger.info("Sigma: %d of %d rules applied (%d files); skipped: %s",
                    len(self._rules), len(rules), len(yml_files), dict(skipped) or "none")

    def matches(self, ev: "RawEvent") -> list[tuple[str, list[str]]]:
        """(rule title, technique IDs) of every rule that is TRUE for ev."""
        if ev.event_id not in _PROCESS_CREATE_IDS or not self._rules:
            return []
        fields = event_fields(ev)
        cand = _candidates(self._index, fields)
        cand.update(self._always)
        out = []
        for i in sorted(cand):
            title, tech, fn, _needs_ = self._rules[i]
            if fn(fields) is True:
                out.append((title, tech))
        return out

    def tag(self, ev: "RawEvent") -> list[str]:
        """Technique IDs of the matching rules; empty if none match."""
        if ev.event_id in _PROCESS_CREATE_IDS:
            self.status["events_checked"] += 1
        found = self.matches(ev)
        if found:
            self.status["events_tagged"] += 1
        return sorted({t for _title, tech in found for t in tech})

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def mode(self) -> str:
        """'sigma' once rules are loaded, else 'none'."""
        return self._mode

    def summary(self) -> str:
        s = self.status
        skipped = ", ".join(f"{n} {why}" for why, n in sorted(s["skipped"].items())) or "none"
        return (f"Sigma: {s['rules_applied']} of {s['rules_read']} rules applied "
                f"({s['rule_files']} files; skipped: {skipped}); "
                f"{s['events_tagged']} of {s['events_checked']} process-creation events tagged")
