"""
IOC Export Formats — STIX 2.1, MISP event JSON, YARA rule, bulk clipboard.

No external dependencies.  Pure stdlib JSON/string generation.

Public API
----------
export_stix(iocs, filepath)   -> int  (number of STIX objects)
export_misp(iocs, filepath)   -> int  (number of MISP attributes)
export_yara(iocs, filepath)   -> int  (number of YARA strings)
format_bulk_clipboard(iocs)   -> str  ("type:value\\n..." for clipboard)
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

# IOC types to skip in exports
_SKIP = frozenset({"summary", "correlation"})


def _get_value(entry: object) -> str:
    """Safely extract value from an IOCEntry dict or bare string."""
    if isinstance(entry, dict):
        return entry.get("value", "")
    return str(entry)


def _now_iso() -> str:
    """UTC now with millisecond precision: STIX 2.1 requires at least that for
    created / modified (Codex C4-1)."""
    d = datetime.now(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _yara_str(s: str) -> str:
    """A YARA text-string body: backslash, quote, newline, tab and other
    control characters escaped, so a literal never spans lines (Codex C4-3)."""
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append(f"\\x{ord(ch):02x}")
        else:
            out.append(ch)
    return "".join(out)


# ── STIX 2.1 ─────────────────────────────────────────────────────────────────

_STIX_TYPE_MAP = {
    "ipv4":         "ipv4-addr",
    "ipv6":         "ipv6-addr",
    "domains":      "domain-name",
    "urls":         "url",
    "md5":          "file",
    "sha1":         "file",
    "sha256":       "file",
    "processes":    "process",
    "users":        "user-account",
}

_STIX_HASH_KEY = {
    "md5":    "MD5",
    "sha1":   "SHA-1",
    "sha256": "SHA-256",
}


def _stix_lit(value: str) -> str:
    """A STIX pattern string literal body: backslash and quote escaped."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


# Categories with no standard STIX 2.1 object: counted and reported, not dropped silently.
STIX_UNSUPPORTED = ("named_pipes", "services", "tasks", "shares")


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    """Build a STIX 2.1 pattern string for the given IOC type and value."""
    v = _stix_lit(value)
    if ioc_type == "users":
        return f"[user-account:account_login = '{v}']"
    if ioc_type == "filepaths":
        d, sep, name = value.replace("/", "\\").rpartition("\\")
        if sep and d and name:
            return (f"[file:name = '{_stix_lit(name)}' AND "
                    f"file:parent_directory_ref.path = '{_stix_lit(d)}']")
        return f"[file:name = '{v}']"
    if ioc_type == "registry":
        return f"[windows-registry-key:key = '{v}']"
    if ioc_type == "commandlines":
        return f"[process:command_line = '{v}']"
    if ioc_type == "processes":
        return f"[process:image_ref.name = '{v}']"
    if ioc_type == "dlls":
        return f"[file:name = '{v}']"
    if ioc_type == "ipv4":
        return f"[ipv4-addr:value = '{v}']"
    if ioc_type == "ipv6":
        return f"[ipv6-addr:value = '{v}']"
    if ioc_type == "domains":
        return f"[domain-name:value = '{v}']"
    if ioc_type == "urls":
        return f"[url:value = '{v}']"
    hash_key = _STIX_HASH_KEY.get(ioc_type)
    if hash_key:
        return f"[file:hashes.'{hash_key}' = '{v}']"
    return None


def export_stix(iocs: dict, filepath: str, skipped: "dict | None" = None) -> int:
    """
    Export IOCs as a STIX 2.1 bundle (pure stdlib JSON).

    Returns the count of STIX indicator objects written.  *skipped*, when
    given, receives {category: number of values} for categories STIX 2.1 has
    no standard object for (STIX_UNSUPPORTED), so the caller can say so.
    """
    ts      = _now_iso()
    objects = []

    # Create a report object referencing all indicators
    report_id = f"report--{uuid.uuid4()}"
    indicator_ids: list[str] = []

    for ioc_type, entries in iocs.items():
        if ioc_type in _SKIP or not isinstance(entries, list):
            continue
        for entry in entries:
            value = _get_value(entry)
            if not value:
                continue
            pattern = _stix_pattern(ioc_type, value)
            if pattern is None:
                if skipped is not None:
                    skipped[ioc_type] = skipped.get(ioc_type, 0) + 1
                continue

            score = entry.get("score", 0) if isinstance(entry, dict) else 0
            ti    = entry.get("threat_intel") if isinstance(entry, dict) else None
            verdict = (ti or {}).get("verdict", "")
            malicious = verdict in ("malicious", "suspicious")

            ind_id = f"indicator--{uuid.uuid4()}"
            indicator_ids.append(ind_id)

            obj = {
                "type":              "indicator",
                "spec_version":      "2.1",
                "id":                ind_id,
                "created":           ts,
                "modified":          ts,
                "name":              f"{ioc_type}: {value[:60]}",
                "indicator_types":   ["malicious-activity"] if malicious else ["anomalous-activity"],
                "pattern":           pattern,
                "pattern_type":      "stix",
                "valid_from":        ts,
                "confidence":        score,
                "labels":            [ioc_type],
            }
            if ti and ti.get("permalink"):
                obj["external_references"] = [{
                    "source_name": "VirusTotal",
                    "url": ti["permalink"],
                }]

            objects.append(obj)

    # Bundle
    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid.uuid4()}",
        "objects":      objects,
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2, ensure_ascii=False)

    return len(objects)


# ── MISP ──────────────────────────────────────────────────────────────────────

_MISP_ATTR_MAP = {
    "ipv4":         ("Network activity", "ip-dst"),
    "ipv6":         ("Network activity", "ip-dst"),
    "domains":      ("Network activity", "domain"),
    "urls":         ("Network activity", "url"),
    "md5":          ("Payload delivery", "md5"),
    "sha1":         ("Payload delivery", "sha1"),
    "sha256":       ("Payload delivery", "sha256"),
    "processes":    ("Artifacts dropped", "filename"),
    "commandlines": ("External analysis", "text"),
    "registry":     ("Persistence mechanism", "regkey"),
    "filepaths":    ("Artifacts dropped", "filename"),
    "users":        ("Person", "target-user"),
    "services":     ("Persistence mechanism", "windows-service-name"),
    "tasks":        ("Persistence mechanism", "text"),
    "named_pipes":  ("Network activity", "named pipe"),
    "shares":       ("Network activity", "windows-share"),
}


def export_misp(iocs: dict, filepath: str) -> int:
    """
    Export IOCs as a MISP event JSON.

    Returns the count of MISP attributes written.
    """
    ts    = str(int(datetime.now(timezone.utc).timestamp()))   # Unix epoch seconds (Codex C4-2)
    attrs = []
    attr_id = 1

    for ioc_type, entries in iocs.items():
        if ioc_type in _SKIP or not isinstance(entries, list):
            continue
        mapping = _MISP_ATTR_MAP.get(ioc_type)
        if not mapping:
            continue
        category, attr_type = mapping

        for entry in entries:
            value = _get_value(entry)
            if not value:
                continue

            score   = entry.get("score", 0) if isinstance(entry, dict) else 0
            ti      = entry.get("threat_intel") if isinstance(entry, dict) else None
            verdict = (ti or {}).get("verdict", "")
            to_ids  = verdict in ("malicious", "suspicious") or score >= 60

            attrs.append({
                "id":            str(attr_id),
                "uuid":          str(uuid.uuid4()),
                "event_id":      "1",
                "category":      category,
                "type":          attr_type,
                "value":         value,
                "to_ids":        to_ids,
                "timestamp":     ts,
                "comment":       f"score={score}" + (f" [{verdict}]" if verdict else ""),
                "deleted":       False,
                "disable_correlation": False,
            })
            attr_id += 1

    misp_event = {
        "Event": {
            "uuid":         str(uuid.uuid4()),
            "info":         "EventHawk IOC Export",
            "date":         _now_iso()[:10],
            "threat_level_id": "2",
            "analysis":     "1",
            "distribution": "0",
            "Attribute":    attrs,
        }
    }

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(misp_event, fh, indent=2, ensure_ascii=False)

    return len(attrs)


# ── YARA ──────────────────────────────────────────────────────────────────────

def export_yara(iocs: dict, filepath: str) -> int:
    """
    Export a YARA rule skeleton from extracted IOCs.

    Includes:
      - File hash conditions (MD5, SHA1, SHA256)
      - Domain strings
      - URL strings
      - High-scoring process and commandline strings

    Returns the count of YARA string definitions written.
    """
    strings: list[str] = []
    conditions: list[str] = []
    count = 0

    # Hashes → hash conditions using YARA hash module
    hash_conds: list[str] = []
    for ioc_type in ("md5", "sha1", "sha256"):
        entries = iocs.get(ioc_type) or []
        for entry in entries:
            value = _get_value(entry)
            if not value:
                continue
            fn = {"md5": "md5", "sha1": "sha1", "sha256": "sha256"}[ioc_type]
            hash_conds.append(f'        hash.{fn}(0, filesize) == "{value}"')
            count += 1
    if hash_conds:
        conditions.append("        (\n" + " or\n".join(hash_conds) + "\n        )")

    # Domains → string search
    def _family(prefix: str, values) -> None:
        # Reference $prefix_* only when at least one string was written: YARA
        # rejects a set that matches no definition (Codex C4-3).
        nonlocal count
        n = 0
        for i, s in values:
            strings.append(f'        ${prefix}_{i} = "{_yara_str(s)}" nocase wide ascii')
            count += 1
            n += 1
        if n:
            conditions.append(f"        any of (${prefix}_*)")

    domains = iocs.get("domains") or []
    _family("dom", [(i, _get_value(en)) for i, en in enumerate(domains[:100]) if _get_value(en)])

    # URLs → string search (first 100)
    urls = iocs.get("urls") or []
    _family("url", [(i, _get_value(en)) for i, en in enumerate(urls[:100])
                    if _get_value(en) and len(_get_value(en)) <= 200])

    # High-scoring commandlines (score > 50, first 50)
    cmdlines = iocs.get("commandlines") or []
    high_cmds = [e for e in cmdlines
                 if isinstance(e, dict) and e.get("score", 0) > 50][:50]
    # A distinctive 60-character substring of each
    _family("cmd", [(i, _get_value(en)[:60]) for i, en in enumerate(high_cmds) if _get_value(en)])

    # High-scoring processes (score > 60, first 50)
    procs = iocs.get("processes") or []
    high_procs = [e for e in procs
                  if isinstance(e, dict) and e.get("score", 0) > 60][:50]
    _family("proc", [(i, _get_value(en)[:80]) for i, en in enumerate(high_procs) if _get_value(en)])

    # Render rule
    ts        = _now_iso()[:10]
    rule_name = "evtx_ioc_" + re.sub(r'[^a-z0-9]', '_', ts)

    lines: list[str] = [
        f"// Generated by EventHawk on {ts}",
        "// Requires YARA with hash module for hash conditions.",
        "",
        f"import \"hash\"",
        "",
        f"rule {rule_name} {{",
        "    meta:",
        f'        description = "IOC indicators exported from EventHawk"',
        f'        date        = "{ts}"',
        f'        ioc_count   = "{count}"',
    ]

    if strings:
        lines.append("    strings:")
        lines.extend(strings)

    if conditions:
        lines.append("    condition:")
        cond_joined = " or\n".join(conditions)
        lines.append(cond_joined)
    else:
        lines.append("    condition:")
        lines.append("        false  // no high-confidence indicators extracted")

    lines.append("}")

    with open(filepath, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    return count


# ── Bulk clipboard ────────────────────────────────────────────────────────────

_BULK_TYPE_PREFIX = {
    "ipv4":         "ip",
    "ipv6":         "ip",
    "domains":      "domain",
    "urls":         "url",
    "md5":          "md5",
    "sha1":         "sha1",
    "sha256":       "sha256",
    "processes":    "process",
    "commandlines": "cmdline",
    "filepaths":    "path",
    "registry":     "registry",
    "users":        "user",
    "computers":    "computer",
    "named_pipes":  "pipe",
    "services":     "service",
    "tasks":        "task",
    "shares":       "share",
    "dlls":         "dll",
}


def format_bulk_clipboard(iocs: dict) -> str:
    """
    Format all IOC values as 'type:value' lines suitable for pasting into
    detection tools, SIEMs, or scripts.

    Returns a newline-separated string.
    """
    lines: list[str] = []
    for ioc_type, entries in iocs.items():
        if ioc_type in _SKIP or not isinstance(entries, list):
            continue
        prefix = _BULK_TYPE_PREFIX.get(ioc_type, ioc_type)
        for entry in entries:
            value = _get_value(entry)
            if value:
                lines.append(f"{prefix}:{value}")
    return "\n".join(lines)
