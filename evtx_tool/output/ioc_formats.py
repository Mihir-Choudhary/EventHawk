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
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def _stix_pattern(ioc_type: str, value: str) -> str | None:
    """Build a STIX 2.1 pattern string for the given IOC type and value."""
    v = value.replace("'", "\\'")
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


def export_stix(iocs: dict, filepath: str) -> int:
    """
    Export IOCs as a STIX 2.1 bundle (pure stdlib JSON).

    Returns the count of STIX indicator objects written.
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
    ts    = _now_iso()
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
    domains = iocs.get("domains") or []
    for i, entry in enumerate(domains[:100]):
        value = _get_value(entry)
        if not value:
            continue
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f'        $dom_{i} = "{escaped}" nocase wide ascii')
        count += 1
    if domains:
        conditions.append("        any of ($dom_*)")

    # URLs → string search (first 100)
    urls = iocs.get("urls") or []
    for i, entry in enumerate(urls[:100]):
        value = _get_value(entry)
        if not value or len(value) > 200:
            continue
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f'        $url_{i} = "{escaped}" nocase wide ascii')
        count += 1
    if urls:
        conditions.append("        any of ($url_*)")

    # High-scoring commandlines (score > 50, first 50)
    cmdlines = iocs.get("commandlines") or []
    high_cmds = [e for e in cmdlines
                 if isinstance(e, dict) and e.get("score", 0) > 50][:50]
    for i, entry in enumerate(high_cmds):
        value = _get_value(entry)
        if not value:
            continue
        # Take a distinctive 60-char substring
        snippet = value[:60].replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f'        $cmd_{i} = "{snippet}" nocase wide ascii')
        count += 1
    if high_cmds:
        conditions.append("        any of ($cmd_*)")

    # High-scoring processes (score > 60, first 50)
    procs = iocs.get("processes") or []
    high_procs = [e for e in procs
                  if isinstance(e, dict) and e.get("score", 0) > 60][:50]
    for i, entry in enumerate(high_procs):
        value = _get_value(entry)
        if not value:
            continue
        snippet = value[:80].replace("\\", "\\\\").replace('"', '\\"')
        strings.append(f'        $proc_{i} = "{snippet}" nocase wide ascii')
        count += 1
    if high_procs:
        conditions.append("        any of ($proc_*)")

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
