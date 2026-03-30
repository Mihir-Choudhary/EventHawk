"""
Context-aware ATT&CK enrichment rules.

Three layers applied on top of the static ATTACK_MAP:

1. Shannon entropy  — flags obfuscated / Base64 CommandLine strings → T1027
2. Process lineage  — parent→child analysis:
     a) suppress generic Execution tags for known-benign system pairs
     b) add high-confidence tags for malicious parent→child combinations
3. Confidence score — adds ``attack_confidence: "low"|"medium"|"high"`` to
   every tag dict so analysts can prioritise

Public API
----------
apply_context_rules(ev: dict) -> None
    Mutates ev["attack_tags"] in-place.  Called from enrich_and_summarize().
"""

from __future__ import annotations

import math
import os
from collections import Counter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _basename(path: str) -> str:
    """Return the lowercase filename component of a Windows/POSIX path."""
    if not path:
        return ""
    return os.path.basename(path.replace("\\", os.sep)).lower()


def shannon_entropy(s: str) -> float:
    """
    Shannon entropy (bits per character) of *s*.

    Calibrated thresholds for Windows command-line strings
    (narrower character set than arbitrary file bytes):

      < 3.8   normal       plain admin commands, short paths
      3.8-5.0 elevated     GUIDs, long arg lists, caret obfuscation
      5.0-5.75 high        random variable names, partial Base64
      >= 5.75 critical     full Base64 / encrypted payloads

    Returns 0.0 for strings shorter than 2 characters.
    """
    if not s or len(s) < 2:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ---------------------------------------------------------------------------
# Suppression table — known-benign parent→child pairs
# When matched on EID 4688 / Sysmon 1, generic Execution (T1059) tags
# from the static map are dropped.  These are definitively system noise.
# ---------------------------------------------------------------------------

_SUPPRESS_PAIRS: frozenset[tuple[str, str]] = frozenset({
    # Windows boot sequence
    ("smss.exe",              "csrss.exe"),
    ("smss.exe",              "winlogon.exe"),
    ("smss.exe",              "wininit.exe"),
    ("wininit.exe",           "services.exe"),
    ("wininit.exe",           "lsass.exe"),
    ("winlogon.exe",          "userinit.exe"),
    ("winlogon.exe",          "dwm.exe"),
    # Service Control Manager children
    ("services.exe",          "svchost.exe"),
    ("services.exe",          "msiexec.exe"),
    ("services.exe",          "spoolsv.exe"),
    ("services.exe",          "lsm.exe"),
    # svchost normal children
    ("svchost.exe",           "dllhost.exe"),
    ("svchost.exe",           "conhost.exe"),
    ("svchost.exe",           "wermgr.exe"),
    ("svchost.exe",           "wsqmcons.exe"),
    ("svchost.exe",           "mssense.exe"),
    ("svchost.exe",           "tiworker.exe"),
    ("svchost.exe",           "wuauclt.exe"),
    ("svchost.exe",           "taskeng.exe"),
    ("svchost.exe",           "wmiprvse.exe"),
    # Windows Defender
    ("msmpeng.exe",           "mpcmdrun.exe"),
    ("msmpeng.exe",           "nissrv.exe"),
    ("mssense.exe",           "msmpeng.exe"),
    # Windows Update / TrustedInstaller
    ("trustedinstaller.exe",  "tiworker.exe"),
    ("tiworker.exe",          "dism.exe"),
    # Shell / Explorer
    ("userinit.exe",          "explorer.exe"),
    ("explorer.exe",          "conhost.exe"),
    # Task Scheduler
    ("taskeng.exe",           "svchost.exe"),
    # SCCM / ConfigMgr agent
    ("ccmexec.exe",           "cscript.exe"),
    ("ccmexec.exe",           "msiexec.exe"),
    ("ccmexec.exe",           "powershell.exe"),
    ("ccmexec.exe",           "conhost.exe"),
    # System idle / registry
    ("registry",              "smss.exe"),
})


# ---------------------------------------------------------------------------
# Lineage rules — high-confidence malicious parent→child combinations
# Each rule adds tags (with confidence pre-set) when both parent and child
# match.  Rules are evaluated in order; all matching rules are applied.
# ---------------------------------------------------------------------------

_LINEAGE_RULES: list[dict] = [
    # Office apps spawning shell/script interpreters → Phishing / Macro
    {
        "parents": {
            "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
            "onenote.exe", "msaccess.exe", "visio.exe", "mspub.exe",
        },
        "children": {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
            "bitsadmin.exe", "curl.exe", "wget.exe", "wmic.exe",
        },
        "tags": [{
            "tactic": "Initial Access",
            "tid":    "T1566",
            "name":   "Phishing: Malicious File (Office→Shell)",
        }],
        "confidence": "high",
    },
    # Web server processes spawning shells → Web Shell
    {
        "parents": {
            "w3wp.exe", "httpd.exe", "nginx.exe", "php-cgi.exe",
            "tomcat.exe", "tomcat9.exe", "java.exe",
        },
        "children": {
            "powershell.exe", "cmd.exe", "whoami.exe", "net.exe", "net1.exe",
            "ipconfig.exe", "systeminfo.exe", "certutil.exe", "wscript.exe",
        },
        "tags": [{
            "tactic": "Persistence",
            "tid":    "T1505.003",
            "name":   "Server Software Component: Web Shell",
        }],
        "confidence": "high",
    },
    # Database engines spawning shells → DB compromise / Server Software Component
    {
        "parents": {
            "sqlservr.exe", "mysqld.exe", "mysqld-nt.exe",
            "oracle.exe", "postgres.exe", "mongod.exe",
        },
        "children": {
            "powershell.exe", "cmd.exe", "whoami.exe",
            "net.exe", "net1.exe", "certutil.exe",
        },
        "tags": [{
            "tactic": "Execution",
            "tid":    "T1059",
            "name":   "Command and Scripting Interpreter (DB Server Spawn)",
        }],
        "confidence": "high",
    },
    # WMI provider host spawning shells → WMI execution / lateral movement
    {
        "parents": {"wmiprvse.exe", "wmiapsrv.exe"},
        "children": {
            "powershell.exe", "cmd.exe", "mshta.exe",
            "wscript.exe", "cscript.exe",
        },
        "tags": [{
            "tactic": "Execution",
            "tid":    "T1047",
            "name":   "Windows Management Instrumentation",
        }],
        "confidence": "high",
    },
    # mshta spawning interpreters → LOLBin proxy execution
    {
        "parents": {"mshta.exe"},
        "children": {
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "regsvr32.exe", "rundll32.exe",
        },
        "tags": [{
            "tactic": "Defense Evasion",
            "tid":    "T1218.005",
            "name":   "System Binary Proxy Execution: Mshta",
        }],
        "confidence": "high",
    },
    # Shell → certutil (download cradle)
    {
        "parents": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
        "children": {"certutil.exe"},
        "tags": [{
            "tactic": "Command and Control",
            "tid":    "T1105",
            "name":   "Ingress Tool Transfer (certutil download cradle)",
        }],
        "confidence": "medium",
    },
    # Shell → regsvr32 (LOLBin)
    {
        "parents": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
        "children": {"regsvr32.exe"},
        "tags": [{
            "tactic": "Defense Evasion",
            "tid":    "T1218.010",
            "name":   "System Binary Proxy Execution: Regsvr32",
        }],
        "confidence": "medium",
    },
    # Shell → rundll32 (LOLBin)
    {
        "parents": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
        "children": {"rundll32.exe"},
        "tags": [{
            "tactic": "Defense Evasion",
            "tid":    "T1218.011",
            "name":   "System Binary Proxy Execution: Rundll32",
        }],
        "confidence": "medium",
    },
    # Shell → mshta (LOLBin)
    {
        "parents": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
        "children": {"mshta.exe"},
        "tags": [{
            "tactic": "Defense Evasion",
            "tid":    "T1218.005",
            "name":   "System Binary Proxy Execution: Mshta",
        }],
        "confidence": "medium",
    },
    # Shell → bitsadmin (download LOLBin)
    {
        "parents": {"powershell.exe", "cmd.exe"},
        "children": {"bitsadmin.exe"},
        "tags": [{
            "tactic": "Command and Control",
            "tid":    "T1197",
            "name":   "BITS Jobs (bitsadmin download cradle)",
        }],
        "confidence": "medium",
    },
    # Shell → wmic (LOLBin lateral movement / execution)
    {
        "parents": {"powershell.exe", "cmd.exe"},
        "children": {"wmic.exe"},
        "tags": [{
            "tactic": "Execution",
            "tid":    "T1047",
            "name":   "Windows Management Instrumentation (wmic LOLBin)",
        }],
        "confidence": "medium",
    },
]


# ---------------------------------------------------------------------------
# High-noise event IDs
# Events where the static-map hit alone is very low signal.
# These get confidence="low" unless a lineage or entropy rule upgrades them.
# ---------------------------------------------------------------------------

_HIGH_NOISE_EIDS: frozenset[int] = frozenset({
    4624,   # Valid Accounts — fires on every single successful logon
    4672,   # Special Privileges — fires on every privileged logon
    4663,   # File and Directory Discovery — extremely chatty
    4656,   # Object access requests — chatty
    5140,   # Network share access — too common for file servers
    7036,   # Service state change — constant background noise
})


# ---------------------------------------------------------------------------
# Process-create event IDs (Security + Sysmon)
# Only these events carry CommandLine / Image / ParentImage fields.
# ---------------------------------------------------------------------------

_PROC_CREATE_EIDS: frozenset[int] = frozenset({4688, 1})


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def apply_context_rules(ev: dict) -> None:
    """
    Context-aware enrichment applied after the static ATTACK_MAP lookup.

    Mutates ev["attack_tags"] in-place:
      - May remove noisy Execution tags for benign parent→child pairs
      - May add high-confidence tags from lineage rules
      - May add T1027 tag when CommandLine entropy is high
      - Adds ``attack_confidence`` key to every tag

    Safe to call on any event dict, including those with no attack_tags.
    """
    ed  = ev.get("event_data") or {}
    eid = ev.get("event_id", 0)
    provider = (ev.get("provider") or "").lower()
    is_sysmon = "sysmon" in provider

    # ── Extract process fields ────────────────────────────────────────────
    # Each .get() tries the canonical capitalisation first, then lowercase
    # fallback — matches what sigma_rules._get_field() does so both layers
    # handle normalised event_data dicts consistently.
    if is_sysmon:
        image        = ed.get("Image")        or ed.get("image")        or ""
        parent_image = ed.get("ParentImage")  or ed.get("parentimage")  or ""
        cmd          = ed.get("CommandLine")  or ed.get("commandline")  or ""
    else:
        image        = (ed.get("NewProcessName")    or ed.get("newprocessname")    or "")
        parent_image = (ed.get("ParentProcessName") or ed.get("parentprocessname") or "")
        cmd          = (ed.get("CommandLine")       or ed.get("commandline")
                        or ed.get("ProcessCommandLine") or ed.get("processcmdline") or "")

    child_name  = _basename(image)
    parent_name = _basename(parent_image)

    tags: list[dict] = list(ev.get("attack_tags") or [])

    # ── Step 1: Suppress benign parent→child noise ───────────────────────
    # Only suppress Execution-tactic tags (T1059 etc.) — leave others intact
    if eid in _PROC_CREATE_EIDS and parent_name and child_name:
        if (parent_name, child_name) in _SUPPRESS_PAIRS:
            tags = [t for t in tags if t.get("tactic") != "Execution"]

    # ── Step 2: Apply lineage rules (add high-confidence tags) ───────────
    if eid in _PROC_CREATE_EIDS and parent_name and child_name:
        for rule in _LINEAGE_RULES:
            if parent_name in rule["parents"] and child_name in rule["children"]:
                for base_tag in rule["tags"]:
                    new_tag = dict(base_tag)
                    new_tag["attack_confidence"] = rule["confidence"]
                    tags.append(new_tag)

    # ── Step 3: Shannon entropy on CommandLine ───────────────────────────
    if eid in _PROC_CREATE_EIDS and cmd and len(cmd) >= 20:
        h = shannon_entropy(cmd)
        if h >= 5.0:
            conf = "high" if h >= 5.75 else "medium"
            tags.append({
                "tactic":            "Defense Evasion",
                "tid":               "T1027",
                "name":              f"Obfuscated Files or Information (entropy {h:.2f})",
                "attack_confidence": conf,
            })

    # ── Step 4: Assign confidence to all tags that don't have it yet ─────
    default_conf = "low" if eid in _HIGH_NOISE_EIDS else "medium"
    for tag in tags:
        if "attack_confidence" not in tag:
            tag["attack_confidence"] = default_conf

    ev["attack_tags"] = tags
