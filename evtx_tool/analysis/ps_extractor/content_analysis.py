"""
PowerShell forensic extraction — content analysis.

Detects safety-net keyword patterns, secondary indicators (obfuscation,
high entropy), and maps findings to MITRE ATT&CK technique IDs.
"""

from __future__ import annotations

import re

from .constants import ATT_CK_MAP, SAFETY_NET_PATTERNS
from .models import ContentAnalysisResult

# Pre-lowercased patterns for fast substring matching (avoids per-call .lower())
_PATTERNS_LOWER: list[str] = [p.lower() for p in SAFETY_NET_PATTERNS]

# High-entropy string detection: base64-like runs ≥60 chars
_HIGH_ENTROPY_RE = re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')

# Obfuscation: -join with array/call
_JOIN_OBFUSC_RE = re.compile(r'-join\s*[\[\(]', re.IGNORECASE)

# Obfuscation: backtick-based splitting/concatenation (not normal line continuation)
# Matches patterns like: "`I"+"`EX" or "In`vo`ke" (mid-word tick insertion)
_TICK_SPLIT_RE = re.compile(r'`[A-Za-z].*`[A-Za-z]')
# Char concatenation: [char]0x48+[char]0x65 or [char]72+[char]101
_CHAR_CONCAT_RE = re.compile(
    r'\[char\]\s*(?:0x[0-9a-f]+|\d+)\s*\+\s*\[char\]',
    re.IGNORECASE,
)


def detect_safety_net_patterns(text: str) -> list[str]:
    """
    Return list of safety-net patterns matched in text.
    Case-insensitive substring search — fast C-level str.__contains__.
    """
    lower = text.lower()
    return [SAFETY_NET_PATTERNS[i] for i, p in enumerate(_PATTERNS_LOWER) if p in lower]


def analyze_script_block(text: str) -> ContentAnalysisResult:
    """
    Run all detection categories against assembled script block text.
    Always tags T1059.001 (PowerShell execution) in att_ck_techniques.
    """
    lower = text.lower()
    patterns = detect_safety_net_patterns(text)

    def _any(*terms: str) -> bool:
        return any(t in lower for t in terms)

    has_encoded = _any(
        "-encodedcommand", "frombase64string", "tobase64string", "base64",
    )
    has_download = _any(
        "downloadstring", "downloadfile", "net.webclient", "invoke-webrequest",
        "bitstransfer", "start-bitstransfer", "net.http",
    )
    has_amsi = _any(
        "amsiscanbuffer", "amsi.dll", "amsiinitfailed",
        "amsiutils", "amsiinitialize",
    )
    has_reflect = _any(
        "reflection.assembly", "assembly.load", "[system.reflection",
        "assembly.loadfrom",
    )
    has_inject = _any(
        "virtualalloc", "writeprocessmemory", "createthread",
        "ntwritevirtualmemory", "ntalloc",
    )
    has_cred = _any(
        "sekurlsa", "mimikatz", "privilege::debug", "pscredential",
        "lsadump", "lsagetlogonsessiondata",
    )
    has_com = _any(
        "new-object -comobject", "new-object -com",
        "createobject(", "activator.createinstance",
    )
    has_wmi = _any(
        "get-wmiobject", "get-ciminstance", "win32_process", "wmic ",
        "system.management.managementobject",
    )
    has_persist = _any(
        "register-scheduledtask", "new-scheduledtask", "schtasks",
        "new-itemproperty", "set-itemproperty", "hklm:", "hkcu:",
    )
    has_lateral = _any(
        "invoke-command", "new-pssession", "enter-pssession",
    )

    # Obfuscation: [char] casting, char(), -join array chains,
    # or high-density backtick escape (mid-word insertion, not normal line continuation)
    has_obfusc = (
        "[char]" in lower
        or "char(" in lower
        or bool(_JOIN_OBFUSC_RE.search(lower))
        or bool(_TICK_SPLIT_RE.search(text))
        or bool(_CHAR_CONCAT_RE.search(lower))
    )

    # High entropy: long base64-like strings
    has_high_entropy = bool(_HIGH_ENTROPY_RE.search(text))

    result = ContentAnalysisResult(
        has_encoded_commands=has_encoded,
        has_download_cradle=has_download,
        has_amsi_bypass=has_amsi,
        has_reflection=has_reflect,
        has_process_injection=has_inject,
        has_credential_access=has_cred,
        has_com_objects=has_com,
        has_wmi_abuse=has_wmi,
        has_persistence_mechanism=has_persist,
        has_lateral_movement=has_lateral,
        has_obfuscation=has_obfusc,
        has_high_entropy_strings=has_high_entropy,
        detected_patterns=patterns,
        att_ck_techniques=[],
    )

    techs: list[str] = []
    for flag, tid in ATT_CK_MAP.items():
        if getattr(result, flag, False):
            techs.append(tid)
    # Always tag PowerShell execution
    if "T1059.001" not in techs:
        techs.insert(0, "T1059.001")
    result.att_ck_techniques = sorted(set(techs))
    return result
