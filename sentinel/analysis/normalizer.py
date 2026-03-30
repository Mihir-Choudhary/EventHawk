"""
Normalization engine for process names and command lines.

Operations run in this fixed order:
  1. GUID/UUID masking
  2. User path abstraction
  3. Version string masking
  4. Per-token Shannon entropy masking
  5. Base64 block masking
  6. Lowercase

Normalization is applied AFTER Sigma pre-tagging so Sigma sees the raw payload.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from pathlib import PurePath

# ── Compiled patterns ──────────────────────────────────────────────────────────
_GUID_RE = re.compile(
    r'\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
    r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?'
)
_USER_PATH_RE = re.compile(
    r'[A-Za-z]:\\[Uu]sers\\[^\\]+\\',
    re.IGNORECASE,
)
_VERSION_RE = re.compile(r'\b\d+\.\d+(?:\.\d+){0,3}\b')
_BASE64_RE = re.compile(
    r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?'
)
_HEX_RE = re.compile(r'^[0-9a-fA-F]+$')
# B28: IP addresses — mask separately before version strings to preserve network indicators
_IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')

# Per-token entropy threshold (bits per character).
# 4.8 catches obfuscated args and encoded blobs without false-positiving on
# short random IDs (caught by GUID pattern first) or hex color codes.
_ENTROPY_THRESHOLD: float = 4.8


def _token_entropy(s: str) -> float:
    """Shannon entropy in bits per character for string s."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_hex(s: str) -> bool:
    return bool(_HEX_RE.match(s)) and len(s) >= 8


def normalize_cmdline(cmdline: str) -> str:
    """
    Normalize a raw command line string to a stable template.
    Returns an all-lowercase masked string.
    """
    s = cmdline.strip()

    # 1. GUID/UUID masking
    s = _GUID_RE.sub('{GUID}', s)

    # 2. User path abstraction
    s = _USER_PATH_RE.sub(r'{USERPATH}\\', s)

    # 2.5. B28: IP address masking (before version masking to prevent loss)
    s = _IP_RE.sub('{IP}', s)

    # 3. Version string masking
    s = _VERSION_RE.sub('{VER}', s)

    # 4. Per-token entropy masking
    tokens = s.split()
    masked: list[str] = []
    for tok in tokens:
        if _token_entropy(tok) > _ENTROPY_THRESHOLD and len(tok) >= 8:
            masked.append('{HEX}' if _looks_hex(tok) else '{ENC}')
        else:
            masked.append(tok)
    s = ' '.join(masked)

    # 5. Base64 block masking (runs after per-token so multi-token B64 is caught)
    s = _BASE64_RE.sub('{B64}', s)

    # 6. Lowercase
    return s.lower()


def normalize_procname(name: str) -> str:
    """
    Normalize a process name: lowercase executable filename, strip directory path.
    Handles both Windows backslash paths and bare names.
    """
    if not name:
        return ''
    return PurePath(name).name.lower()
