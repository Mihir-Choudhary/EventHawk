"""
IOC Suspicion Scorer — assign a 0-100 risk score to each IOC value.

No external dependencies. Pure-Python heuristics only.
Called by analysis_worker_proc after ioc_extractor returns entries.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter

# ── Suspicious process path fragments ─────────────────────────────────────────

_SUSP_PROC_PATHS = (
    "\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\temp",
    "\\users\\public\\",
    "\\programdata\\",
    "\\windows\\temp\\",
    "\\recycler\\",
    "\\$recycle.bin\\",
    "\\desktop\\",
    "\\downloads\\",
    "\\startup\\",
)

# LOLBAS (Living Off The Land Binaries) — flag when run from non-standard paths
_LOLBAS = frozenset({
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe", "bitsadmin.exe",
    "forfiles.exe", "pcalua.exe", "bash.exe", "wmic.exe", "cmstp.exe",
    "installutil.exe", "ieexec.exe", "mavinject.exe", "presentationhost.exe",
    "xwizard.exe", "syncappvpublishingserver.exe", "appsyncpublishingserver.exe",
    "msbuild.exe", "regasm.exe", "regsvcs.exe", "msconfig.exe", "odbcconf.exe",
    "expand.exe", "extrac32.exe", "ftp.exe", "hh.exe", "makecab.exe",
    "netsh.exe", "print.exe", "replace.exe", "rpcping.exe",
    "runscripthelper.exe", "scriptrunner.exe", "sqltoolss.exe", "wab.exe",
})

_LOLBAS_STANDARD_PATHS = (
    "\\system32\\", "\\syswow64\\", "\\sysnative\\",
)

_SCRIPT_EXTS = frozenset({".bat", ".vbs", ".ps1", ".hta", ".js", ".jse", ".vbe", ".wsf", ".wsh"})

# ── Masquerade detection: legitimate process stems (no extension) ──────────────
# Used by _levenshtein() to detect typosquatting of known-good process names.
# e.g. svch0st.exe (edit distance 1 from svchost) → score +60

_LEGIT_PROC_STEMS = frozenset({
    "svchost", "lsass", "csrss", "wininit", "services", "smss", "spoolsv",
    "explorer", "winlogon", "taskmgr", "notepad", "mspaint", "msiexec",
    "regsvr32", "rundll32", "cmd", "powershell", "wscript", "cscript",
    "mshta", "wmic", "certutil", "bitsadmin", "netsh", "sc", "reg",
    "regedit", "taskkill", "tasklist", "ipconfig", "ping", "nslookup",
    "systeminfo", "whoami", "net", "nltest", "klist", "msconfig",
    "dxdiag", "calc", "wordpad", "mmc", "eventvwr", "perfmon", "resmon",
    "msedge", "chrome", "firefox", "iexplore", "outlook", "winword",
    "excel", "powerpnt", "acrord32", "acrobat", "conhost", "dllhost",
    "runtimebroker", "searchindexer", "userinit", "dwm", "fontdrvhost",
})
# Sorted tuple kept for reference; actual masquerade loop uses _LEGIT_BY_LEN below.
_LEGIT_PROC_STEMS_ITER = tuple(sorted(_LEGIT_PROC_STEMS))

# Group stems by length so the masquerade check only iterates stems within ±2
# of the target length — eliminates 80-90% of iterations vs the flat loop.
_LEGIT_BY_LEN: dict[int, tuple] = {}
for _s in _LEGIT_PROC_STEMS:
    _LEGIT_BY_LEN.setdefault(len(_s), []).append(_s)
_LEGIT_BY_LEN = {k: tuple(v) for k, v in _LEGIT_BY_LEN.items()}

# ── Suspicious TLDs (60+) ─────────────────────────────────────────────────────

_SUSP_TLDS = frozenset({
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "pw", "cc", "su",
    "ru", "cn", "ro", "bg", "ua", "kz", "in", "vn", "id", "ph",
    "bd", "pk", "ng", "ke", "gh", "ci", "me", "biz", "mobi", "link",
    "click", "download", "stream", "work", "gdn", "racing", "review",
    "date", "trade", "accountant", "science", "party", "faith", "win",
    "loan", "bid", "men", "webcam", "online", "site", "website", "space",
    "host", "life", "world", "network", "live", "zone", "press", "uno",
    "store", "club", "pro", "fit", "guru", "black", "adult", "xxx", "porn",
    "icu", "cyou", "monster", "hair", "beauty", "quest", "cfd", "lol",
    "bond", "sbs", "bar", "boats", "buzz", "hair", "mov", "zip",
})

# ── Known brand names for typosquatting detection ────────────────────────────

_BRANDS = (
    "microsoft", "google", "amazon", "paypal", "apple", "facebook",
    "twitter", "dropbox", "github", "linkedin", "netflix", "spotify",
    "instagram", "outlook", "onedrive", "sharepoint", "office365",
    "gmail", "yahoo", "adobe", "salesforce", "oracle", "cisco",
)

# ── Known TOR exit node IPs (small curated set) ──────────────────────────────
# Full list would be 7000+ entries; using a small representative set.
# In practice, analysts should use a live feed — this is a static fallback.

_TOR_EXITS = frozenset({
    "51.15.43.205", "51.15.43.204", "51.15.43.203",
    "176.10.104.240", "176.10.104.243", "176.10.107.180",
    "163.172.160.182", "163.172.142.200", "163.172.136.101",
    "109.70.100.18", "109.70.100.30", "109.70.100.34",
    "195.176.3.19", "195.176.3.23", "193.11.114.43",
    "93.115.95.201", "93.115.95.202", "85.248.227.163",
    "185.220.101.0", "185.220.101.1", "185.220.101.2",
    "185.220.101.3", "185.220.101.4", "185.220.101.5",
    "185.220.100.240", "185.220.100.241", "185.220.100.242",
    "89.234.157.254", "46.165.230.5", "46.165.221.166",
    "77.247.181.162", "77.247.181.163", "94.142.242.84",
    "199.249.230.66", "199.249.230.68", "199.249.230.112",
})

# ── Known cloud CDN IP prefixes (short list, for low-score bypass) ────────────

_CLOUD_PREFIXES = (
    "13.", "52.", "54.", "18.", "34.", "35.",     # AWS broad
    "20.", "40.", "104.40.", "137.116.",           # Azure
    "8.34.", "8.35.", "23.236.", "23.251.",        # GCP
    "104.244.",                                     # Twitter CDN
    "157.240.",                                     # Facebook
)

# ── Compiled cmdline patterns ─────────────────────────────────────────────────

_RE_B64_SEGMENT  = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
_RE_PERCENT_ENC  = re.compile(r'%[0-9a-fA-F]{2}')
_RE_CARETS       = re.compile(r'\^')
_RE_NET_USERADD  = re.compile(r'net\s+(user|localgroup)\s+.*\s+/add', re.IGNORECASE)
_RE_SCHTASK      = re.compile(r'schtasks\s*/create', re.IGNORECASE)
_RE_WMIC_PROC    = re.compile(r'wmic\s+(process|path|call)', re.IGNORECASE)
_RE_MSD_DISABLE  = re.compile(r'Set-MpPreference\s+.*Disable\w*Monitor', re.IGNORECASE)
_RE_MSD_EXCL     = re.compile(r'Add-MpPreference\s+.*ExclusionPath', re.IGNORECASE)
_RE_MIMIKATZ     = re.compile(r'(Invoke-Mimikatz|sekurlsa::|lsadump::|kerberos::)', re.IGNORECASE)
_RE_SAM_REG      = re.compile(r'reg\s+(add|save)\s+.*HKLM\\SAM', re.IGNORECASE)
_RE_CERTUTIL_DEC = re.compile(r'certutil\s+.*-(decode|urlcache)', re.IGNORECASE)
_RE_BITS_TRANS   = re.compile(r'bitsadmin\s+/transfer', re.IGNORECASE)
_RE_REGSVR_HTTP  = re.compile(r'regsvr32\s+.*/s\s+.*/u\s+.*/i:https?://', re.IGNORECASE)
_RE_MSHTA_URL    = re.compile(r'mshta\s+(https?|vbscript|javascript):', re.IGNORECASE)
_RE_IEX          = re.compile(r'\bIEX\b|Invoke-Expression', re.IGNORECASE)
_RE_WEBDL        = re.compile(r'DownloadString|DownloadFile|Net\.Http|WebClient|Invoke-WebRequest|wget\b|curl\b', re.IGNORECASE)
_RE_BITS_START   = re.compile(r'Start-BitsTransfer', re.IGNORECASE)

# ── Registry autorun / persistence keys ──────────────────────────────────────

_REG_PERSIST_FRAGMENTS = (
    "\\run\\", "\\runonce\\", "\\runonceex\\",
    "\\appinit_dlls", "\\winlogon\\",
    "\\image file execution options\\",
    "\\bootexecute", "bootexecute",
    "\\browser helper objects\\",
    "\\inprocserver32", "\\localserver32",
)
_REG_SERVICES = "\\system\\currentcontrolset\\services\\"
_REG_BROWSER_EXT = (
    "\\extensions\\", "\\chrome\\extensions",
    "\\firefox\\extensions", "\\edge\\extensions",
)

# ── Private IP ranges ─────────────────────────────────────────────────────────

_RE_PRIVATE_IPv4 = re.compile(
    r'^(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|'
    r'192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+|'
    r'0\.\d+\.\d+\.\d+|224\.\d+\.\d+\.\d+|255\.255\.255\.255)$'
)


# ── Helper: Shannon entropy ───────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s or len(s) < 2:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


# ── Helper: consonant ratio ───────────────────────────────────────────────────

_VOWELS = frozenset("aeiouAEIOU")

def _consonant_ratio(s: str) -> float:
    letters = [c for c in s if c.isalpha()]
    if not letters:
        return 0.0
    consonants = sum(1 for c in letters if c not in _VOWELS)
    return consonants / len(letters)


# ── Levenshtein distance (for masquerade detection) ───────────────────────────

def _levenshtein(a: str, b: str, max_dist: int = 2) -> int:
    """
    Space-optimized iterative Levenshtein distance with early-termination.

    Returns max_dist+1 immediately when the minimum achievable distance in
    any DP row exceeds max_dist, avoiding completing the full table.
    O(min(|a|,|b|)) space via rolling arrays.
    """
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    if a == b:
        return 0
    if len(a) > len(b):        # ensure a is shorter (minimise inner alloc)
        a, b = b, a
    prev = list(range(len(a) + 1))
    for j, cb in enumerate(b, 1):
        curr = [j] + [0] * len(a)
        row_min = j
        for i, ca in enumerate(a, 1):
            cost = 0 if ca == cb else 1
            curr[i] = min(prev[i] + 1, curr[i - 1] + 1, prev[i - 1] + cost)
            if curr[i] < row_min:
                row_min = curr[i]
        if row_min > max_dist:          # early exit: can't improve below threshold
            return max_dist + 1
        prev = curr
    return prev[len(a)]


# ── Scoring functions by type ─────────────────────────────────────────────────

def _score_ip(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    if _RE_PRIVATE_IPv4.match(value):
        return 0, ["Private/internal address"]
    if value in _TOR_EXITS:
        reasons.append("Known TOR exit node")
        return min(100, 85), reasons
    for prefix in _CLOUD_PREFIXES:
        if value.startswith(prefix):
            reasons.append("Cloud/CDN provider range")
            return 5, reasons
    score = 30
    reasons.append("Public IP address")
    return score, reasons


def _score_process(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    vl = value.lower().replace("/", "\\")
    base = os.path.basename(vl)
    stem, ext = os.path.splitext(base)

    # No directory separator → bare filename only
    if "\\" not in vl and "/" not in value:
        score += 15
        reasons.append("No path — possible LOLBin or injected process")

    # Suspicious path fragments
    for frag in _SUSP_PROC_PATHS:
        if frag in vl:
            score += 35
            reasons.append(f"Suspicious path location ({frag.strip(chr(92))})")
            break  # count once even if multiple fragments match

    # Drive root: C:\something.exe (no subdirectory)
    if re.match(r'^[a-z]:\\[^\\]+$', vl):
        score += 30
        reasons.append("Executable at drive root")

    # Double extension
    if re.search(r'\.(pdf|doc|docx|xls|xlsx|txt|jpg|png|zip)\.(exe|bat|ps1|vbs|hta|js)$', vl, re.IGNORECASE):
        score += 50
        reasons.append("Double extension (masquerading)")

    # High-entropy filename (random-looking)
    if _entropy(stem) > 3.8 and len(stem) >= 6:
        score += 30
        reasons.append("High-entropy filename (random/generated)")

    # LOLBAS from non-standard path
    if base in _LOLBAS:
        in_standard = any(sp in vl for sp in _LOLBAS_STANDARD_PATHS)
        if not in_standard and "\\" in vl:
            score += 40
            reasons.append(f"LOLBAS binary ({base}) from non-standard path")

    # Script-like extension as a process
    if ext in _SCRIPT_EXTS:
        score += 25
        reasons.append(f"Script file executed as process ({ext})")

    # ── Masquerade check: stem is within edit distance 1-2 of a legitimate process
    # Skip when stem IS a legitimate process (no false positive on the real thing).
    # Skip stems shorter than 4 chars (too many coincidental matches on short names).
    if stem not in _LEGIT_PROC_STEMS and len(stem) >= 4:
        stem_len = len(stem)
        _found = False
        for _chk_len in range(max(1, stem_len - 2), stem_len + 3):
            for legit in _LEGIT_BY_LEN.get(_chk_len, ()):
                dist = _levenshtein(stem, legit, max_dist=2)
                if dist in (1, 2):
                    score += 60
                    reasons.append(
                        f"Possible name masquerading of '{legit}.exe' "
                        f"(edit distance: {dist})"
                    )
                    _found = True
                    break
            if _found:
                break

    return min(100, score), reasons


def _score_domain(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    vl = value.lower()
    parts = vl.rstrip(".").split(".")

    tld = parts[-1] if parts else ""
    second_level = parts[-2] if len(parts) >= 2 else ""

    # Suspicious TLD
    if tld in _SUSP_TLDS:
        score += 30
        reasons.append(f"Suspicious TLD (.{tld})")

    # Punycode (IDN)
    if any(p.startswith("xn--") for p in parts):
        score += 35
        reasons.append("IDN/punycode domain (potential homograph attack)")

    # DGA heuristic: consonant ratio
    cr = _consonant_ratio(second_level)
    if cr > 0.72 and len(second_level) >= 6:
        score += 50
        reasons.append(f"DGA-like domain (consonant ratio {cr:.2f})")

    # Long label
    if second_level and len(second_level) > 22:
        score += 20
        reasons.append("Unusually long second-level domain label")

    # High digit ratio
    if second_level:
        digit_ratio = sum(1 for c in second_level if c.isdigit()) / len(second_level)
        if digit_ratio > 0.4:
            score += 20
            reasons.append("High digit ratio in domain label")

    # Deep subdomain (many levels)
    if len(parts) > 5:
        score += 15
        reasons.append(f"Deep subdomain ({len(parts)} levels)")

    # Typosquatting: check edit distance to known brands
    if second_level and len(second_level) >= 5:
        for brand in _BRANDS:
            dist = _levenshtein(second_level, brand, max_dist=2)
            if 0 < dist <= 2:
                score += 40
                reasons.append(f"Possible typosquatting of '{brand}' (edit distance {dist})")
                break

    return min(100, score), reasons


def _score_cmdline(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    vl = value  # keep original case for case-sensitive patterns

    if _RE_B64_SEGMENT.search(vl):
        score += 55
        reasons.append("Base64-encoded segment detected")

    if re.search(r'(-enc|-EncodedCommand)', vl, re.IGNORECASE):
        score += 50
        reasons.append("Encoded command flag (-enc / -EncodedCommand)")

    if re.search(r'(-w\s+hidden|-windowstyle\s+hidden)', vl, re.IGNORECASE):
        score += 35
        reasons.append("Hidden window style flag")

    if re.search(r'(-nop|-NoProfile)', vl, re.IGNORECASE):
        score += 20
        reasons.append("NoProfile flag (-nop / -NoProfile)")

    if re.search(r'-NonInteractive', vl, re.IGNORECASE):
        score += 15
        reasons.append("NonInteractive flag (-NonInteractive)")

    if _RE_IEX.search(vl):
        score += 45
        reasons.append("Invoke-Expression / IEX detected")

    if _RE_WEBDL.search(vl):
        score += 40
        reasons.append("Web download method detected")

    if _RE_CERTUTIL_DEC.search(vl):
        score += 45
        reasons.append("Certutil decode / urlcache abuse")

    if _RE_BITS_TRANS.search(vl):
        score += 40
        reasons.append("BITSAdmin transfer (possible download)")

    if _RE_REGSVR_HTTP.search(vl):
        score += 45
        reasons.append("Regsvr32 remote script execution (Squiblydoo)")

    if _RE_MSHTA_URL.search(vl):
        score += 50
        reasons.append("MSHTA loading remote/inline script")

    if len(_RE_CARETS.findall(vl)) >= 5:
        score += 30
        reasons.append("Caret obfuscation (5+ ^ chars)")

    if len(_RE_PERCENT_ENC.findall(vl)) >= 4:
        score += 25
        reasons.append("Percent-encoded characters (obfuscation)")

    if _RE_NET_USERADD.search(vl):
        score += 60
        reasons.append("Net user/localgroup add (account manipulation)")

    if _RE_SCHTASK.search(vl):
        score += 35
        reasons.append("Scheduled task creation")

    if _RE_WMIC_PROC.search(vl):
        score += 30
        reasons.append("WMIC process execution")

    if _RE_MSD_EXCL.search(vl):
        score += 60
        reasons.append("Windows Defender exclusion path added")

    if _RE_MSD_DISABLE.search(vl):
        score += 65
        reasons.append("Windows Defender real-time protection disabled")

    if _RE_BITS_START.search(vl):
        score += 35
        reasons.append("Start-BitsTransfer (background download)")

    if _RE_MIMIKATZ.search(vl):
        score += 80
        reasons.append("Mimikatz / credential dumping indicators")

    if _RE_SAM_REG.search(vl):
        score += 70
        reasons.append("Registry SAM hive access (credential theft)")

    if re.search(r'(runas|Start-Process)\s+.*-Credential', vl, re.IGNORECASE):
        score += 35
        reasons.append("Process started with alternate credentials")

    if re.search(r'(net\s+use|mount|New-PSDrive)\s+\\\\', vl, re.IGNORECASE):
        score += 25
        reasons.append("Remote share mount")

    if re.search(r'(sc\s+(create|config|start)|New-Service)', vl, re.IGNORECASE):
        score += 40
        reasons.append("Service creation/modification")

    if re.search(r'(vssadmin|wbadmin|bcdedit|fsutil)\s+.*(delete|disable|set)', vl, re.IGNORECASE):
        score += 65
        reasons.append("Shadow copy / backup deletion (possible ransomware)")

    if len(vl) > 500:
        score += 15
        reasons.append("Unusually long command line (> 500 chars)")

    return min(100, score), reasons


def _score_registry(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    vl = value.lower()

    for frag in _REG_PERSIST_FRAGMENTS:
        if frag in vl:
            if "appinit" in frag:
                score += 60
                reasons.append("AppInit_DLLs persistence key")
            elif "bootexecute" in frag:
                score += 65
                reasons.append("BootExecute persistence key")
            elif "image file execution" in frag:
                score += 55
                reasons.append("Image File Execution Options (debugger hijack)")
            elif "winlogon" in frag:
                score += 50
                reasons.append("Winlogon key (persistence / credential access)")
            elif "run" in frag:
                score += 40
                reasons.append("Autorun key (persistence)")
            else:
                score += 30
                reasons.append(f"Suspicious registry key ({frag.strip(chr(92))})")
            break

    if _REG_SERVICES in vl:
        score += 25
        reasons.append("Services key (possible service persistence)")

    for frag in _REG_BROWSER_EXT:
        if frag in vl:
            score += 25
            reasons.append("Browser extension registry key")
            break

    if "\\clsid\\" in vl or "inprocserver" in vl or "localserver" in vl:
        score += 30
        reasons.append("COM server registration (possible hijack)")

    return min(100, score), reasons


def _score_url(value: str) -> tuple[int, list[str]]:
    reasons: list[str] = []
    score = 0
    vl = value.lower()

    # IP address used instead of domain
    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', vl):
        score += 40
        reasons.append("IP address used in URL instead of domain")

    # Non-standard port
    port_m = re.search(r'https?://[^/:]+:(\d+)', vl)
    if port_m:
        port = int(port_m.group(1))
        if port not in (80, 443, 8080, 8443, 8000, 8888, 3000):
            score += 25
            reasons.append(f"Non-standard port ({port})")

    if vl.startswith("http://") and not any(
        priv in vl for priv in ("127.0.0.1", "localhost", "192.168.", "10.", "172.")
    ):
        score += 20
        reasons.append("Plain HTTP (unencrypted) connection")

    if "/temp/" in vl or "/tmp/" in vl:
        score += 25
        reasons.append("Temp/tmp path in URL")

    if re.search(r'\.(exe|dll|ps1|bat|vbs|hta|msi|cmd|scr|cpl|jar|war)(\?|$)', vl):
        score += 40
        reasons.append("Executable/script download via URL")

    if len(_RE_PERCENT_ENC.findall(value)) >= 4:
        score += 25
        reasons.append("URL contains percent-encoded characters")

    if len(value) > 300:
        score += 15
        reasons.append("Unusually long URL")

    return min(100, score), reasons


def _score_hash(_value: str) -> tuple[int, list[str]]:
    # Hashes are scored 0 by default — threat intel enrichment overrides to 95
    return 0, ["Hash — use Threat Intel to check reputation"]


# ── Public API ────────────────────────────────────────────────────────────────

_SCORERS = {
    "ipv4":         _score_ip,
    "ipv6":         _score_ip,
    "processes":    _score_process,
    "filepaths":    _score_process,      # reuse — same path heuristics
    "dlls":         _score_process,
    "services":     _score_process,
    "domains":      _score_domain,
    "commandlines": _score_cmdline,
    "registry":     _score_registry,
    "urls":         _score_url,
    "md5":          _score_hash,
    "sha1":         _score_hash,
    "sha256":       _score_hash,
    "users":        lambda v: (0, []),
    "computers":    lambda v: (0, []),
    "named_pipes":  lambda v: (10, ["Named pipe — review for lateral movement"]),
    "tasks":        lambda v: (20, ["Scheduled task — common persistence mechanism"]),
    "shares":       lambda v: (15, ["Network share access"]),
}


def score_ioc(ioc_type: str, value: str) -> tuple[int, list[str]]:
    """
    Score a single IOC value.

    Parameters
    ----------
    ioc_type : str
        One of the IOC type keys (ipv4, domains, commandlines, etc.)
    value : str
        The IOC value string.

    Returns
    -------
    (score, reasons)
        score   : int, 0-100
        reasons : list[str] of human-readable scoring reasons
    """
    fn = _SCORERS.get(ioc_type)
    if fn is None:
        return 0, []
    try:
        return fn(value)
    except Exception:
        return 0, []
