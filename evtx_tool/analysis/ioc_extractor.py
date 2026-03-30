"""
IOC Extractor — extract Indicators of Compromise from parsed Windows events.

Extracts: IPv4/IPv6, MD5/SHA1/SHA256, domains, users, computers, processes,
command lines, file paths, registry keys, URLs, named pipes, services,
scheduled tasks, network shares, loaded DLLs.

Each IOC is returned as an IOCEntry dict with context:
    value, count, first_seen, last_seen, event_ids, users,
    computers, sources, score, score_reasons, threat_intel

Scoring (0-100) is NOT performed here — call ioc_scorer.score_ioc() after
extraction (done by analysis_worker_proc after extract_iocs returns).
"""

from __future__ import annotations

import os
import re

# ── Compiled regex patterns ──────────────────────────────────────────────────

_RE_IPv4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_IPv6 = re.compile(
    r'\b(?:'
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,7}:'
    r'|:(?::[0-9a-fA-F]{1,4}){1,7}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}'
    r'|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}'
    r'|::(?:ffff(?::0{1,4})?:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)'
      r'(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}'
    r')\b'
)
_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_SHA1   = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_MD5    = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_HEX32_QUICK = re.compile(r'[0-9a-fA-F]{32}')

# Expanded TLD list (50+)
_TLD_LIST = (
    "com|net|org|io|gov|edu|co|uk|de|fr|ru|cn|top|xyz|info|biz|us|ca|au|jp"
    "|tk|ml|ga|cf|gq|pw|cc|su|ro|bg|ua|kz|in|vn|id|ph|bd|pk|ng|ke|gh|ci"
    "|me|mobi|link|click|download|stream|work|gdn|racing|review|date|trade"
    "|accountant|science|party|faith|win|loan|bid|men|webcam|online|site"
    "|website|space|host|life|world|network|live|zone|press|uno|store|club"
    "|pro|fit|guru|black|adult|icu|cyou|monster|buzz|sbs|bar|lol|cfd"
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:' + _TLD_LIST + r')\b',
    re.IGNORECASE,
)

_RE_URL = re.compile(
    r'https?://[^\s"\'<>{}\[\]\\]{6,}',
    re.IGNORECASE,
)

# ── Noise filters ─────────────────────────────────────────────────────────────

_NOISE_IPS = frozenset({
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "169.254.169.254",
    "::1", "-", "",
})
_NOISE_USERS = frozenset({
    "-", "", "n/a", "anonymous logon", "local service", "network service",
    "system", "window manager", "font driver host", "dwm-1", "dwm-2",
    "umfd-0", "umfd-1",
})
_NOISE_COMPUTERS = frozenset({"-", "", "n/a"})

# Noise filters for new IOC types
_NOISE_PIPES = frozenset({
    "\\srvsvc", "\\wkssvc", "\\lsass", "\\svcctl", "\\winreg",
    "\\epmapper", "\\spoolss", "\\netdfs", "\\atsvc", "\\tapsrv",
    "\\samr", "\\browser", "\\eventlog",
})
_NOISE_SHARES = frozenset({
    "ipc$", "admin$", "sysvol", "netlogon", "print$", "c$", "d$",
})

# Standard system paths (used for DLL and LOLBAS filtering)
_SYSTEM_PATHS = ("\\system32\\", "\\syswow64\\", "\\sysnative\\")

# ── Event ID sets ─────────────────────────────────────────────────────────────

_PROCESS_EIDS  = frozenset({1, 4688})
_FILE_EIDS     = frozenset({11, 15, 4663, 4656, 4660})
_REG_EIDS      = frozenset({13, 4656, 4657, 4660, 4663})
_NET_EIDS      = frozenset({3, 4624, 4625, 4648, 4776, 5140, 5145})
_URL_EIDS      = frozenset({4688, 1, 4104})          # cmdline + PS scriptblock
_PIPE_EIDS     = frozenset({17, 18})                  # Sysmon named pipes
_SERVICE_EIDS  = frozenset({7045})
_TASK_EIDS     = frozenset({4698, 4699, 4700, 4702})
_SHARE_EIDS    = frozenset({5140, 5145})
_DLL_EIDS      = frozenset({7})                       # Sysmon ImageLoaded


# ── Accumulator ───────────────────────────────────────────────────────────────

class _Accum:
    """Per-IOC-value context accumulator."""
    __slots__ = ("count", "first", "last", "eids", "record_ids", "users", "computers", "sources")

    def __init__(self, ts: str, eid: int, record_id: int, user: str, computer: str, source: str) -> None:
        self.count     = 1
        self.first     = ts
        self.last      = ts
        self.eids: set[int]       = {eid}       if eid       else set()
        self.record_ids: set[int] = {record_id} if record_id else set()
        self.users: set[str]      = {user}      if user      else set()
        self.computers: set[str]  = {computer}  if computer  else set()
        self.sources: set[str]    = {source}    if source    else set()

    def update(self, ts: str, eid: int, record_id: int, user: str, computer: str, source: str) -> None:
        self.count += 1
        if ts:
            if not self.first or ts < self.first:
                self.first = ts
            if not self.last or ts > self.last:
                self.last = ts
        if eid:
            self.eids.add(eid)
        if record_id:
            self.record_ids.add(record_id)
        if user:
            self.users.add(user)
        if computer:
            self.computers.add(computer)
        if source:
            self.sources.add(source)


def _accum(store: dict, key: str,
           ts: str, eid: int, record_id: int, user: str, computer: str, source: str) -> None:
    """Add or update an IOC value in the accumulator store."""
    key = key.strip()
    if not key:
        return
    if key in store:
        store[key].update(ts, eid, record_id, user, computer, source)
    else:
        store[key] = _Accum(ts, eid, record_id, user, computer, source)


def _to_entry(val: str, accum: _Accum) -> dict:
    """Convert an _Accum to a fully-structured IOCEntry dict."""
    return {
        "value":         val,
        "count":         accum.count,
        "first_seen":    accum.first or None,
        "last_seen":     accum.last  or None,
        "event_ids":     sorted(accum.eids)[:20],
        "record_ids":    sorted(accum.record_ids)[:50_000],
        "users":         sorted(accum.users)[:10],
        "computers":     sorted(accum.computers)[:10],
        "sources":       sorted(accum.sources)[:5],
        "score":         0,
        "score_reasons": [],
        "threat_intel":  None,
    }


# ── Noise helpers ─────────────────────────────────────────────────────────────

def _clean_ip(ip: str) -> str | None:
    ip = ip.strip()
    if ip in _NOISE_IPS or ip.startswith("0."):
        return None
    return ip


def _clean_user(user: str) -> str | None:
    u = user.strip()
    if not u or u.lower() in _NOISE_USERS or u.endswith("$"):
        return None
    return u


def _get_user(ed: dict) -> str:
    """Return the first non-noise username found in event data."""
    for field in ("SubjectUserName", "TargetUserName", "UserName",
                  "AccountName", "SamAccountName"):
        val = ed.get(field, "")
        if val:
            u = _clean_user(str(val))
            if u:
                return u
    return ""


# ── Main extraction function ──────────────────────────────────────────────────

def extract_iocs(events: list[dict], progress_fn: object = None) -> dict:
    """
    Scan all events and extract IOCs with full context.

    Parameters
    ----------
    events : list[dict]
        Parsed event dicts (from the EVTX parser).
    progress_fn : callable(int) or None
        Called with percentage 0-100 periodically.

    Returns
    -------
    dict with IOCEntry lists per type key, plus "summary" and "correlation" (empty).
    Each IOCEntry has: value, count, first_seen, last_seen, event_ids,
    users, computers, sources, score (0), score_reasons ([]), threat_intel (None).
    """
    # Accumulator dicts: {value: _Accum}
    st_ipv4:        dict[str, _Accum] = {}
    st_ipv6:        dict[str, _Accum] = {}
    st_md5:         dict[str, _Accum] = {}
    st_sha1:        dict[str, _Accum] = {}
    st_sha256:      dict[str, _Accum] = {}
    st_domains:     dict[str, _Accum] = {}
    st_users:       dict[str, _Accum] = {}
    st_computers:   dict[str, _Accum] = {}
    st_processes:   dict[str, _Accum] = {}
    st_commandlines: dict[str, _Accum] = {}
    st_filepaths:   dict[str, _Accum] = {}
    st_registry:    dict[str, _Accum] = {}
    st_urls:        dict[str, _Accum] = {}
    st_named_pipes: dict[str, _Accum] = {}
    st_services:    dict[str, _Accum] = {}
    st_tasks:       dict[str, _Accum] = {}
    st_shares:      dict[str, _Accum] = {}
    st_dlls:        dict[str, _Accum] = {}

    total           = len(events)
    report_interval = max(1, total // 20)
    last_pct        = -1

    for idx, ev in enumerate(events):
        if progress_fn and idx % report_interval == 0:
            pct = int(idx / total * 100) if total else 0
            if pct != last_pct:
                progress_fn(pct)
                last_pct = pct

        eid       = ev.get("event_id", 0) or 0
        record_id = int(ev.get("record_id", 0) or 0)
        ed        = ev.get("event_data", {}) or {}
        ts        = ev.get("timestamp", "") or ev.get("TimeCreated", "") or ""
        comp      = ev.get("computer", "") or ""
        src       = os.path.basename(
            ev.get("source_file", "") or ev.get("_source", "") or ""
        )
        user = _get_user(ed)

        # Short aliases for the hot path
        def _a(store: dict, key: str) -> None:
            _accum(store, key, ts, eid, record_id, user, comp, src)

        # ── Computer name ─────────────────────────────────────────────────
        if comp and comp not in _NOISE_COMPUTERS:
            _a(st_computers, comp)

        # ── User fields ───────────────────────────────────────────────────
        for ufield in ("SubjectUserName", "TargetUserName", "UserName",
                       "AccountName", "SamAccountName"):
            val = ed.get(ufield, "")
            if val:
                u = _clean_user(str(val))
                if u:
                    _a(st_users, u)

        # ── IP address fields ─────────────────────────────────────────────
        for ipfield in ("IpAddress", "SourceNetworkAddress", "CallerIPAddress",
                        "RemoteAddress", "WorkstationName", "DestinationIp",
                        "SourceIp", "ClientAddress"):
            val = str(ed.get(ipfield, "") or "")
            if val:
                for ip in _RE_IPv4.findall(val):
                    c = _clean_ip(ip)
                    if c:
                        _a(st_ipv4, c)
                for ip in _RE_IPv6.findall(val):
                    _a(st_ipv6, ip.strip())

        # ── Process / command-line ────────────────────────────────────────
        if eid in _PROCESS_EIDS:
            for cmdfield in ("CommandLine", "ProcessCommandLine"):
                cmd = ed.get(cmdfield, "")
                if cmd:
                    _a(st_commandlines, str(cmd)[:500])
            for imgfield in ("Image", "NewProcessName", "ApplicationPath"):
                img = ed.get(imgfield, "")
                if img:
                    _a(st_processes, str(img))

        # ── File paths ────────────────────────────────────────────────────
        if eid in _FILE_EIDS:
            for ffield in ("TargetFilename", "ObjectName", "FileName"):
                val = ed.get(ffield, "")
                if val and ("\\" in str(val) or "/" in str(val)):
                    _a(st_filepaths, str(val))

        # ── Registry ──────────────────────────────────────────────────────
        if eid in _REG_EIDS:
            for rfield in ("ObjectName", "KeyPath", "TargetObject"):
                val = ed.get(rfield, "")
                if val:
                    vs = str(val)
                    if "HKEY" in vs.upper() or "\\SOFTWARE\\" in vs.upper() \
                            or "\\SYSTEM\\" in vs.upper():
                        _a(st_registry, vs)

        # ── Hash fields ───────────────────────────────────────────────────
        for hfield in ("Hashes", "Hash", "FileHash", "ImageHash", "MD5", "SHA256"):
            val = str(ed.get(hfield, "") or "")
            if not val or not _RE_HEX32_QUICK.search(val):
                continue
            for part in val.replace(",", " ").split():
                if "=" in part:
                    part = part.split("=", 1)[1]
                found256 = _RE_SHA256.findall(part)
                for h in found256:
                    _a(st_sha256, h.lower())
                part_s1 = _RE_SHA256.sub("", part)
                found1 = _RE_SHA1.findall(part_s1)
                for h in found1:
                    _a(st_sha1, h.lower())
                part_s2 = _RE_SHA1.sub("", part_s1)
                sha256_pfx = {m[:32] for m in found256}
                sha1_pfx   = {m[:32] for m in found1}
                for m in _RE_MD5.findall(part_s2):
                    if m not in sha256_pfx and m not in sha1_pfx:
                        _a(st_md5, m.lower())

        # ── Full-text scan for IPs/domains in free-form fields ────────────
        if eid in _NET_EIDS or eid in _PROCESS_EIDS:
            text = " ".join(str(v)[:2000] for v in ed.values() if v)[:4000]
            for ip in _RE_IPv4.findall(text):
                c = _clean_ip(ip)
                if c:
                    _a(st_ipv4, c)
            for dom in _RE_DOMAIN.findall(text):
                if len(dom) > 4 and "." in dom:
                    _a(st_domains, dom.lower())

        # ── URLs ──────────────────────────────────────────────────────────
        if eid in _URL_EIDS:
            for ufield in ("CommandLine", "ProcessCommandLine", "ScriptBlockText",
                           "CommandName", "Parameters"):
                val = ed.get(ufield, "")
                if not val:
                    continue
                for url in _RE_URL.findall(str(val)):
                    # Strip trailing punctuation that's unlikely part of URL
                    url = url.rstrip(".,;:)'\"")
                    if len(url) >= 10:
                        _a(st_urls, url)

        # ── Named pipes (Sysmon EID 17/18) ───────────────────────────────
        if eid in _PIPE_EIDS:
            pipe = ed.get("PipeName", "") or ed.get("pipeName", "")
            if pipe:
                p = str(pipe).lower()
                if p not in _NOISE_PIPES:
                    _a(st_named_pipes, str(pipe))

        # ── Services (EID 7045 — new service installed) ───────────────────
        if eid in _SERVICE_EIDS:
            svc_name = ed.get("ServiceName", "") or ed.get("serviceName", "")
            if svc_name:
                _a(st_services, str(svc_name))
            # Also log the service binary path as a process
            img = ed.get("ImagePath", "") or ed.get("imagePath", "")
            if img:
                _a(st_processes, str(img))

        # ── Scheduled tasks (EID 4698/4699/4700/4702) ────────────────────
        if eid in _TASK_EIDS:
            task = ed.get("TaskName", "") or ed.get("taskName", "")
            if task:
                _a(st_tasks, str(task))

        # ── Network shares (EID 5140/5145) ────────────────────────────────
        if eid in _SHARE_EIDS:
            share = ed.get("ShareName", "") or ed.get("shareName", "")
            if share and share.lower() not in _NOISE_SHARES:
                _a(st_shares, str(share))

        # ── DLLs (Sysmon EID 7 — ImageLoaded, non-system only) ───────────
        if eid in _DLL_EIDS:
            img = ed.get("ImageLoaded", "") or ed.get("imageLoaded", "")
            if img:
                vs = str(img)
                vl = vs.lower()
                # Only include if .dll extension AND not a standard system DLL
                if vl.endswith(".dll") and not any(sp in vl for sp in _SYSTEM_PATHS):
                    _a(st_dlls, vs)

    # ── Conversion: _Accum → IOCEntry, sort by value ─────────────────────────
    def _finalize(store: dict) -> list[dict]:
        return [_to_entry(v, a) for v, a in store.items()]

    result = {
        "ipv4":         _finalize(st_ipv4),
        "ipv6":         _finalize(st_ipv6),
        "md5":          _finalize(st_md5),
        "sha1":         _finalize(st_sha1),
        "sha256":       _finalize(st_sha256),
        "domains":      _finalize(st_domains),
        "users":        _finalize(st_users),
        "computers":    _finalize(st_computers),
        "processes":    _finalize(st_processes),
        "commandlines": _finalize(st_commandlines),
        "filepaths":    _finalize(st_filepaths),
        "registry":     _finalize(st_registry),
        "urls":         _finalize(st_urls),
        "named_pipes":  _finalize(st_named_pipes),
        "services":     _finalize(st_services),
        "tasks":        _finalize(st_tasks),
        "shares":       _finalize(st_shares),
        "dlls":         _finalize(st_dlls),
        "correlation":  {},   # populated by ioc_correlation.correlate_iocs() later
    }

    # Summary: count of entries per type
    result["summary"] = {
        k: len(v) for k, v in result.items()
        if k not in ("summary", "correlation")
    }

    if progress_fn:
        progress_fn(100)

    return result
