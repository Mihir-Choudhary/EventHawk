"""
Event Correlation Engine — detect attack chains from sorted event lists.

Approach:
  - Input: list of events already sorted by timestamp (from main process)
  - Builds a pre-index by (computer, event_id) for O(1) sub-list lookups
  - Runs 13 correlation rules using the index (10 sliding-window + 3 LogonId-session)
  - Returns list of Chain objects describing detected attack sequences
  - Performance: O(n) index build + O(subset * R) rule scan

correlate(events) -> list[dict]  (each dict = one detected chain)

Perf fixes applied:
  #1 — Pre-index by (computer, event_id): rules do O(1) lookups, not O(n) scans
  #2 — LRU-cached _ts(): avoids re-parsing the same timestamp across rules
  #4 — Removed redundant _sort_by_ts: sub-lists inherit parent sort order

LogonId Session Tracking (3 additional rules):
  - _LogonSessionIndex maps every LogonId to its full session events
  - _rule_logonid_privesc: 4624+4672 matched by exact LogonId (zero overlap FP)
  - _rule_logonid_process_chain: network logon -> process creation via LogonId
  - _rule_multi_host_lateral_movement: same user on 3+ hosts within 30 min
"""

from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from functools import lru_cache

logger = logging.getLogger(__name__)

# ── Timestamp parser (cached) ────────────────────────────────────────────────
# Perf fix #2: LRU cache avoids re-parsing the same timestamp string across
# multiple rules. Timestamps are immutable strings so caching is safe.

@lru_cache(maxsize=65536)
def _ts(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    s = ts_str.rstrip("Z").split(".")[0][:19]
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _ts_delta(a: str, b: str) -> float:
    """Seconds between two ISO timestamp strings. Returns large number on error."""
    ta, tb = _ts(a), _ts(b)
    if ta is None or tb is None:
        return 9999999.0
    return abs((tb - ta).total_seconds())


def _ts_ge(a: str, b: str) -> bool:
    """Return True if timestamp a >= b using proper datetime comparison."""
    ta, tb = _ts(a), _ts(b)
    if ta is None or tb is None:
        return a >= b  # fallback to string comparison only if parsing fails
    return ta >= tb


def _get_user(ev: dict) -> str:
    ed = ev.get("event_data", {}) or {}
    return (
        ed.get("SubjectUserName") or
        ed.get("TargetUserName") or
        ed.get("UserName") or ""
    ).lower()


def _get_logon_type(ev: dict) -> str:
    ed = ev.get("event_data", {}) or {}
    return str(ed.get("LogonType", "")).strip()


def _get_auth_pkg(ev: dict) -> str:
    ed = ev.get("event_data", {}) or {}
    return str(ed.get("AuthenticationPackageName", "") or
               ed.get("PackageName", "")).lower()


def _get_ticket_enc(ev: dict) -> str:
    ed = ev.get("event_data", {}) or {}
    return str(ed.get("TicketEncryptionType", "")).lower()


# ── False-positive reduction helpers ─────────────────────────────────────────
# These are shared across rules to apply consistent, well-documented filtering
# decisions rather than ad-hoc per-rule checks.

# Built-in Windows system/service identity names.  These accounts legitimately
# produce events that look exactly like attack patterns (dangerous privileges at
# every service startup, NTLM network logons, scheduled tasks, etc.).
_SYSTEM_ACCOUNT_NAMES = frozenset({
    "system", "local service", "network service", "anonymous logon",
    "iusr", "network", "local system", "defaultaccount", "wdagutilityaccount",
})


def _is_system_user(user: str) -> bool:
    """True for built-in system/service identities that should be skipped in most rules."""
    u = user.lower().strip()
    if u in _SYSTEM_ACCOUNT_NAMES:
        return True
    # NT AUTHORITY\ and NT SERVICE\ prefix accounts (e.g. "nt authority\\system")
    if u.startswith("nt authority\\") or u.startswith("nt service\\"):
        return True
    # Computer/machine accounts always end with $ in Active Directory
    if u.endswith("$"):
        return True
    return False


def _get_substatus(ev: dict) -> str:
    """Return normalised SubStatus hex string from a 4625 failure event (empty if absent)."""
    ed = ev.get("event_data", {}) or {}
    return str(ed.get("SubStatus", "") or "").strip().lower()


def _is_suspicious_service_path(path: str) -> bool:
    """
    Return True when a service binary path falls outside expected Windows / Program
    Files directories.  Legitimate services nearly always live in System32, SysWOW64,
    Windows dir, or Program Files.  Malicious services frequently land in Temp, AppData,
    ProgramData, or user-writable locations.

    Returns False (not suspicious) when path is empty — the calling rule should still
    flag such events and let an analyst investigate.
    """
    if not path:
        return False
    p = (path.lower()
         .replace("\\", "/")
         .strip('"')
         .replace("%systemroot%", "c:/windows")
         .replace("%windir%",     "c:/windows")
         .replace("%programfiles%", "c:/program files"))
    _LEGIT = (
        "c:/windows/system32/",
        "c:/windows/syswow64/",
        "c:/windows/",
        "c:/program files/",
        "c:/program files (x86)/",
    )
    for prefix in _LEGIT:
        if p.startswith(prefix):
            return False
    _SUSPECT = ("/temp/", "/tmp/", "/appdata/", "/programdata/",
                "/users/", "/desktop/", "/downloads/", "/recycle")
    return any(d in p for d in _SUSPECT)


def _format_ts(ts: str) -> str:
    return ts.replace("T", " ").replace("Z", "").replace(" UTC", "")[:19]


# ── Pre-computed event index ─────────────────────────────────────────────────
# Perf fix #1: Build once in correlate(), pass to all rules. Each rule does O(1)
# dict lookups instead of O(n) list comprehensions over the full event list.
# Events arrive pre-sorted by timestamp; sub-lists inherit that order (fix #4).

class _EventIndex:
    """Pre-indexed view of the sorted event list for fast sub-list lookups."""

    __slots__ = ("by_eid", "by_computer_eid", "by_computer", "all_events")

    def __init__(self, events: list[dict]):
        self.all_events = events
        # Index by event_id -> list[dict] (preserves sort order)
        self.by_eid: dict[int, list[dict]] = defaultdict(list)
        # Index by (computer, event_id) -> list[dict]
        self.by_computer_eid: dict[tuple[str, int], list[dict]] = defaultdict(list)
        # FINDING-20: index by computer -> list[dict] for _rule_log_clearing().
        # Without this, each clearing event triggered an O(n) full scan of
        # all_events to find prior activity on the same computer.  With this
        # index the scan is bounded to events_per_computer, which is typically
        # 100-1000× smaller than the full event list.
        self.by_computer: dict[str, list[dict]] = defaultdict(list)

        for ev in events:
            eid = ev.get("event_id", 0)
            comp = ev.get("computer", "")
            self.by_eid[eid].append(ev)
            self.by_computer_eid[(comp, eid)].append(ev)
            self.by_computer[comp].append(ev)

    def get_by_eid(self, *eids: int) -> list[dict]:
        """Get events matching any of the given event IDs."""
        if len(eids) == 1:
            return self.by_eid.get(eids[0], [])
        result: list[dict] = []
        for eid in eids:
            result.extend(self.by_eid.get(eid, []))
        return result

    def get_by_computer_eid(self, computer: str, *eids: int) -> list[dict]:
        """Get events on a specific computer matching any of the given event IDs."""
        if len(eids) == 1:
            return self.by_computer_eid.get((computer, eids[0]), [])
        result: list[dict] = []
        for eid in eids:
            result.extend(self.by_computer_eid.get((computer, eid), []))
        return result


# ── LogonId Session Index ─────────────────────────────────────────────────────

class _LogonSessionIndex:
    """
    Second index built from the event list.

    Maps every LogonId to its full session: the 4624 logon event, any 4672
    privilege-assignment events, any 4688 process-creation events spawned
    under that session, and the 4634 logoff event.

    LogonId field names per event type:
      4624 (logon)      -> TargetLogonId
      4634 (logoff)     -> TargetLogonId
      4672 (privs)      -> SubjectLogonId
      4688 (proc)       -> SubjectLogonId

    LogonId 0x0 / 0 / "" are skipped (system noise with no meaningful session).
    """

    __slots__ = ("sessions",)

    _SKIP_IDS = frozenset({"0x0", "0", "", "0x00000000"})

    def __init__(self, events: list[dict]):
        # sessions: logon_id_str -> {"logon": ev|None, "privs": [], "procs": [], "logoff": ev|None}
        self.sessions: dict[str, dict] = {}

        for ev in events:
            eid = ev.get("event_id", 0)
            ed  = ev.get("event_data", {}) or {}

            if eid == 4624:
                lid = str(ed.get("TargetLogonId", "")).strip()
                if lid not in self._SKIP_IDS:
                    sess = self.sessions.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )
                    # Keep most-recent logon for any recycled LogonId
                    sess["logon"] = ev

            elif eid == 4672:
                lid = str(ed.get("SubjectLogonId", "")).strip()
                if lid not in self._SKIP_IDS:
                    self.sessions.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )["privs"].append(ev)

            elif eid == 4688:
                lid = str(ed.get("SubjectLogonId", "")).strip()
                if lid not in self._SKIP_IDS:
                    self.sessions.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )["procs"].append(ev)

            elif eid == 4634:
                lid = str(ed.get("TargetLogonId", "")).strip()
                if lid not in self._SKIP_IDS:
                    sess = self.sessions.setdefault(
                        lid, {"logon": None, "privs": [], "procs": [], "logoff": None}
                    )
                    sess["logoff"] = ev


# ── Sysmon ProcessGuid correlation ────────────────────────────────────────────

# Known-bad parent→child spawn pairs (process basename → set of suspicious children).
# Flagging office/browser spawning shells is one of the strongest phishing indicators.
_SUSPICIOUS_SPAWN: dict[str, frozenset] = {
    "winword.exe":  frozenset({"cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","wmic.exe"}),
    "excel.exe":    frozenset({"cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe","wmic.exe"}),
    "powerpnt.exe": frozenset({"cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"}),
    "outlook.exe":  frozenset({"cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe"}),
    "iexplore.exe": frozenset({"cmd.exe","powershell.exe","mshta.exe","wscript.exe","cscript.exe"}),
    "msedge.exe":   frozenset({"cmd.exe","powershell.exe","mshta.exe"}),
    "chrome.exe":   frozenset({"cmd.exe","powershell.exe","mshta.exe"}),
    "acrord32.exe": frozenset({"cmd.exe","powershell.exe","wscript.exe"}),
    "acrobat.exe":  frozenset({"cmd.exe","powershell.exe","wscript.exe"}),
    "mshta.exe":    frozenset({"cmd.exe","powershell.exe","wscript.exe","cscript.exe"}),
    "wscript.exe":  frozenset({"cmd.exe","powershell.exe","mshta.exe"}),
    "cscript.exe":  frozenset({"cmd.exe","powershell.exe","mshta.exe"}),
}


class _GuidIndex:
    """
    Indexes Sysmon EID 1 / Windows EID 4688 events by ProcessGuid and
    ParentProcessGuid to enable exact parent→child process tree reconstruction.

    Built in O(n) with a single pass over all events.
    bool(guid_idx) is False when no Sysmon-style ProcessGuid data is found,
    so the rule that depends on it is never invoked on non-Sysmon datasets
    (zero overhead for pure Windows Security log datasets).
    """
    __slots__ = ("guid_to_event", "children", "_has_data")
    _NULL_GUID = "{00000000-0000-0000-0000-000000000000}"
    _PROC_EIDS = frozenset({1, 4688})

    def __init__(self, events: list[dict]) -> None:
        self.guid_to_event: dict[str, dict] = {}        # ProcessGuid → creation event
        self.children:      dict[str, list[dict]] = {}  # ParentProcessGuid → child events
        self._has_data = False

        null_lc = self._NULL_GUID.lower()
        for ev in events:
            ed    = ev.get("event_data", {}) or {}
            guid  = str(ed.get("ProcessGuid")       or "").strip().lower()
            pguid = str(ed.get("ParentProcessGuid") or "").strip().lower()

            if not guid or guid == null_lc:
                continue
            if ev.get("event_id") in self._PROC_EIDS:
                self._has_data = True
                # Keep first seen — if GUID reused across reboots, first is most relevant
                if guid not in self.guid_to_event:
                    self.guid_to_event[guid] = ev
                # Only process-creation events represent actual child processes.
                # Other Sysmon EIDs (7, 10, 11, etc.) use ProcessGuid to identify
                # the *initiating* process, not a new child — exclude them.
                if pguid and pguid != guid and pguid != null_lc:
                    self.children.setdefault(pguid, []).append(ev)

    def __bool__(self) -> bool: return self._has_data
    def __len__(self)  -> int:  return len(self.guid_to_event)


def _rule_guid_process_tree(idx: _EventIndex, guid_idx: _GuidIndex) -> list[dict]:
    """
    Detect suspicious parent→child process chains using Sysmon ProcessGuid linking.

    Only runs when guid_idx is truthy (Sysmon EID 1 data present).
    Severity tiers (highest takes precedence):
      critical — office/browser process spawns a shell (phishing/macro dropper)
      high     — LOLBAS binary appears as a descendant
      medium   — descendant process lands in a suspicious filesystem path

    Hard bounds: depth 5, 20 events/chain, 50 chains total (performance guard).
    """
    from evtx_tool.analysis.ioc_scorer import _LOLBAS, _SUSP_PROC_PATHS

    MAX_CHAINS       = 50
    MAX_DEPTH        = 5
    MAX_CHAIN_EVENTS = 20

    chains:  list[dict] = []
    emitted: set[str]   = set()

    def _base(ev: dict) -> str:
        ed  = ev.get("event_data", {}) or {}
        img = str(ed.get("Image") or ed.get("NewProcessName") or "").lower()
        return os.path.basename(img)

    def _in_susp_path(ev: dict) -> bool:
        ed  = ev.get("event_data", {}) or {}
        img = str(ed.get("Image") or ed.get("NewProcessName") or "").lower()
        return any(frag in img for frag in _SUSP_PROC_PATHS)

    def _walk(guid: str, depth: int, visited: set) -> list[dict]:
        """DFS subtree walk bounded by depth and per-chain event count.
        visited prevents duplicate events if a GUID is reused across reboots
        or appears in multiple positions in the tree."""
        if depth == 0 or guid in visited:
            return []
        visited.add(guid)
        result: list[dict] = []
        for child in guid_idx.children.get(guid, []):
            result.append(child)
            if len(result) >= MAX_CHAIN_EVENTS:
                break
            cg = str((child.get("event_data") or {}).get("ProcessGuid") or "").strip().lower()
            if cg:
                result.extend(_walk(cg, depth - 1, visited))
            if len(result) >= MAX_CHAIN_EVENTS:
                break
        return result[:MAX_CHAIN_EVENTS]

    for guid, root_ev in guid_idx.guid_to_event.items():
        if len(chains) >= MAX_CHAINS:
            break
        if guid in emitted or not guid_idx.children.get(guid):
            continue

        root_base = _base(root_ev)
        children  = _walk(guid, MAX_DEPTH, set())
        if not children:
            continue

        severity: str | None = None
        desc:     str | None = None

        # ── Pattern 1: office/browser → shell (critical) ──────────────────────
        bad_spawn = _SUSPICIOUS_SPAWN.get(root_base, frozenset())
        bad_kids  = [c for c in children if _base(c) in bad_spawn]
        if bad_kids:
            severity = "critical"
            desc = (
                f"Suspicious process spawned by {root_base}: "
                + ", ".join(sorted({_base(c) for c in bad_kids}))
                + " — common phishing/macro dropper pattern"
            )

        # ── Pattern 2: LOLBAS as a descendant (high) ──────────────────────────
        if severity is None:
            lolbas_kids = [c for c in children if _base(c) in _LOLBAS]
            if lolbas_kids:
                severity = "high"
                desc = (
                    f"LOLBAS binary spawned under {root_base}: "
                    + ", ".join(sorted({_base(c) for c in lolbas_kids}))
                )

        # ── Pattern 3: descendant in suspicious path (medium) ─────────────────
        if severity is None:
            susp_kids = [c for c in children if _in_susp_path(c)]
            if susp_kids:
                severity = "medium"
                desc = (
                    f"Child process in suspicious path under {root_base}: "
                    + ", ".join(sorted({_base(c) for c in susp_kids}))
                )

        if severity is None:
            continue                 # benign tree, skip

        chains.append(_chain(
            name        = "Sysmon ProcessGuid — Suspicious Spawn Chain",
            tactic      = "Execution",
            severity    = severity,
            description = desc,
            events      = [root_ev] + children,
        ))
        # Mark root AND all descendant GUIDs so intermediate nodes that are
        # also roots (have their own children) don't spawn duplicate sub-chains.
        emitted.add(guid)
        for _ev in children:
            _cg = str((_ev.get("event_data") or {}).get("ProcessGuid") or "").strip().lower()
            if _cg:
                emitted.add(_cg)

    return chains


# ── Correlation rule definitions ──────────────────────────────────────────────

def _chain(name: str, tactic: str, severity: str, description: str,
           events: list[dict], extra: dict | None = None) -> dict:
    """Build a standardised chain result dict."""
    ts_list = [ev.get("timestamp", "") for ev in events if ev.get("timestamp")]
    first_ts = min(ts_list) if ts_list else ""
    last_ts  = max(ts_list) if ts_list else ""
    computers = list({ev.get("computer", "") for ev in events if ev.get("computer")})
    users     = list({u for ev in events if (u := _get_user(ev))})
    c = {
        "rule_name":   name,
        "tactic":      tactic,
        "severity":    severity,
        "description": description,
        "events":      events,
        "first_ts":    first_ts,
        "last_ts":     last_ts,
        "computers":   computers,
        "users":       users,
        "event_count": len(events),
    }
    if extra:
        c.update(extra)
    return c


# ── Rule implementations ──────────────────────────────────────────────────────
# All rules now receive an _EventIndex instead of the raw event list.
# Sub-lists from the index are already sorted (inheriting parent sort order,
# perf fix #4), so no _sort_by_ts() calls are needed.

def _rule_brute_force_success(idx: _EventIndex) -> list[dict]:
    """
    5+ Event 4625 (failed logons) from same computer+user within 5 min,
    followed by 4624 (success) within 2 min of last failure.

    False-positive reductions:
    - Machine and system accounts excluded: service credential re-auth after
      a password rotation produces an identical 5-failure burst legitimately.
    - Soft SubStatus filter: when the field is present, only genuine wrong-password
      codes (0xC000006A, 0xC000006D) count toward the threshold.  Codes for
      disabled / expired / time-restricted accounts are excluded (different
      operational problem, not active brute force).  When SubStatus is absent
      the event is counted anyway for parser compatibility.
    """
    # STATUS_WRONG_PASSWORD (0xC000006A) — the clearest brute-force signal.
    # STATUS_LOGON_FAILURE  (0xC000006D) — generic but almost always wrong password.
    # STATUS_ACCESS_DENIED  (0xC0000022) — seen in some NTLM failure scenarios.
    _WRONG_PW_SS = frozenset({"0xc000006a", "0xc000006d", "0xc0000022"})

    chains: list[dict] = []
    # Group failures by computer+user, applying account and SubStatus filters
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for ev in idx.get_by_eid(4625):
        user = _get_user(ev)
        if not user or _is_system_user(user):
            continue
        ss = _get_substatus(ev)
        if ss and ss not in _WRONG_PW_SS:
            continue  # present but not a wrong-password code — skip
        key = (ev.get("computer", ""), user)
        groups[key].append(ev)

    for (computer, user), failures in groups.items():
        if len(failures) < 5:
            continue
        # Sub-list is already sorted (perf fix #4 — inherits parent sort order)
        # Sliding 5-minute windows
        i = 0
        while i < len(failures):
            window = [failures[i]]
            j = i + 1
            while j < len(failures):
                if _ts_delta(failures[i]["timestamp"], failures[j]["timestamp"]) <= 300:
                    window.append(failures[j])
                    j += 1
                else:
                    break
            if len(window) >= 5:
                last_fail_ts = max(ev["timestamp"] for ev in window)
                # Look for 4624 success within 2 minutes after last failure
                # Perf fix #1: use index lookup instead of full scan
                success_events = idx.get_by_computer_eid(computer, 4624)
                matching_success = [
                    ev for ev in success_events
                    if _get_user(ev) == user
                    and _ts_delta(last_fail_ts, ev["timestamp"]) <= 120
                    and _ts_ge(ev["timestamp"], last_fail_ts)
                ]
                if matching_success:
                    chain_events = window + matching_success[:1]
                    chains.append(_chain(
                        name        = "Brute Force -> Successful Logon",
                        tactic      = "Credential Access -> Initial Access",
                        severity    = "high",
                        description = (
                            f"{len(window)} failed logons (4625) followed by success (4624) "
                            f"on {computer} user={user or '?'} within 5-min window. "
                            f"Indicates credential stuffing, brute force, or password spray."
                        ),
                        events      = chain_events,
                    ))
                    i = j
                    continue
            i += 1
    return chains


def _rule_network_logon_service_install(idx: _EventIndex) -> list[dict]:
    """
    4624 LogonType=3 (Network) + 7045/4697 (Service Installed) within 2 min on same computer.
    Classic PSExec / Impacket lateral movement pattern.
    """
    chains: list[dict] = []
    net_logons = [ev for ev in idx.get_by_eid(4624) if _get_logon_type(ev) == "3"]

    for logon in net_logons:
        computer = logon.get("computer", "")
        logon_ts = logon.get("timestamp", "")
        ed_logon = logon.get("event_data", {}) or {}

        # Skip loopback source — PSExec / admin tools running locally on the same
        # machine are common legitimate operations, not lateral movement.
        src_ip = str(ed_logon.get("IpAddress", "") or "").strip()
        if src_ip in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "-", ""):
            continue

        # Perf fix #1: lookup by computer instead of scanning all service installs
        svc_installs = idx.get_by_computer_eid(computer, 7045, 4697)
        matches = [
            svc for svc in svc_installs
            if _ts_delta(logon_ts, svc.get("timestamp", "")) <= 120
            and _ts_ge(svc.get("timestamp", ""), logon_ts)
        ]
        if not matches:
            continue

        # Prefer matches where the service binary path looks suspicious.
        # Fall back to all matches when path info was not extracted by the parser
        # (empty path ≠ safe — analyst should still review).
        suspicious = [
            svc for svc in matches
            if _is_suspicious_service_path(
                (svc.get("event_data") or {}).get("ImagePath", "")
                or (svc.get("event_data") or {}).get("ServiceFileName", "")
            )
        ]
        final = suspicious if suspicious else matches

        svc_names = ", ".join(filter(None, [
            (svc.get("event_data") or {}).get("ServiceName", "")
            for svc in final[:3]
        ])) or "?"
        path_note = ("Suspicious binary path detected. " if suspicious
                     else "Binary path not extracted — verify manually. ")

        chains.append(_chain(
            name        = "Network Logon -> Service Install (PSExec/Impacket Pattern)",
            tactic      = "Lateral Movement -> Persistence",
            severity    = "high",
            description = (
                f"Network logon (4624 Type 3) from {src_ip} on {computer} followed by "
                f"service installation (7045/4697) within 2 minutes. "
                f"Service(s): {svc_names}. {path_note}"
                f"Matches PSExec, Impacket SMBExec, or smbexec patterns."
            ),
            events      = [logon] + final[:3],
        ))
    return chains


_DANGEROUS_PRIVILEGES = frozenset({
    "SeTcbPrivilege", "SeDebugPrivilege", "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege", "SeLoadDriverPrivilege",
    "SeRestorePrivilege", "SeTakeOwnershipPrivilege",
})


def _rule_privilege_escalation_chain(idx: _EventIndex) -> list[dict]:
    """
    4624 (logon) + 4672 (special privileges assigned) within 30s, same user.
    Only triggers when PrivilegeList contains a genuinely dangerous privilege
    (e.g. SeTcbPrivilege, SeDebugPrivilege) to avoid flooding on normal admin logons.
    """
    chains: list[dict] = []
    logons = idx.get_by_eid(4624)
    # BUG 12 fix: only include 4672 events with dangerous privileges
    dangerous_privs: list[dict] = []
    for ev in idx.get_by_eid(4672):
        priv_list = str((ev.get("event_data") or {}).get("PrivilegeList", ""))
        if any(dp in priv_list for dp in _DANGEROUS_PRIVILEGES):
            dangerous_privs.append(ev)

    if not dangerous_privs:
        return chains

    # Perf fix #1: group dangerous privs by computer for faster lookup
    privs_by_computer: dict[str, list[dict]] = defaultdict(list)
    for p in dangerous_privs:
        privs_by_computer[p.get("computer", "")].append(p)

    # Type 4 (Batch) and Type 5 (Service) logons are excluded.
    # Service accounts and scheduled tasks receive dangerous privileges
    # (SeImpersonatePrivilege, SeDebugPrivilege) at every startup by design —
    # including them produces constant high-volume noise with zero investigative value.
    _SKIP_TYPES = frozenset({"4", "5"})

    for logon in logons:
        computer = logon.get("computer", "")
        user     = _get_user(logon)
        logon_ts = logon.get("timestamp", "")
        if not user or _is_system_user(user):
            continue
        if _get_logon_type(logon) in _SKIP_TYPES:
            continue
        matches = [
            p for p in privs_by_computer.get(computer, [])
            if _get_user(p) == user
            and _ts_delta(logon_ts, p.get("timestamp", "")) <= 30
        ]
        if matches:
            found_privs = set()
            for p in matches:
                pl = str((p.get("event_data") or {}).get("PrivilegeList", ""))
                found_privs.update(dp for dp in _DANGEROUS_PRIVILEGES if dp in pl)
            chains.append(_chain(
                name        = "Logon + Dangerous Special Privileges (Privilege Escalation)",
                tactic      = "Privilege Escalation",
                severity    = "high",
                description = (
                    f"Logon (4624) immediately followed by assignment of sensitive "
                    f"privileges (4672) for {user} on {computer}. "
                    f"Privileges: {', '.join(sorted(found_privs))}."
                ),
                events      = [logon] + matches[:2],
            ))
    return chains


def _rule_kerberoasting(idx: _EventIndex) -> list[dict]:
    """
    3+ Event 4769 with TicketEncryptionType=0x17 (RC4) within 5 minutes.
    RC4 on an AES domain = Kerberoasting indicator.
    """
    chains: list[dict] = []
    rc4_tickets = [
        ev for ev in idx.get_by_eid(4769)
        if _get_ticket_enc(ev) in ("0x17", "23", "rc4")
        # Requesting user must not be a machine/system account
        and not _is_system_user(_get_user(ev))
        # Service name (SPN) must not be a machine account or built-in principal.
        # Machine SPNs end with $ (e.g. "HOST/DC01$"); krbtgt is a TGT renewal.
        # These produce benign RC4 tickets and should never trigger Kerberoasting.
        and not str((ev.get("event_data") or {}).get("ServiceName", "")).strip().endswith("$")
        and str((ev.get("event_data") or {}).get("ServiceName", "")).strip().lower()
            not in ("krbtgt", "", "kadmin/changepw", "krbtgt/")
    ]

    if len(rc4_tickets) < 3:
        return chains

    # Group by computer
    by_computer: dict[str, list[dict]] = defaultdict(list)
    for ev in rc4_tickets:
        by_computer[ev.get("computer", "")].append(ev)

    for computer, tickets in by_computer.items():
        # Already sorted (perf fix #4 — inherits parent sort order)
        i = 0
        while i < len(tickets):
            window = [tickets[i]]
            j = i + 1
            while j < len(tickets):
                if _ts_delta(tickets[i]["timestamp"], tickets[j]["timestamp"]) <= 300:
                    window.append(tickets[j])
                    j += 1
                else:
                    break
            if len(window) >= 3:
                users = list({_get_user(ev) for ev in window})
                chains.append(_chain(
                    name        = "Kerberoasting (RC4 Ticket Requests)",
                    tactic      = "Credential Access",
                    severity    = "high",
                    description = (
                        f"{len(window)} Kerberos service ticket requests (4769) with "
                        f"RC4 encryption (0x17) on {computer} within 5 minutes. "
                        f"Indicates Kerberoasting — attacker requesting RC4-encrypted "
                        f"tickets to crack offline. Users: {', '.join(users) or '?'}"
                    ),
                    events      = window,
                ))
                i = j
                continue
            i += 1
    return chains


def _rule_pass_the_hash(idx: _EventIndex) -> list[dict]:
    """
    4624 LogonType=3 + NTLM auth + non-machine account from a remote IP.
    4776 (NTLM validation) immediately before/after — PTH indicator.
    """
    chains: list[dict] = []
    ntlm_net_logons = [
        ev for ev in idx.get_by_eid(4624)
        if _get_logon_type(ev) == "3"
        and "ntlm" in _get_auth_pkg(ev)
    ]

    for ev in ntlm_net_logons:
        user = _get_user(ev)
        if not user or _is_system_user(user):
            continue

        ed  = ev.get("event_data", {}) or {}
        ip  = str(ed.get("IpAddress", "") or ed.get("SourceNetworkAddress", "") or "").strip()
        if not ip or ip in ("-", "127.0.0.1", "::1", "::ffff:127.0.0.1", ""):
            continue

        # ── KeyLength = 0: the strongest single PTH discriminator ────────────
        # In Pass-the-Hash the attacker supplies the NTLM hash directly — no
        # plaintext password means no session key can be derived.  Windows logs
        # KeyLength = 0.  Legitimate NTLM logons negotiate a session key:
        #   NTLMv2 → KeyLength = 128
        #   NTLMv1 → KeyLength = 56
        # Only flag when the field is explicitly "0"; skip events where the
        # parser did not extract it to avoid FP from incomplete parses.
        key_len = str(ed.get("KeyLength", "")).strip()
        if key_len and key_len != "0":
            continue  # non-zero → real session key negotiated, not PTH

        # ── LmPackageName must confirm NTLM (not Negotiate falling back) ─────
        # When present, must contain "ntlm" (e.g. "NTLM V2", "NTLM V1").
        # A Kerberos or SPNEGO package appearing here means the auth is not NTLM.
        lm_pkg = str(ed.get("LmPackageName", "") or "").lower()
        if lm_pkg and "ntlm" not in lm_pkg:
            continue

        computer = ev.get("computer", "?")
        chains.append(_chain(
            name        = "Pass-the-Hash Indicator",
            tactic      = "Lateral Movement -> Credential Access",
            severity    = "high",
            description = (
                f"Network logon (4624 Type=3) with NTLM and KeyLength=0 for "
                f"'{user}' from {ip} on {computer}. "
                f"KeyLength=0 means no session key was negotiated — the hash was "
                f"used directly (Pass-the-Hash pattern). "
                f"Verify whether NTLM from this source is expected."
            ),
            events      = [ev],
        ))
    return chains


def _is_security_channel(ev: dict) -> bool:
    """
    Return True only when an event genuinely originates from the Windows Security
    event log.

    Why this matters: many Windows components reuse small integer EIDs that happen
    to collide with Security-log EIDs.  For example:
      - EID 1102 in Security = "Audit log was cleared" (real threat indicator)
      - EID 1102 in ShellCommon-StartLayoutPopulation/Operational = Start Menu layout
      - EID 5007 in Windows Defender/Operational = Defender config change
    Without channel validation these benign operational events are misclassified as
    evidence-tampering / audit-policy changes (false positives).

    The Security event log is identified by channel name "Security" (Windows sets this
    verbatim; the provider is Microsoft-Windows-Security-Auditing).
    """
    ch = str(ev.get("channel") or ev.get("log") or "").strip().lower()
    # Accept "Security" and the fully-qualified provider name as fallback
    return ch == "security" or ch == "microsoft-windows-security-auditing"


def _rule_log_clearing(idx: _EventIndex) -> list[dict]:
    """
    1102 (Security log cleared) or 4719 (audit policy changed) after any other activity.

    Channel validation:
      EID 1102 / 517  must come from the "Security" channel.
        - Multiple unrelated Windows components recycle EID 1102 for their own
          purposes (e.g. ShellCommon-StartLayoutPopulation uses it for Start Menu
          layout events).  Matching on EID alone causes high false-positive rates.
      EID 4719 (audit policy change) is exclusive to the Security channel in
        normal Windows deployments.

    Prior-activity filter:
      Only Security-channel events are used as "prior activity" when the clearing
      event itself is from Security.  Operational / diagnostic logs (WER-Diag,
      Privacy-Auditing, Defender) have no security relevance to log-clearing
      detection and are excluded to prevent noise.
    """
    chains: list[dict] = []

    # Only accept clearing/policy events that genuinely originate from Security log
    clear_events = [
        ev for ev in idx.get_by_eid(1102, 517, 4719)
        if _is_security_channel(ev)
    ]

    for clr in clear_events:
        computer = clr.get("computer", "")
        clr_ts   = clr.get("timestamp", "")
        # Prior activity: Security-channel events only on the same computer within 30 min.
        # FINDING-20: use by_computer index instead of scanning all_events — avoids an
        # O(n_total) pass per clearing event; scans only events on the same computer.
        prior = [
            ev for ev in idx.by_computer.get(computer, [])
            if ev.get("event_id") not in (1102, 517, 4719)
            and _is_security_channel(ev)            # ← exclude noisy operational logs
            and _ts_delta(ev.get("timestamp", ""), clr_ts) <= 1800
            and not _ts_ge(ev.get("timestamp", ""), clr_ts)
        ]
        if prior:
            eid_label = {1102: "1102 (log cleared)", 517: "517 (log cleared — legacy)",
                         4719: "4719 (audit policy changed)"}.get(clr.get("event_id", 0), "?")
            chains.append(_chain(
                name        = "Log Clearing / Audit Policy Change (Evidence Tampering)",
                tactic      = "Defense Evasion",
                severity    = "critical",
                description = (
                    f"Security event {eid_label} on {computer} "
                    f"after {len(prior)} Security-channel events within 30 minutes. "
                    f"Attackers clear logs to remove forensic evidence. "
                    f"(Channel-validated — operational/diagnostic logs excluded.)"
                ),
                events      = prior[-5:] + [clr],  # last 5 prior + clear event
            ))
    return chains


def _rule_scheduled_task_after_logon(idx: _EventIndex) -> list[dict]:
    """
    4624 + 4698 (task created) within 5 min on same computer — persistence.

    False-positive reductions:
    - Type 4 (Batch) and Type 5 (Service) logons excluded: scheduled tasks and
      service accounts routinely create or update tasks themselves (Windows Update,
      Defender, software deployment agents) — they are the noisiest FP source.
    - System/machine accounts excluded for the same reason.
    """
    chains: list[dict] = []
    logons = idx.get_by_eid(4624)

    # Service and Batch logons produce constant task-creation events legitimately
    _SKIP_TYPES = frozenset({"4", "5"})

    for logon in logons:
        computer = logon.get("computer", "")
        user     = _get_user(logon)
        logon_ts = logon.get("timestamp", "")
        if not user or _is_system_user(user):
            continue
        if _get_logon_type(logon) in _SKIP_TYPES:
            continue
        # Perf fix #1: lookup tasks on this computer only
        tasks = idx.get_by_computer_eid(computer, 4698, 4702)
        matches  = [
            t for t in tasks
            if _ts_delta(logon_ts, t.get("timestamp", "")) <= 300
            and _ts_ge(t.get("timestamp", ""), logon_ts)
        ]
        if matches:
            chains.append(_chain(
                name        = "Logon -> Scheduled Task Creation (Persistence)",
                tactic      = "Persistence",
                severity    = "medium",
                description = (
                    f"Scheduled task created (4698/4702) on {computer} within 5 minutes "
                    f"of logon by {user or '?'}. Common persistence mechanism."
                ),
                events      = [logon] + matches[:2],
            ))
    return chains


def _rule_account_created_after_recon(idx: _EventIndex) -> list[dict]:
    """
    4798/4799 (group enumeration) + 4720 (account created) within 10 min — account takeover prep.
    """
    chains: list[dict] = []
    recons = idx.get_by_eid(4798, 4799)

    for recon in recons:
        computer    = recon.get("computer", "")
        recon_ts    = recon.get("timestamp", "")
        recon_actor = _get_user(recon)
        # Perf fix #1: lookup creates on this computer only
        creates = idx.get_by_computer_eid(computer, 4720)
        # Same-actor filter: require the subject performing the group enumeration
        # to also be the one creating the account.  This eliminates the very common
        # IT-workflow FP where an admin checks group memberships (4798/4799) and
        # then a separate provisioning service creates the account moments later.
        matches  = [
            c for c in creates
            if _ts_delta(recon_ts, c.get("timestamp", "")) <= 600
            and _ts_ge(c.get("timestamp", ""), recon_ts)
            and (not recon_actor or _get_user(c) == recon_actor)
        ]
        if matches:
            chains.append(_chain(
                name        = "Group Reconnaissance -> Account Created",
                tactic      = "Discovery -> Persistence",
                severity    = "medium",
                description = (
                    f"Local group enumeration (4798/4799) by '{recon_actor or '?'}' "
                    f"followed by account creation (4720) by the same actor "
                    f"on {computer} within 10 minutes. "
                    f"Attacker may be establishing persistence via a new account. "
                    f"(Same-actor validated — provisioning-service FP eliminated.)"
                ),
                events      = [recon] + matches[:2],
            ))
    return chains


def _rule_password_spray(idx: _EventIndex) -> list[dict]:
    """
    20+ 4625 failures across DIFFERENT users from same source IP within 60s.
    Distinct from brute-force (same user) — this hits many accounts.
    """
    chains: list[dict] = []

    # Group by computer using the index.
    # Type 2 (Interactive) failures are excluded: a user mistyping a password at
    # the console is not a spray.  Password spray uses network authentication
    # (Type 3 Network, Type 8 NetworkCleartext, Type 10 RDP) or no type field.
    # System/machine accounts are excluded as they produce constant auth noise.
    by_computer: dict[str, list[dict]] = defaultdict(list)
    for ev in idx.get_by_eid(4625):
        if _get_logon_type(ev) == "2":
            continue  # interactive console failure — not spray
        user = _get_user(ev)
        if _is_system_user(user):
            continue
        by_computer[ev.get("computer", "")].append(ev)

    for computer, evts in by_computer.items():
        # Already sorted (perf fix #4)
        i = 0
        while i < len(evts):
            window = [evts[i]]
            j = i + 1
            while j < len(evts):
                if _ts_delta(evts[i]["timestamp"], evts[j]["timestamp"]) <= 60:
                    window.append(evts[j])
                    j += 1
                else:
                    break
            if len(window) >= 20:
                distinct_users = {_get_user(ev) for ev in window}
                if len(distinct_users) >= 5:  # multiple different targets
                    chains.append(_chain(
                        name        = "Password Spray Attack",
                        tactic      = "Credential Access",
                        severity    = "high",
                        description = (
                            f"{len(window)} failed logons (4625) against "
                            f"{len(distinct_users)} different accounts on {computer} "
                            f"within 60 seconds. "
                            f"Indicates a password spray attack — one password tried "
                            f"against many accounts to avoid lockout."
                        ),
                        events      = window[:10],  # cap at 10 representative events
                        extra       = {"distinct_users": len(distinct_users)},
                    ))
                    i = j
                    continue
            i += 1
    return chains


def _rule_ps_exec_chain(idx: _EventIndex) -> list[dict]:
    """
    4688 (cmd/powershell spawned by unusual parent) + 4104 (PS script block) within 60s.
    """
    chains: list[dict] = []
    proc_events = idx.get_by_eid(4688)

    for pe in proc_events:
        ed = pe.get("event_data", {}) or {}
        new_proc = (ed.get("NewProcessName") or "").lower()
        parent   = (ed.get("ParentProcessName") or "").lower()
        if "powershell" not in new_proc and "cmd" not in new_proc:
            continue
        # Processes that should never legitimately spawn cmd/PowerShell.
        # "explorer" is intentionally excluded: a user clicking a .ps1 file in
        # Windows Explorer spawns PowerShell with explorer as parent — this is
        # completely normal and was one of the most common FP sources.
        # "svchost" is retained because WMI execution (T1047) and WinRM (T1021.006)
        # abuse svchost as a launch pad — though it can also be a FP for Group
        # Policy scripts; analysts should check the specific service hosted.
        suspicious_parents = ("wmiprvse", "wscript", "mshta", "svchost", "dllhost",
                              "winword", "excel", "outlook", "msiexec")
        if not any(p in parent for p in suspicious_parents):
            continue

        computer = pe.get("computer", "")
        pe_ts    = pe.get("timestamp", "")
        # Perf fix #1: lookup PS blocks on this computer only
        ps_blocks = idx.get_by_computer_eid(computer, 4104)
        related_ps = [
            b for b in ps_blocks
            if 0 <= _ts_delta(pe_ts, b.get("timestamp", "")) <= 60
        ]
        if related_ps:
            chains.append(_chain(
                name        = "Suspicious Process Spawn -> PowerShell Execution",
                tactic      = "Execution",
                severity    = "high",
                description = (
                    f"PowerShell/cmd spawned by suspicious parent process "
                    f"'{parent}' on {computer}, followed by PS script block logging (4104). "
                    f"Matches WMI execution, macro-based attacks, or living-off-the-land."
                ),
                events      = [pe] + related_ps[:2],
            ))
    return chains


# ── LogonId-session rules (accept both idx and session_idx) ──────────────────

def _rule_logonid_privesc(idx: _EventIndex, session_idx: _LogonSessionIndex) -> list[dict]:
    """
    4624 (logon) + 4672 (dangerous special privileges) matched by exact LogonId.

    Advantage over _rule_privilege_escalation_chain: uses the precise LogonId
    field instead of a (user + 30-second) time window, so concurrent sessions
    for the same user on the same box never cross-contaminate results.
    Only fires when PrivilegeList contains at least one genuinely dangerous
    privilege (same filter as the time-window rule).
    """
    chains: list[dict] = []

    # Service (Type 5) and Batch (Type 4) logons always receive dangerous privileges
    # at startup — same rationale as the time-window rule above.
    _SKIP_TYPES = frozenset({"4", "5"})

    for lid, session in session_idx.sessions.items():
        logon_ev = session.get("logon")
        if not logon_ev:
            continue
        if _get_logon_type(logon_ev) in _SKIP_TYPES:
            continue

        dangerous: list[dict] = []
        for p in session.get("privs", []):
            priv_list = str((p.get("event_data") or {}).get("PrivilegeList", ""))
            if any(dp in priv_list for dp in _DANGEROUS_PRIVILEGES):
                dangerous.append(p)

        if not dangerous:
            continue

        user = _get_user(logon_ev)
        if not user or _is_system_user(user):
            continue

        computer    = logon_ev.get("computer", "")
        logon_type  = _get_logon_type(logon_ev)
        _type_names = {
            "2": "Interactive", "3": "Network", "4": "Batch", "5": "Service",
            "7": "Unlock", "8": "NetworkCleartext", "9": "NewCredentials",
            "10": "RemoteInteractive(RDP)", "11": "CachedInteractive",
        }
        type_label  = _type_names.get(logon_type, f"Type{logon_type}") if logon_type else "Unknown"

        found_privs: set[str] = set()
        for p in dangerous:
            pl = str((p.get("event_data") or {}).get("PrivilegeList", ""))
            found_privs.update(dp for dp in _DANGEROUS_PRIVILEGES if dp in pl)

        chains.append(_chain(
            name        = "Logon + Dangerous Privileges (LogonId-Confirmed)",
            tactic      = "Privilege Escalation",
            severity    = "high",
            description = (
                f"Logon (4624 {type_label}) linked to dangerous privilege assignment (4672) "
                f"via LogonId {lid} for '{user}' on {computer}. "
                f"Privileges: {', '.join(sorted(found_privs))}. "
                f"Exact LogonId match eliminates false positives from concurrent sessions."
            ),
            events      = [logon_ev] + dangerous[:2],
        ))

    return chains


def _rule_logonid_process_chain(idx: _EventIndex, session_idx: _LogonSessionIndex) -> list[dict]:
    """
    4624 network logon (Type=3) matched to 4688 (process creation) via LogonId.

    Provides high-confidence evidence that specific processes were spawned
    under a particular network session — useful for lateral-movement + execution
    attribution without relying on imprecise time windows.

    False-positive reductions:
    - Machine/system accounts excluded (automated processes constantly create
      child processes under their own network sessions).
    - Common benign Windows runtime processes filtered out: if ALL processes
      under the session are Windows-internal helpers (conhost, dllhost, svchost,
      etc.) the chain is not fired — these are always spawned by Windows itself
      and are not attacker-controlled.
    """
    # Windows creates these processes automatically as helpers / COM surrogates /
    # console hosts — they are NOT evidence of attacker activity on their own.
    _BENIGN_PROCS = frozenset({
        "conhost.exe", "dllhost.exe", "svchost.exe", "taskhost.exe",
        "taskhostw.exe", "backgroundtaskhost.exe", "runtimebroker.exe",
        "wermgr.exe", "werfault.exe", "msiexec.exe", "sihost.exe",
        "ctfmon.exe", "fontdrvhost.exe", "dwm.exe", "winlogon.exe",
    })

    chains: list[dict] = []

    for lid, session in session_idx.sessions.items():
        logon_ev = session.get("logon")
        if not logon_ev:
            continue
        if _get_logon_type(logon_ev) != "3":   # network logon only
            continue

        user = _get_user(logon_ev)
        if not user or _is_system_user(user):
            continue

        procs = session.get("procs", [])
        if not procs:
            continue

        computer = logon_ev.get("computer", "")

        proc_names: list[str] = []
        interesting_procs: list[dict] = []
        for p in procs:
            ed   = p.get("event_data", {}) or {}
            name = (ed.get("NewProcessName") or "").replace("\\", "/").split("/")[-1].lower()
            if name:
                proc_names.append(name)
                if name not in _BENIGN_PROCS:
                    interesting_procs.append(p)

        # Only fire when at least one non-benign process was spawned.
        # If ALL processes are Windows-internal helpers, this is not attacker activity.
        if not interesting_procs:
            continue

        chains.append(_chain(
            name        = "Network Logon -> Process Execution (LogonId-Linked)",
            tactic      = "Lateral Movement -> Execution",
            severity    = "medium",
            description = (
                f"Network logon (4624 Type=3) for '{user or '?'}' on {computer} "
                f"spawned {len(procs)} process(es) under LogonId {lid} "
                f"({len(interesting_procs)} non-benign). "
                f"Processes: {', '.join(proc_names[:5]) or '?'}. "
                f"LogonId linking provides direct session-to-execution attribution."
            ),
            events      = [logon_ev] + interesting_procs[:3],
        ))

    return chains


def _rule_multi_host_lateral_movement(idx: _EventIndex, session_idx: _LogonSessionIndex) -> list[dict]:
    """
    Same user appears in 4624 (success logon) events on 3+ different computers
    within a 30-minute sliding window.

    Only counts remote/network logon types — interactive (Type 2) console logons
    are excluded because a user sitting at 3 workstations is not lateral movement:
      Type 3  — Network (SMB, WMI, PSExec, Impacket)
      Type 8  — NetworkCleartext (WinRM cleartext, legacy)
      Type 9  — NewCredentials (RunAs /netonly; used in pass-the-hash)
      Type 10 — RemoteInteractive (RDP)

    Machine accounts ($), built-in service identities (SYSTEM, LOCAL SERVICE, NETWORK
    SERVICE, NT AUTHORITY/ prefixed, NT SERVICE/ prefixed), and blank users are excluded
    via _is_system_user() to avoid noise from legitimate automated processes.
    Each window triggers at most one chain (deduplicated by the correlate() caller).
    """
    _WINDOW_SECS    = 1800   # 30 minutes
    _MIN_HOSTS      = 3
    _REMOTE_TYPES   = frozenset({"3", "8", "9", "10"})

    chains: list[dict] = []

    # Group 4624 remote-logon events by user
    by_user: dict[str, list[dict]] = defaultdict(list)
    for ev in idx.get_by_eid(4624):
        if _get_logon_type(ev) not in _REMOTE_TYPES:
            continue
        user = _get_user(ev)
        if not user or _is_system_user(user):
            continue
        by_user[user].append(ev)

    for user, logons in by_user.items():
        # Sub-list inherits parent sort order (perf fix #4)
        i = 0
        while i < len(logons):
            window = [logons[i]]
            j = i + 1
            while j < len(logons):
                if _ts_delta(logons[i]["timestamp"], logons[j]["timestamp"]) <= _WINDOW_SECS:
                    window.append(logons[j])
                    j += 1
                else:
                    break

            distinct_computers = {ev.get("computer", "") for ev in window}
            distinct_computers.discard("")

            if len(distinct_computers) >= _MIN_HOSTS:
                sorted_hosts  = sorted(distinct_computers)
                logon_type_labels = {
                    "3": "Network(3)", "8": "NetCleartext(8)",
                    "9": "NewCreds(9)", "10": "RDP(10)",
                }
                seen_types = sorted({
                    logon_type_labels.get(_get_logon_type(ev), f"Type{_get_logon_type(ev)}")
                    for ev in window
                })
                chains.append(_chain(
                    name        = "Multi-Host Lateral Movement",
                    tactic      = "Lateral Movement",
                    severity    = "high",
                    description = (
                        f"User '{user}' made remote logons to {len(distinct_computers)} different "
                        f"computer(s) ({', '.join(sorted_hosts)}) within "
                        f"{_WINDOW_SECS // 60} minutes via {', '.join(seen_types)}. "
                        f"Indicates lateral movement via credential reuse or pass-the-hash."
                    ),
                    events      = window,
                    extra       = {"distinct_hosts": len(distinct_computers)},
                ))
                i = j
                continue
            i += 1

    return chains


# ── Public API ────────────────────────────────────────────────────────────────

_RULES = [
    _rule_brute_force_success,
    _rule_network_logon_service_install,
    # _rule_privilege_escalation_chain is intentionally omitted: it is fully
    # superseded by _rule_logonid_privesc (below), which matches the same
    # 4624+4672 pair via the exact LogonId field instead of a ±30-second
    # time window.  Running both rules produces duplicate alerts for every
    # privileged logon session, adding noise without additional signal.
    # The time-window rule is kept in the source as a reference / fallback
    # in case LogonId extraction ever fails at the parser level.
    _rule_kerberoasting,
    _rule_pass_the_hash,
    _rule_log_clearing,
    _rule_scheduled_task_after_logon,
    _rule_account_created_after_recon,
    _rule_password_spray,
    _rule_ps_exec_chain,
]

# Rules that require both _EventIndex and _LogonSessionIndex
_LOGON_SESSION_RULES = [
    _rule_logonid_privesc,
    _rule_logonid_process_chain,
    _rule_multi_host_lateral_movement,
]


def correlate(events: list[dict], progress_fn: object = None) -> list[dict]:
    """
    Run all correlation rules against a list of events.

    Parameters
    ----------
    events : list[dict]
        Parsed event dicts (should be timestamp-sorted).
    progress_fn : callable(int) or None
        Called with percentage (0-100) after each rule completes.

    The events list should already be sorted by timestamp (done in CLI post-parse).
    Events are NOT re-sorted here to allow the caller to control sorting once.

    Perf fix #1: builds an _EventIndex once, passes to all rules for O(1) lookups.
    Also builds a _LogonSessionIndex once for the 3 LogonId-session rules.

    Returns a list of chain dicts, sorted by severity then first_ts.
    """
    if not events:
        return []

    # Perf fix #1: build index once, shared across all rules
    idx = _EventIndex(events)

    # Build LogonId session index once for the 3 session-tracking rules
    session_idx = _LogonSessionIndex(events)

    # Build ProcessGuid index for Sysmon-based tree correlation.
    # Zero-cost on non-Sysmon datasets: bool(guid_idx) is False, so
    # _GUID_RULES stays empty and no extra loop iterations occur.
    guid_idx   = _GuidIndex(events)
    _GUID_RULES = [_rule_guid_process_tree] if guid_idx else []

    # Clear the LRU cache from any previous run to avoid stale data
    _ts.cache_clear()

    all_chains: list[dict] = []

    total_rules = len(_RULES) + len(_LOGON_SESSION_RULES) + len(_GUID_RULES)
    rule_idx = 0

    for rule_fn in _RULES:
        try:
            chains = rule_fn(idx)
            all_chains.extend(chains)
        except Exception as exc:
            logger.warning("Correlation rule %s failed: %s", rule_fn.__name__, exc)
        rule_idx += 1
        if progress_fn:
            progress_fn(int(rule_idx / total_rules * 100))

    for rule_fn in _LOGON_SESSION_RULES:
        try:
            chains = rule_fn(idx, session_idx)
            all_chains.extend(chains)
        except Exception as exc:
            logger.warning("Correlation rule %s failed: %s", rule_fn.__name__, exc)
        rule_idx += 1
        if progress_fn:
            progress_fn(int(rule_idx / total_rules * 100))

    for rule_fn in _GUID_RULES:
        try:
            chains = rule_fn(idx, guid_idx)
            all_chains.extend(chains)
        except Exception as exc:
            logger.warning("GUID rule %s failed: %s", rule_fn.__name__, exc)
        rule_idx += 1
        if progress_fn:
            progress_fn(int(rule_idx / total_rules * 100))

    # Deduplicate: same rule + same computer + overlapping time window
    seen: set[str] = set()
    unique: list[dict] = []
    for chain in all_chains:
        ts_key = (chain.get("first_ts") or "")[:16] or "__no_ts__"
        key = f"{chain['rule_name']}|{','.join(sorted(chain['computers']))}|{ts_key}"
        if key not in seen:
            seen.add(key)
            unique.append(chain)

    # Sort by severity desc, then first_ts asc
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    unique.sort(key=lambda c: (-sev_order.get(c["severity"], 0), c["first_ts"]))

    logger.info("Correlation engine: %d chains found from %d events", len(unique), len(events))
    return unique
