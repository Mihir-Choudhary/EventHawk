"""
MITRE ATT&CK mapping for Windows Event IDs.

Maps Event ID -> list of ATT&CK technique references.
All lookups are O(1) dict access — zero performance overhead.

enrich_with_attack(events) mutates the events list in-place,
adding an 'attack_tags' key to each event. Safe to call on large lists.
"""

from __future__ import annotations

from evtx_tool.analysis.context_rules import apply_context_rules
from evtx_tool.analysis.sigma_rules import get_sigma_tags

# ── Tactic display order ──────────────────────────────────────────────────────

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access",
    "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]

TACTIC_COLORS = {
    "Initial Access":        "#c0392b",
    "Execution":             "#e67e22",
    "Persistence":           "#8e44ad",
    "Privilege Escalation":  "#d35400",
    "Defense Evasion":       "#16a085",
    "Credential Access":     "#2980b9",
    "Discovery":             "#27ae60",
    "Lateral Movement":      "#e74c3c",
    "Collection":            "#f39c12",
    "Command and Control":   "#1abc9c",
    "Exfiltration":          "#9b59b6",
    "Impact":                "#c0392b",
    "Reconnaissance":        "#7f8c8d",
    "Resource Development":  "#95a5a6",
}

# ── Core mapping: Event ID -> list of technique refs ─────────────────────────
# Format: {"tactic", "tid" (technique id), "name", "url"}

ATTACK_MAP: dict[int, list[dict]] = {

    # ── Initial Access ──────────────────────────────────────────────────────
    4624: [{"tactic": "Initial Access",       "tid": "T1078",     "name": "Valid Accounts"}],
    4648: [{"tactic": "Initial Access",       "tid": "T1078",     "name": "Valid Accounts"},
           {"tactic": "Lateral Movement",     "tid": "T1550.002", "name": "Pass the Hash"}],

    # ── Execution ───────────────────────────────────────────────────────────
    4688: [{"tactic": "Execution",            "tid": "T1059",     "name": "Command and Scripting Interpreter"}],
    4104: [{"tactic": "Execution",            "tid": "T1059.001", "name": "PowerShell"}],
    4698: [{"tactic": "Execution",            "tid": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task"}],
    4702: [{"tactic": "Execution",            "tid": "T1053.005", "name": "Scheduled Task/Job: Scheduled Task"}],

    # ── Persistence ─────────────────────────────────────────────────────────
    4697: [{"tactic": "Persistence",          "tid": "T1543.003", "name": "Create or Modify System Process: Windows Service"}],
    7045: [{"tactic": "Persistence",          "tid": "T1543.003", "name": "Create or Modify System Process: Windows Service"}],
    4720: [{"tactic": "Persistence",          "tid": "T1136.001", "name": "Create Account: Local Account"}],
    4722: [{"tactic": "Persistence",          "tid": "T1078",     "name": "Valid Accounts"}],
    4723: [{"tactic": "Persistence",          "tid": "T1098",     "name": "Account Manipulation"}],
    4724: [{"tactic": "Persistence",          "tid": "T1098",     "name": "Account Manipulation"}],
    4725: [{"tactic": "Defense Evasion",      "tid": "T1078",     "name": "Valid Accounts"}],
    4728: [{"tactic": "Persistence",          "tid": "T1098.007", "name": "Account Manipulation: Additional Local or Domain Groups"}],
    4732: [{"tactic": "Persistence",          "tid": "T1098.007", "name": "Account Manipulation: Additional Local or Domain Groups"}],
    4756: [{"tactic": "Persistence",          "tid": "T1098.007", "name": "Account Manipulation: Additional Local or Domain Groups"}],
    4776: [{"tactic": "Credential Access",    "tid": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"}],

    # ── Privilege Escalation ────────────────────────────────────────────────
    4672: [{"tactic": "Privilege Escalation", "tid": "T1134",     "name": "Access Token Manipulation"}],
    4673: [{"tactic": "Privilege Escalation", "tid": "T1134",     "name": "Access Token Manipulation"}],
    4674: [{"tactic": "Privilege Escalation", "tid": "T1134",     "name": "Access Token Manipulation"}],
    4611: [{"tactic": "Privilege Escalation", "tid": "T1134.002", "name": "Access Token Manipulation: Create Process with Token"}],

    # ── Defense Evasion ─────────────────────────────────────────────────────
    1102: [{"tactic": "Defense Evasion",      "tid": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs"}],
    517:  [{"tactic": "Defense Evasion",      "tid": "T1070.001", "name": "Indicator Removal: Clear Windows Event Logs"}],
    4719: [{"tactic": "Defense Evasion",      "tid": "T1562.002", "name": "Impair Defenses: Disable Windows Event Logging"}],
    4946: [{"tactic": "Defense Evasion",      "tid": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall"}],
    4947: [{"tactic": "Defense Evasion",      "tid": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall"}],
    4948: [{"tactic": "Defense Evasion",      "tid": "T1562.004", "name": "Impair Defenses: Disable or Modify System Firewall"}],
    7040: [{"tactic": "Defense Evasion",      "tid": "T1562.001", "name": "Impair Defenses: Disable or Modify Tools"}],
    4735: [{"tactic": "Defense Evasion",      "tid": "T1078.002", "name": "Valid Accounts: Domain Accounts"}],
    4737: [{"tactic": "Defense Evasion",      "tid": "T1078.002", "name": "Valid Accounts: Domain Accounts"}],

    # ── Credential Access ───────────────────────────────────────────────────
    4625: [{"tactic": "Credential Access",    "tid": "T1110",     "name": "Brute Force"}],
    4740: [{"tactic": "Credential Access",    "tid": "T1110.001", "name": "Brute Force: Password Guessing"}],
    4771: [{"tactic": "Credential Access",    "tid": "T1110",     "name": "Brute Force (Kerberos pre-auth)"}],
    4768: [{"tactic": "Credential Access",    "tid": "T1558",     "name": "Steal or Forge Kerberos Tickets"}],
    4769: [{"tactic": "Credential Access",    "tid": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}],
    4777: [{"tactic": "Credential Access",    "tid": "T1110",     "name": "Brute Force (NTLM validation fail)"}],

    # ── Discovery ───────────────────────────────────────────────────────────
    4798: [{"tactic": "Discovery",            "tid": "T1069.001", "name": "Permission Groups Discovery: Local Groups"}],
    4799: [{"tactic": "Discovery",            "tid": "T1069.001", "name": "Permission Groups Discovery: Local Groups"}],
    4662: [{"tactic": "Discovery",            "tid": "T1087.002", "name": "Account Discovery: Domain Account"}],
    4663: [{"tactic": "Discovery",            "tid": "T1083",     "name": "File and Directory Discovery"}],
    7036: [{"tactic": "Discovery",            "tid": "T1082",     "name": "System Information Discovery"}],

    # ── Lateral Movement ────────────────────────────────────────────────────
    5140: [{"tactic": "Lateral Movement",     "tid": "T1039",     "name": "Data from Network Shared Drive"}],
    5141: [{"tactic": "Lateral Movement",     "tid": "T1570",     "name": "Lateral Tool Transfer"}],
    5142: [{"tactic": "Lateral Movement",     "tid": "T1570",     "name": "Lateral Tool Transfer"}],
    5143: [{"tactic": "Lateral Movement",     "tid": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"}],
    5144: [{"tactic": "Lateral Movement",     "tid": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"}],
    5145: [{"tactic": "Lateral Movement",     "tid": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares"}],

    # ── Collection ──────────────────────────────────────────────────────────
    4656: [{"tactic": "Collection",           "tid": "T1005",     "name": "Data from Local System"}],
    4660: [{"tactic": "Collection",           "tid": "T1485",     "name": "Data Destruction"}],

    # ── Impact ──────────────────────────────────────────────────────────────
    7034: [{"tactic": "Impact",               "tid": "T1489",     "name": "Service Stop"}],
    7035: [{"tactic": "Impact",               "tid": "T1529",     "name": "System Shutdown/Reboot"}],

    # ── Sysmon events (channel: Microsoft-Windows-Sysmon) ──────────────────
    # EventID 1  in Sysmon = Process Create
    1:    [{"tactic": "Execution",            "tid": "T1059",     "name": "Command and Scripting Interpreter (Sysmon Process Create)"}],
    # EventID 3  = Network connection
    3:    [{"tactic": "Command and Control",  "tid": "T1071",     "name": "Application Layer Protocol (Sysmon Network)"}],
    # EventID 7  = Image loaded
    7:    [{"tactic": "Defense Evasion",      "tid": "T1055.001", "name": "Process Injection: DLL Injection (Sysmon Image Load)"}],
    # EventID 8  = CreateRemoteThread
    8:    [{"tactic": "Privilege Escalation", "tid": "T1055",     "name": "Process Injection: CreateRemoteThread (Sysmon)"}],
    # EventID 10 = ProcessAccess (LSASS)
    10:   [{"tactic": "Credential Access",   "tid": "T1003.001", "name": "OS Credential Dumping: LSASS Memory (Sysmon ProcessAccess)"}],
    # EventID 11 = FileCreate
    11:   [{"tactic": "Persistence",          "tid": "T1547",     "name": "Boot or Logon Autostart Execution (Sysmon FileCreate)"}],
    # EventID 13 = RegistryValueSet
    13:   [{"tactic": "Persistence",          "tid": "T1112",     "name": "Modify Registry (Sysmon)"}],
    # EventID 15 = FileCreateStreamHash
    15:   [{"tactic": "Defense Evasion",      "tid": "T1553",     "name": "Subvert Trust Controls (Sysmon ADS)"}],
    # EventID 22 = DNSEvent
    22:   [{"tactic": "Command and Control",  "tid": "T1071.004", "name": "Application Layer Protocol: DNS (Sysmon)"}],
    # EventID 23 = FileDelete
    23:   [{"tactic": "Defense Evasion",      "tid": "T1070.004", "name": "Indicator Removal: File Deletion (Sysmon)"}],
    # EventID 25 = ProcessTampering
    25:   [{"tactic": "Defense Evasion",      "tid": "T1055",     "name": "Process Injection: Process Tampering (Sysmon)"}],
}

# Sysmon EventIDs that need special handling (shared IDs with Security log)
_SYSMON_PROVIDER = "microsoft-windows-sysmon"

# ── Public API ────────────────────────────────────────────────────────────────

def get_attack_tags(event_id: int, provider: str = "") -> list[dict]:
    """Return ATT&CK tags for a given event_id. Returns empty list if unmapped."""
    # Low-numbered Sysmon IDs (1-25) clash with Security IDs.
    # Only apply Sysmon mapping when provider is Sysmon.
    if event_id <= 25:
        if _SYSMON_PROVIDER in provider.lower():
            return ATTACK_MAP.get(event_id, [])
        else:
            # For non-Sysmon sources, skip low-number generic mappings
            # (event IDs 1-25 are only meaningful in Sysmon context)
            return []
    return ATTACK_MAP.get(event_id, [])


def enrich_with_attack(events: list[dict]) -> None:
    """
    Add 'attack_tags' key to each event in-place.
    Returns nothing — mutates the list.
    O(n) — pure dict lookups, no I/O.
    """
    for ev in events:
        ev["attack_tags"] = get_attack_tags(
            ev.get("event_id", 0),
            ev.get("provider", ""),
        )


def enrich_and_summarize(events: list[dict]) -> dict:
    """
    Enrich events with ATT&CK tags AND build the summary in a single O(n) pass.

    FINDING-16: replaces the old two-call pattern in ParseWorker:
      enrich_with_attack(events)        # pass 1
      attack_summary = build_attack_summary(events)  # pass 2
    with one pass that does both simultaneously.

    Returns the same dict shape as build_attack_summary().
    """
    by_tactic: dict[str, int]    = {}
    by_technique: dict[str, dict] = {}
    total_tagged = 0

    for ev in events:
        # Sigma rules take precedence for covered event IDs (field-level conditions).
        # Falls back to the static ATTACK_MAP for uncovered event IDs.
        sigma_result = get_sigma_tags(ev)
        if sigma_result is not None:
            tags = sigma_result
        else:
            tags = get_attack_tags(ev.get("event_id", 0), ev.get("provider", ""))
        ev["attack_tags"] = tags
        apply_context_rules(ev)          # lineage, entropy, confidence scoring
        tags = ev["attack_tags"]         # re-read — context may have modified it
        if tags:
            total_tagged += 1
            for tag in tags:
                tactic = tag["tactic"]
                tid    = tag["tid"]
                name   = tag["name"]
                by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
                if tid not in by_technique:
                    by_technique[tid] = {"name": name, "tactic": tactic, "count": 0}
                by_technique[tid]["count"] += 1

    return {
        "by_tactic":    by_tactic,
        "by_technique": by_technique,
        "total_tagged": total_tagged,
    }


def build_attack_summary(events: list[dict]) -> dict:
    """
    Summarise ATT&CK coverage across all events.

    Returns:
        {
          "by_tactic":     {tactic: count},
          "by_technique":  {tid: {"name", "tactic", "count"}},
          "total_tagged":  int,
        }
    """
    by_tactic: dict[str, int] = {}
    by_technique: dict[str, dict] = {}
    total_tagged = 0

    for ev in events:
        tags = ev.get("attack_tags") or get_attack_tags(
            ev.get("event_id", 0), ev.get("provider", "")
        )
        if tags:
            total_tagged += 1
            for tag in tags:
                tactic = tag["tactic"]
                tid    = tag["tid"]
                name   = tag["name"]
                by_tactic[tactic] = by_tactic.get(tactic, 0) + 1
                if tid not in by_technique:
                    by_technique[tid] = {"name": name, "tactic": tactic, "count": 0}
                by_technique[tid]["count"] += 1

    return {
        "by_tactic":    by_tactic,
        "by_technique": by_technique,
        "total_tagged": total_tagged,
    }
