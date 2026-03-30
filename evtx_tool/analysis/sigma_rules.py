"""
Sigma-like conditional rule engine for ATT&CK detection.

Replaces the flat ATTACK_MAP lookup for high-noise event IDs with field-level
Selection / Filter / Condition logic — the same model used by the Sigma framework.

Each rule has:
  selection   – dict of field conditions that must ALL match (AND)
  filter      – dict of conditions; if ALL match, event is excluded (optional)
  filter_any  – list of filter dicts; excluded if ANY block matches (optional)
  condition   – "selection" or "selection and not filter"
  tags        – list of ATT&CK tag dicts to assign (empty list = explicit suppress)
  confidence  – "low" | "medium" | "high" (written into each tag dict)

Supported field condition operators (key suffix):
  no suffix / _is_any   exact match (case-insensitive); value may be list
  _contains / _contains_any   substring match; value may be list
  _endswith / _endswith_any   suffix match; value may be list
  _startswith / _startswith_any  prefix match; value may be list

Special field names (top-level event keys):
  event_id   → ev["event_id"] (compared as string)
  channel    → ev["channel"].lower()
  provider   → ev["provider"].lower()
  All others → ev["event_data"][field].lower()

Public API
----------
get_sigma_tags(ev: dict) -> list[dict] | None
    Returns matched tags if any sigma rule's selection covers this event.
    Returns None if no sigma rule is registered for this event_id
    (caller should fall back to the static ATTACK_MAP).
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Condition evaluation engine
# ---------------------------------------------------------------------------

_OP_SUFFIXES: tuple[str, ...] = (
    "endswith_any", "startswith_any", "contains_any",
    "endswith", "startswith", "contains", "is_any",
)


def _parse_key(key: str) -> tuple[str, str]:
    """Split 'FieldName_op' → ('FieldName', 'op').  No known suffix → 'exact'."""
    for op in _OP_SUFFIXES:
        suffix = "_" + op
        if key.endswith(suffix):
            return key[:-len(suffix)], op
    return key, "exact"


def _get_field(ev: dict, field: str) -> str:
    """Return a field value as a lowercase string for comparison."""
    if field == "event_id":
        return str(ev.get("event_id", ""))
    if field == "channel":
        return (ev.get("channel") or "").lower()
    if field == "provider":
        return (ev.get("provider") or "").lower()
    ed = ev.get("event_data") or {}
    val = ed.get(field)
    if val is None:                      # some parsers lowercase keys
        val = ed.get(field.lower())
    return str(val or "").lower()


def _match_op(fv: str, op: str, value) -> bool:
    """Evaluate one condition: field_value <op> value."""
    if isinstance(value, list):
        vals = [str(v).lower() for v in value]
    else:
        vals = [str(value).lower()]
    if op in ("exact", "is_any"):
        return fv in vals
    if op in ("contains", "contains_any"):
        return any(v in fv for v in vals)
    if op in ("endswith", "endswith_any"):
        return any(fv.endswith(v) for v in vals)
    if op in ("startswith", "startswith_any"):
        return any(fv.startswith(v) for v in vals)
    return False


def _eval_block(ev: dict, block: dict) -> bool:
    """All conditions in *block* must hold (AND logic)."""
    for raw_key, value in block.items():
        field, op = _parse_key(raw_key)
        if not _match_op(_get_field(ev, field), op, value):
            return False
    return True


def _is_filtered(ev: dict, rule: dict) -> bool:
    """Return True if the event matches any filter block and should be excluded."""
    if rule.get("filter") and _eval_block(ev, rule["filter"]):
        return True
    for block in rule.get("filter_any") or []:
        if _eval_block(ev, block):
            return True
    return False


# ---------------------------------------------------------------------------
# Sigma-style rules
# Ordered from most-specific to least-specific within each event ID group so
# that deduplication (by tactic+tid) retains the highest-confidence tag.
# ---------------------------------------------------------------------------

_SIGMA_RULES: list[dict] = [

    # ═══════════════════════════════════════════════════════════════════════
    # 4624 — Logon (currently tagged T1078 for EVERY logon = extreme noise)
    # Split by LogonType so each subtype gets calibrated confidence.
    # ═══════════════════════════════════════════════════════════════════════

    # Service logons (Type 5) — constant background noise, suppress entirely
    {
        "name":      "Logon: Service Account (Type 5) — suppress",
        "selection": {"event_id": "4624", "LogonType": "5"},
        "condition": "selection",
        "tags":      [],   # explicit suppress
        "confidence": "low",
    },
    # Unlock (Type 7) — user unlocking workstation
    {
        "name":      "Logon: Workstation Unlock (Type 7) — suppress",
        "selection": {"event_id": "4624", "LogonType": "7"},
        "condition": "selection",
        "tags":      [],
        "confidence": "low",
    },
    # RDP logon (Type 10) — remote interactive, medium-high signal
    {
        "name":      "Logon: Remote Desktop Protocol (Type 10)",
        "selection": {"event_id": "4624", "LogonType": "10"},
        "filter_any": [
            {"TargetUserName_is_any": ["anonymous logon", "dwm-1", "dwm-2", "dwm-3"]},
        ],
        "condition": "selection and not filter",
        "tags": [
            {"tactic": "Initial Access",   "tid": "T1078",     "name": "Valid Accounts: RDP Logon"},
            {"tactic": "Lateral Movement", "tid": "T1021.001", "name": "Remote Services: Remote Desktop Protocol"},
        ],
        "confidence": "medium",
    },
    # Network logon (Type 3) — lateral movement candidate
    {
        "name":      "Logon: Network Logon (Type 3)",
        "selection": {"event_id": "4624", "LogonType": "3"},
        "filter_any": [
            {"TargetUserName_is_any": ["anonymous logon"]},
        ],
        "condition": "selection and not filter",
        "tags": [
            {"tactic": "Initial Access",   "tid": "T1078",   "name": "Valid Accounts: Network Logon"},
            {"tactic": "Lateral Movement", "tid": "T1021",   "name": "Remote Services: Network Logon"},
        ],
        "confidence": "medium",
    },
    # Batch logon (Type 4) — scheduled tasks, low signal
    {
        "name":      "Logon: Batch / Scheduled Task (Type 4)",
        "selection": {"event_id": "4624", "LogonType": "4"},
        "condition": "selection",
        "tags": [{"tactic": "Persistence", "tid": "T1053.005", "name": "Scheduled Task (Batch Logon)"}],
        "confidence": "low",
    },
    # Interactive logon (Type 2) — user at keyboard, low signal
    {
        "name":      "Logon: Interactive (Type 2)",
        "selection": {"event_id": "4624", "LogonType": "2"},
        "filter_any": [
            {"TargetUserName_is_any": [
                "anonymous logon", "dwm-1", "dwm-2", "dwm-3",
                "umfd-0", "umfd-1", "font driver host",
            ]},
            {"TargetUserName_endswith": "$"},   # machine accounts
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Initial Access", "tid": "T1078", "name": "Valid Accounts: Interactive Logon"}],
        "confidence": "low",
    },
    # Catch-all for other logon types (RemoteInteractive Type 11, NewCredentials Type 9…)
    {
        "name":      "Logon: Other Type",
        "selection": {"event_id": "4624"},
        "filter_any": [
            {"LogonType_is_any": ["2", "3", "4", "5", "7", "10"]},
            {"TargetUserName_endswith": "$"},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Initial Access", "tid": "T1078", "name": "Valid Accounts"}],
        "confidence": "low",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 4625 — Failed Logon  (differentiate severity by SubStatus)
    # ═══════════════════════════════════════════════════════════════════════

    # Account locked out — strong indicator of brute force
    {
        "name":      "Failed Logon: Account Locked Out (0xC0000234)",
        "selection": {"event_id": "4625", "SubStatus": "0xc0000234"},
        "condition": "selection",
        "tags": [{"tactic": "Credential Access", "tid": "T1110.001",
                  "name": "Brute Force: Password Guessing (Account Lockout)"}],
        "confidence": "high",
    },
    # Wrong password
    {
        "name":      "Failed Logon: Wrong Password",
        "selection": {
            "event_id": "4625",
            "SubStatus_is_any": ["0xc000006a", "0xc000006d"],
        },
        "condition": "selection",
        "tags": [{"tactic": "Credential Access", "tid": "T1110",
                  "name": "Brute Force: Failed Logon (Wrong Password)"}],
        "confidence": "medium",
    },
    # All other failed logon sub-statuses
    {
        "name":      "Failed Logon: Other",
        "selection": {"event_id": "4625"},
        "filter_any": [
            {"SubStatus_is_any": ["0xc000006a", "0xc000006d", "0xc0000234"]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Credential Access", "tid": "T1110",
                  "name": "Brute Force: Failed Logon"}],
        "confidence": "low",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 4672 — Special Privileges Assigned
    # Filter constant system-account noise; only flag real user accounts.
    # ═══════════════════════════════════════════════════════════════════════
    {
        "name":      "Special Privileges: Non-System Account",
        "selection": {"event_id": "4672"},
        "filter_any": [
            {"SubjectUserName_is_any": [
                "system", "local service", "network service",
                "window manager", "dwm-1", "dwm-2", "dwm-3",
                "umfd-0", "umfd-1", "font driver host",
            ]},
            {"SubjectUserName_endswith": "$"},   # machine accounts (e.g. DESKTOP-ABC$)
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Privilege Escalation", "tid": "T1134",
                  "name": "Access Token Manipulation: Special Privileges Assigned"}],
        "confidence": "medium",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 4688 — Process Creation (Security log)
    # Split by NewProcessName into specific sub-techniques; suppress noise.
    # ═══════════════════════════════════════════════════════════════════════

    # conhost.exe is always spawned alongside cmd.exe — explicitly suppress
    {
        "name":      "Process Create: conhost (suppress — cmd companion process)",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith": "\\conhost.exe",
        },
        "condition": "selection",
        "tags":      [],
        "confidence": "low",
    },
    # PowerShell — T1059.001
    {
        "name":      "Process Create: PowerShell",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith": "\\powershell.exe",
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.001",
                  "name": "Command and Scripting Interpreter: PowerShell"}],
        "confidence": "medium",
    },
    # Windows Command Shell — T1059.003 (lower confidence when user-initiated)
    {
        "name":      "Process Create: Command Shell (system-spawned)",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith": "\\cmd.exe",
        },
        "filter_any": [
            # User opened cmd from Explorer — expected behaviour, lower signal
            {"ParentProcessName_endswith_any": ["\\explorer.exe"]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Execution", "tid": "T1059.003",
                  "name": "Command and Scripting Interpreter: Windows Command Shell"}],
        "confidence": "medium",
    },
    {
        "name":      "Process Create: Command Shell (user-initiated from Explorer)",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith": "\\cmd.exe",
            "ParentProcessName_endswith": "\\explorer.exe",
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.003",
                  "name": "Command and Scripting Interpreter: Windows Command Shell"}],
        "confidence": "low",
    },
    # Script hosts — T1059.005
    {
        "name":      "Process Create: Script Host (WScript / CScript)",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith_any": ["\\wscript.exe", "\\cscript.exe"],
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.005",
                  "name": "Command and Scripting Interpreter: Visual Basic / Script Host"}],
        "confidence": "medium",
    },
    # mshta.exe — T1218.005
    {
        "name":      "Process Create: Mshta (LOLBin)",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith": "\\mshta.exe",
        },
        "condition": "selection",
        "tags": [{"tactic": "Defense Evasion", "tid": "T1218.005",
                  "name": "System Binary Proxy Execution: Mshta"}],
        "confidence": "medium",
    },
    # Suppress pure system-noise child processes (no signal)
    {
        "name":      "Process Create: System Noise (suppress)",
        "selection": {
            "event_id": "4688",
            "NewProcessName_endswith_any": [
                "\\svchost.exe", "\\dllhost.exe", "\\msiexec.exe",
                "\\spoolsv.exe", "\\wermgr.exe", "\\tiworker.exe",
                "\\taskhostw.exe", "\\taskhost.exe", "\\smss.exe",
                "\\csrss.exe", "\\winlogon.exe", "\\wininit.exe",
                "\\lsass.exe", "\\services.exe", "\\searchindexer.exe",
                "\\audiodg.exe", "\\dwm.exe",
            ],
        },
        "condition": "selection",
        "tags":      [],
        "confidence": "low",
    },
    # Catch-all for other 4688 events (not handled above)
    {
        "name":      "Process Create: Other Executable",
        "selection": {"event_id": "4688"},
        "filter_any": [
            {"NewProcessName_endswith_any": [
                "\\powershell.exe", "\\cmd.exe", "\\wscript.exe",
                "\\cscript.exe", "\\mshta.exe", "\\conhost.exe",
                "\\svchost.exe", "\\dllhost.exe", "\\msiexec.exe",
                "\\spoolsv.exe", "\\wermgr.exe", "\\tiworker.exe",
                "\\taskhostw.exe", "\\taskhost.exe", "\\smss.exe",
                "\\csrss.exe", "\\winlogon.exe", "\\wininit.exe",
                "\\lsass.exe", "\\services.exe", "\\searchindexer.exe",
                "\\audiodg.exe", "\\dwm.exe",
            ]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Execution", "tid": "T1059",
                  "name": "Command and Scripting Interpreter"}],
        "confidence": "low",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # Sysmon Event ID 1 — Process Creation (rich CommandLine + ParentImage)
    # Differentiated by CommandLine patterns for high-confidence detection.
    # ═══════════════════════════════════════════════════════════════════════

    # PowerShell with encoded command (-enc / -e / -encodedcommand)
    {
        "name":      "Sysmon: PowerShell Encoded Command",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith": "\\powershell.exe",
            "CommandLine_contains_any": ["-enc ", "-encodedcommand", " -e "],
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.001",
                  "name": "PowerShell: Encoded Command (Obfuscation Indicator)"}],
        "confidence": "high",
    },
    # PowerShell download cradle (WebClient / IWR / Invoke-WebRequest)
    {
        "name":      "Sysmon: PowerShell Download Cradle",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith": "\\powershell.exe",
            "CommandLine_contains_any": [
                "downloadstring", "downloadfile", "webclient",
                "invoke-webrequest", "iwr ", "system.net.webclient",
                "new-object net.", "curl ", "wget ",
            ],
        },
        "condition": "selection",
        "tags": [
            {"tactic": "Execution",          "tid": "T1059.001", "name": "PowerShell: Download Cradle"},
            {"tactic": "Command and Control", "tid": "T1105",     "name": "Ingress Tool Transfer"},
        ],
        "confidence": "high",
    },
    # PowerShell IEX / Invoke-Expression
    {
        "name":      "Sysmon: PowerShell Invoke-Expression",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith": "\\powershell.exe",
            "CommandLine_contains_any": [
                "iex(", "iex (", "| iex", "|iex",
                "invoke-expression",
            ],
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.001",
                  "name": "PowerShell: Invoke-Expression (Code Injection Indicator)"}],
        "confidence": "high",
    },
    # PowerShell bypass flags
    {
        "name":      "Sysmon: PowerShell ExecutionPolicy Bypass",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith": "\\powershell.exe",
            "CommandLine_contains_any": [
                "bypass", "-nop ", "-noprofile", "-windowstyle hidden",
                "-executionpolicy bypass",
            ],
        },
        "condition": "selection",
        "tags": [{"tactic": "Defense Evasion", "tid": "T1059.001",
                  "name": "PowerShell: Execution Policy Bypass / Hidden Window"}],
        "confidence": "medium",
    },
    # PowerShell generic (no suspicious CommandLine pattern)
    {
        "name":      "Sysmon: PowerShell Generic",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith": "\\powershell.exe",
        },
        "filter_any": [
            {"CommandLine_contains_any": [
                "-enc ", "-encodedcommand", " -e ",
                "downloadstring", "downloadfile", "webclient",
                "invoke-webrequest", "iwr ",
                "iex(", "iex (", "| iex", "invoke-expression",
                "bypass", "-nop ", "-noprofile",
            ]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Execution", "tid": "T1059.001",
                  "name": "Command and Scripting Interpreter: PowerShell"}],
        "confidence": "medium",
    },
    # Sysmon: cmd.exe
    {
        "name":      "Sysmon: Windows Command Shell",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith": "\\cmd.exe",
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.003",
                  "name": "Command and Scripting Interpreter: Windows Command Shell"}],
        "confidence": "medium",
    },
    # Sysmon: Script hosts
    {
        "name":      "Sysmon: Script Host (WScript / CScript)",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
            "Image_endswith_any": ["\\wscript.exe", "\\cscript.exe"],
        },
        "condition": "selection",
        "tags": [{"tactic": "Execution", "tid": "T1059.005",
                  "name": "Command and Scripting Interpreter: Visual Basic / Script Host"}],
        "confidence": "medium",
    },
    # Sysmon: Generic process (not one of the above)
    {
        "name":      "Sysmon: Generic Process Create",
        "selection": {
            "event_id": "1",
            "channel_contains": "sysmon",
        },
        "filter_any": [
            {"Image_endswith_any": [
                "\\powershell.exe", "\\cmd.exe",
                "\\wscript.exe", "\\cscript.exe",
                "\\conhost.exe", "\\svchost.exe",
            ]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Execution", "tid": "T1059",
                  "name": "Command and Scripting Interpreter"}],
        "confidence": "low",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 4663 — Object Access
    # Without path filtering this fires on every file read. Only tag when
    # the object is a sensitive credential store / hive.
    # ═══════════════════════════════════════════════════════════════════════
    {
        "name":      "Object Access: Credential Store / LSASS / NTDS",
        "selection": {
            "event_id": "4663",
            "ObjectName_contains_any": [
                "\\sam\\sam", "\\security\\sam", "\\system\\sam",
                "lsass.exe", "ntds.dit", "\\ntds\\",
                "system.sav", "security.sav", "sam.sav",
                "\\lsa\\",
            ],
        },
        "condition": "selection",
        "tags": [{"tactic": "Credential Access", "tid": "T1003.001",
                  "name": "OS Credential Dumping: LSASS / SAM / NTDS Access"}],
        "confidence": "high",
    },
    # All other 4663 events — suppress (too noisy, file access = universal)
    {
        "name":      "Object Access: Generic (suppress — too noisy without path filter)",
        "selection": {"event_id": "4663"},
        "filter_any": [
            {"ObjectName_contains_any": [
                "\\sam\\sam", "\\security\\sam", "lsass.exe", "ntds.dit",
            ]},
        ],
        "condition": "selection and not filter",
        "tags":      [],
        "confidence": "low",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 7045 — New Service Installed
    # Two mutually exclusive buckets based on ImagePath location:
    #   • Windows/system path → LOW  (unsigned third-party software can still
    #     install under C:\Windows but it's less likely to be malware)
    #   • Non-system path    → HIGH (temp dirs, user dirs, unusual locations)
    # ═══════════════════════════════════════════════════════════════════════

    # Service installed from a Windows or Program Files system directory
    {
        "name":      "New Service: System Path (low confidence)",
        "selection": {
            "event_id": "7045",
            "ImagePath_startswith_any": [
                "c:\\windows\\", "%systemroot%\\", "%windir%\\",
                "c:\\program files\\", "c:\\program files (x86)\\",
            ],
        },
        "condition": "selection",
        "tags": [{"tactic": "Persistence", "tid": "T1543.003",
                  "name": "Create or Modify System Process: Windows Service (System Path)"}],
        "confidence": "low",
    },
    # Service installed from outside the system directories — high suspicion
    {
        "name":      "New Service: Non-System Path (high confidence)",
        "selection": {"event_id": "7045"},
        "filter_any": [
            {"ImagePath_startswith_any": [
                "c:\\windows\\", "%systemroot%\\", "%windir%\\",
                "c:\\program files\\", "c:\\program files (x86)\\",
            ]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Persistence", "tid": "T1543.003",
                  "name": "Create or Modify System Process: Windows Service (Non-System Path)"}],
        "confidence": "high",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 5140 / 5145 — Network Share Access
    # Admin shares (ADMIN$, C$, IPC$) = lateral movement; others = low
    # ═══════════════════════════════════════════════════════════════════════
    {
        "name":      "Network Share: Admin Share Access (lateral movement)",
        "selection": {
            "event_id_is_any": ["5140", "5145"],
            "ShareName_endswith_any": ["\\admin$", "\\c$", "\\d$", "\\e$", "\\ipc$"],
        },
        "condition": "selection",
        "tags": [{"tactic": "Lateral Movement", "tid": "T1021.002",
                  "name": "Remote Services: SMB/Windows Admin Shares"}],
        "confidence": "medium",
    },
    {
        "name":      "Network Share: Non-Admin Share (low signal)",
        "selection": {"event_id_is_any": ["5140", "5145"]},
        "filter_any": [
            {"ShareName_endswith_any": ["\\admin$", "\\c$", "\\d$", "\\e$", "\\ipc$"]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Lateral Movement", "tid": "T1039",
                  "name": "Data from Network Shared Drive"}],
        "confidence": "low",
    },

    # ═══════════════════════════════════════════════════════════════════════
    # 4769 — Kerberos Service Ticket Request (Kerberoasting)
    # RC4 encryption type (0x17) = strong kerberoasting indicator
    # ═══════════════════════════════════════════════════════════════════════
    {
        "name":      "Kerberoasting: Weak Encryption Type (RC4)",
        "selection": {
            "event_id": "4769",
            "TicketEncryptionType_is_any": ["0x17", "0x18", "23", "24"],
        },
        "filter_any": [
            {"ServiceName_endswith": "$"},   # machine account TGT requests
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Credential Access", "tid": "T1558.003",
                  "name": "Kerberoasting: RC4 Encryption (High-Confidence Indicator)"}],
        "confidence": "high",
    },
    {
        "name":      "Kerberoasting: Strong Encryption",
        "selection": {"event_id": "4769"},
        "filter_any": [
            {"ServiceName_endswith": "$"},
            {"TicketEncryptionType_is_any": ["0x17", "0x18", "23", "24"]},
        ],
        "condition": "selection and not filter",
        "tags": [{"tactic": "Credential Access", "tid": "T1558.003",
                  "name": "Steal or Forge Kerberos Tickets: Kerberoasting"}],
        "confidence": "medium",
    },
]


# ---------------------------------------------------------------------------
# Covered event IDs — derived from the rules above at import time.
# Events with these IDs are handled exclusively by sigma rules; the static
# ATTACK_MAP is NOT consulted for them.
# ---------------------------------------------------------------------------

def _build_covered_eids() -> frozenset[str]:
    covered: set[str] = set()
    for rule in _SIGMA_RULES:
        sel = rule.get("selection", {})
        if "event_id" in sel:
            covered.add(str(sel["event_id"]))
        if "event_id_is_any" in sel:
            for eid in sel["event_id_is_any"]:
                covered.add(str(eid))
    return frozenset(covered)


_SIGMA_COVERED_EIDS: frozenset[str] = _build_covered_eids()

# Confidence ranking for deduplication
_CONF_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_sigma_tags(ev: dict) -> list[dict] | None:
    """
    Evaluate all sigma rules against *ev*.

    Returns a (possibly empty) list of ATT&CK tag dicts if this event's ID is
    covered by at least one sigma rule — even if all rules are filtered out.

    Returns None if no sigma rule is registered for this event_id, signalling
    the caller to fall back to the static ATTACK_MAP.
    """
    eid_str = str(ev.get("event_id", ""))
    if eid_str not in _SIGMA_COVERED_EIDS:
        return None

    collected: list[dict] = []
    any_selection_matched = False

    for rule in _SIGMA_RULES:
        if not _eval_block(ev, rule["selection"]):
            continue
        any_selection_matched = True

        cond = rule.get("condition", "selection")
        if "not filter" in cond and _is_filtered(ev, rule):
            continue

        conf = rule.get("confidence", "medium")
        for base_tag in rule.get("tags") or []:
            tag = dict(base_tag)
            tag["attack_confidence"] = conf
            collected.append(tag)

    if not any_selection_matched:
        # No rule's selection matched — caller falls back to ATTACK_MAP
        return None

    # Deduplicate by (tactic, tid): keep the highest-confidence entry
    best: dict[tuple[str, str], dict] = {}
    for tag in collected:
        key = (tag.get("tactic", ""), tag.get("tid", ""))
        existing = best.get(key)
        if existing is None:
            best[key] = tag
        elif _CONF_RANK.get(tag["attack_confidence"], 0) > _CONF_RANK.get(
                existing["attack_confidence"], 0):
            best[key] = tag

    return list(best.values())
