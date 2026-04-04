"""
PowerShell forensic extraction — constants.

Channel names, relevant event IDs, safety-net keyword patterns,
and MITRE ATT&CK technique mappings.
"""

from __future__ import annotations

# ── Channel names (exact values as recorded in System.Channel) ────────────────

PS_OPERATIONAL_CHANNELS: frozenset[str] = frozenset({
    "Microsoft-Windows-PowerShell/Operational",   # PS 5.1 scripting events
    "PowerShellCore/Operational",                  # PS Core 6/7 scripting events
})
PS_CLASSIC_CHANNEL = "Windows PowerShell"         # PS 5.1 engine lifecycle events
ALL_PS_CHANNELS: frozenset[str] = PS_OPERATIONAL_CHANNELS | frozenset({PS_CLASSIC_CHANNEL})

# ── Event IDs we care about ───────────────────────────────────────────────────

RELEVANT_EVENT_IDS: frozenset[int] = frozenset({4103, 4104, 400, 403, 600, 800})

# ── Safety-net auto-logging keyword patterns ──────────────────────────────────
# Derived from PowerShell source (CompiledScriptBlock.cs) and public MS research.
# Used for case-insensitive substring matching against ScriptBlockText content.

SAFETY_NET_PATTERNS: list[str] = [
    # Encoded command execution
    "-EncodedCommand",
    "-enc ",
    "-ec ",
    "EncodedCommand",

    # Invocation techniques
    "Invoke-Expression",
    "IEX(",
    "IEX ",
    "&{",
    ".()",

    # Download cradles
    "DownloadString",
    "DownloadFile",
    "Net.WebClient",
    "System.Net.WebClient",
    "WebRequest",
    "Invoke-WebRequest",
    "curl ",
    "wget ",
    "Net.Http.HttpClient",
    "BitsTransfer",
    "Start-BitsTransfer",

    # Reflection / dynamic loading
    "Reflection.Assembly",
    "[Reflection.Assembly]",
    "Assembly.Load",
    "Assembly.LoadFrom",
    "[System.Reflection",

    # Process / shellcode injection
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateThread",
    "OpenProcess",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "RtlMoveMemory",
    "memset(",

    # AMSI bypass
    "AmsiScanBuffer",
    "AmsiInitialize",
    "amsiInitFailed",
    "amsi.dll",
    "AMSI",

    # COM objects
    "New-Object -ComObject",
    "New-Object -Com",
    "CreateObject(",
    "Activator.CreateInstance",

    # WMI
    "wmic ",
    "Get-WMIObject",
    "Get-CimInstance",
    "Win32_Process",

    # Credential access
    "sekurlsa",
    "lsadump",
    "Mimikatz",
    "privilege::debug",
    "Net.NetworkCredential",
    "ConvertTo-SecureString",
    "PSCredential",

    # Obfuscation indicators (bare backtick removed — fires on all line-continuation; use content_analysis.py regex instead)
    "char(",
    "[char]",
    "[convert]::ToBase64String",
    "[convert]::FromBase64String",
    "[System.Convert]",
    "Base64",
    "FromBase64",
    "ToBase64",
    "-join",
    "-split",

    # Known attack tooling
    "PowerSploit",
    "PowerView",
    "Invoke-Mimikatz",
    "Invoke-Shellcode",
    "Invoke-ReflectivePEInjection",
    "Get-GPPPassword",
    "Invoke-Kerberoast",
    "Invoke-BloodHound",

    # Registry / persistence
    "HKLM:",
    "HKCU:",
    "New-ItemProperty",
    "Set-ItemProperty",
    "reg.exe",
    "New-ScheduledTask",
    "Register-ScheduledTask",
    "schtasks",

    # Remoting / lateral movement
    "Invoke-Command",
    "New-PSSession",
    "Enter-PSSession",

    # Execution policy bypass
    "Set-ExecutionPolicy",
    "Bypass",
    "-ExecutionPolicy Bypass",
    "Unrestricted",

    # Network sockets
    "System.Net.Sockets",
    "TCPClient",
    "UDPClient",
    "System.IO.Pipes",

    # Add-Type C# compilation (bypasses script-level detection)
    "Add-Type",
    "DllImport",
    "kernel32",
    "GetProcAddress",
]


# ── MITRE ATT&CK technique mappings ──────────────────────────────────────────

ATT_CK_MAP: dict[str, str] = {
    "has_encoded_commands":      "T1059.001",   # PowerShell
    "has_download_cradle":       "T1105",        # Ingress Tool Transfer
    "has_amsi_bypass":           "T1562.001",    # Disable Security Tools
    "has_reflection":            "T1620",        # Reflective Code Loading
    "has_process_injection":     "T1055",        # Process Injection
    "has_credential_access":     "T1003",        # OS Credential Dumping
    "has_com_objects":           "T1559.001",    # Component Object Model
    "has_wmi_abuse":             "T1047",        # WMI
    "has_persistence_mechanism": "T1053.005",    # Scheduled Task/Job
    "has_lateral_movement":      "T1021.006",    # WinRM
    "has_obfuscation":           "T1027",        # Obfuscated Files or Info
}

# ── Zero GUID (degenerate ScriptBlockId) ─────────────────────────────────────
ZERO_GUID = "00000000-0000-0000-0000-000000000000"

# ── Known high-risk providers (loaded via EID 600) ───────────────────────────
NOTABLE_PROVIDERS: frozenset[str] = frozenset({
    "Certificate",   # cert store access — key theft / rogue root CA
    "WSMan",         # WinRM / remote management
    "ActiveDirectory",
})
