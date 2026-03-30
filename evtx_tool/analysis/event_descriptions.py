"""
event_descriptions.py
─────────────────────
Human-readable, context-aware one-liner descriptions for common Windows
event IDs.  Used exclusively by the GUI's Brief detail panel.

get_event_description(ev) → str | None
    Returns a plain-text sentence explaining what the event represents,
    enriched with sub-condition details (logon type, sub-status, process
    name, service name, etc.) where available.
    Returns None for unknown / uncommon event IDs so the panel stays clean.
"""

from __future__ import annotations

import os

# ── helpers ───────────────────────────────────────────────────────────────

def _ed(ev: dict) -> dict:
    """Return event_data dict (always a dict, never None)."""
    return ev.get("event_data") or {}


def _f(ed: dict, *keys: str) -> str:
    """
    Case-insensitive field fetch from event_data.
    Tries each key as-is, then lowercase.  Returns '' if not found.
    """
    for k in keys:
        v = ed.get(k) or ed.get(k.lower())
        if v is not None:
            s = str(v).strip()
            if s:
                return s
    return ""


def _basename(path: str) -> str:
    """Return lowercase filename portion of a Windows/POSIX path."""
    if not path:
        return ""
    return os.path.basename(path.replace("\\", "/")).lower()


def _provider(ev: dict) -> str:
    return (ev.get("provider") or "").lower()


def _channel(ev: dict) -> str:
    return (ev.get("channel") or "").lower()


def _is_sysmon(ev: dict) -> bool:
    return "sysmon" in _provider(ev)


def _is_powershell(ev: dict) -> bool:
    p = _provider(ev)
    return "powershell" in p


def _is_tasksched(ev: dict) -> bool:
    p = _provider(ev)
    return "taskscheduler" in p or "task scheduler" in p


def _is_rdp_local(ev: dict) -> bool:
    p = _provider(ev)
    return "terminalservices-localsessionmanager" in p


def _is_rdp_remote(ev: dict) -> bool:
    p = _provider(ev)
    return "terminalservices-remoteconnectionmanager" in p or "terminalservices-gateway" in p


# ── Logon type tables ─────────────────────────────────────────────────────

_LOGON_TYPE_LABEL: dict[str, str] = {
    "2":  "Interactive",
    "3":  "Network",
    "4":  "Batch",
    "5":  "Service",
    "7":  "Unlock",
    "8":  "NetworkCleartext",
    "9":  "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
    "12": "CachedRemoteInteractive",
    "13": "CachedUnlock",
}

_LOGON_TYPE_DESC: dict[str, str] = {
    "2":  "Generated when a user logs on locally at the keyboard or console "
          "(interactive session).",
    "3":  "Generated when a user or computer authenticates over the network — "
          "typical for SMB file-share access, IIS with Windows authentication, "
          "or net use connections.",
    "4":  "Generated when a scheduled task (batch job) runs under a stored "
          "account. Routine on most systems.",
    "5":  "Generated when a Windows service starts under a service account. "
          "Very common and normally benign.",
    "7":  "Generated when a previously locked workstation is unlocked by the "
          "original user.",
    "8":  "Generated when credentials are passed in cleartext, such as via "
          "IIS basic authentication. Flag if unexpected.",
    "9":  "Generated when a process is launched with RunAs /netonly — "
          "alternate credentials are used only for outbound network access; "
          "local context is unchanged.",
    "10": "Generated when a user establishes a Remote Desktop (RDP) or "
          "Terminal Services session from a remote machine.",
    "11": "Generated when a user logs on using cached domain credentials "
          "because the domain controller is unreachable.",
    "12": "Generated when a user connects remotely using cached credentials.",
    "13": "Generated when cached credentials are used to unlock a workstation.",
}

# ── 4625 sub-status messages ──────────────────────────────────────────────

_SUBSTATUS_DESC: dict[str, str] = {
    "0xc0000064": "User account does not exist in the directory.",
    "0xc000006a": "Incorrect password supplied for a valid account.",
    "0xc000006d": "Authentication failed — bad username or password.",
    "0xc000006e": "Account restriction — logon policy prevents this logon.",
    "0xc000006f": "Logon attempt is outside the account's permitted hours.",
    "0xc0000070": "Logon attempt is from an unauthorised workstation.",
    "0xc0000071": "Password has expired and must be changed before logon.",
    "0xc0000072": "Account is currently disabled.",
    "0xc0000133": "Clock skew too large; Kerberos requires clocks within 5 minutes.",
    "0xc000015b": "Account has not been granted the requested logon type on "
                  "this machine.",
    "0xc0000193": "Account has expired.",
    "0xc0000224": "User must change password at next logon.",
    "0xc0000234": "Account is currently locked out.",
}

# ── 4769 encryption types ─────────────────────────────────────────────────

_KRB_ENC: dict[str, str] = {
    "0x1":  "DES-CBC-CRC (very weak)",
    "0x3":  "DES-CBC-MD5 (weak)",
    "0x11": "AES128-CTS-HMAC-SHA1-96",
    "0x12": "AES256-CTS-HMAC-SHA1-96 (strong)",
    "0x17": "RC4-HMAC (weak — common Kerberoasting target)",
    "0x18": "RC4-HMAC-EXP (very weak — Kerberoasting target)",
    "0x1a": "AES256-CTS-HMAC-SHA384-192",
}

# ── 4768 / 4776 result codes ──────────────────────────────────────────────

_KRB_RESULT: dict[str, str] = {
    "0x0":  "Success",
    "0x6":  "User not found in the KDC database.",
    "0x7":  "Server not found in the KDC database.",
    "0xc":  "Policy restriction — logon denied by policy.",
    "0x12": "Account disabled, expired, or locked out.",
    "0x17": "Password has expired.",
    "0x18": "Incorrect pre-authentication data (wrong password).",
    "0x25": "Clock skew too large.",
}

# ── Sysmon event labels ───────────────────────────────────────────────────

_SYSMON_DESC: dict[int, str] = {
    1:  "A new process was created. Records image path, command line, "
        "and parent process to help trace execution chains.",
    2:  "A process changed a file's creation timestamp. Can indicate "
        "timestomping (anti-forensic technique).",
    3:  "A network connection was initiated by a process. Logs source and "
        "destination IP/port and process name.",
    4:  "The Sysmon service state changed (started or stopped).",
    5:  "A process terminated. Records image path and process ID.",
    6:  "A device driver (kernel module) was loaded. Unsigned drivers "
        "are flagged as particularly suspicious.",
    7:  "A DLL or executable image was loaded into a process.",
    8:  "A process created a remote thread in another process — common "
        "technique for code injection (e.g. DLL injection).",
    9:  "A process used \\Device\\PhysicalDisk raw disk access, "
        "potentially bypassing the file system for credential dumping.",
    10: "A process opened a handle to another process with access rights "
        "that could allow memory reading or injection (e.g. lsass dump).",
    11: "A file was created or overwritten. Captures creation of new "
        "executables, scripts, and documents.",
    12: "A registry key or value was created or deleted.",
    13: "A registry value was modified.",
    14: "A registry key or value was renamed.",
    15: "A file stream (ADS) was created — alternate data streams can "
        "be used to hide payloads.",
    16: "Sysmon configuration was changed.",
    17: "A named pipe was created by a process.",
    18: "A process connected to a named pipe — used by many lateral "
        "movement techniques (PSExec, SMB named-pipe channels).",
    19: "A WMI event filter was registered — used in WMI persistence.",
    20: "A WMI event consumer was registered — used in WMI persistence.",
    21: "A WMI consumer-to-filter binding was created — completes WMI "
        "persistence setup.",
    22: "A DNS query was made by a process. Helps detect C2 beaconing "
        "and domain generation algorithm (DGA) traffic.",
    23: "A file was deleted. If combined with process info, can indicate "
        "cleanup after malware execution.",
    24: "Contents were added to the clipboard — may capture credentials "
        "or sensitive data.",
    25: "Process image was tampered with (hollowed or replaced in memory).",
    26: "A file deletion was detected and the file was saved to the "
        "Sysmon archive before removal.",
    27: "Execution of a file was blocked because it is an executable.",
    28: "Execution was blocked because the file matched a shredding rule.",
    29: "Kerberos pre-authentication failed for a Sysmon-monitored host.",
}

# ── PowerShell event labels (Microsoft-Windows-PowerShell / Windows PowerShell) ──

_PS_DESC: dict[int, str] = {
    # Classic "Windows PowerShell" event log
    400:   "PowerShell engine started. Records host application and version. "
           "Indicates a PowerShell session was opened.",
    403:   "PowerShell engine stopped. Paired with EID 400 to bracket a "
           "complete PowerShell session.",
    500:   "PowerShell provider started (e.g. Registry, FileSystem, Alias).",
    501:   "PowerShell provider stopped.",
    600:   "PowerShell provider lifecycle event — records provider start/stop.",
    800:   "PowerShell pipeline execution details. Records the command "
           "pipeline and its parameters for the session.",
    # Microsoft-Windows-PowerShell/Operational
    4100:  "PowerShell execution error. An error occurred during pipeline "
           "execution; records the error message and script name.",
    4103:  "PowerShell module logging. Captures the full output and input "
           "of a module pipeline execution (requires module logging GPO).",
    4104:  "PowerShell script block logging. Records the full content of "
           "every script block executed (requires ScriptBlock logging GPO). "
           "Critical for detecting obfuscated/encoded payloads.",
    4105:  "PowerShell script block invocation started — marks the beginning "
           "of a tracked script block execution.",
    4106:  "PowerShell script block invocation completed — paired with 4105.",
    53504: "PowerShell script block logging event (older format). Full script "
           "content is recorded for forensic review.",
}

# ── Task Scheduler event labels (Microsoft-Windows-TaskScheduler/Operational) ──

_TASKSCHED_DESC: dict[int, str] = {
    100:  "Task started. The task was launched by the scheduler.",
    101:  "Task failed to start. The scheduler attempted to launch the task "
          "but the process could not be created.",
    102:  "Task completed. Records the result code of the task action.",
    103:  "Task action failed. An individual action within the task returned "
          "a non-zero exit code.",
    104:  "Task did not run because the trigger condition was not met "
          "(e.g. idle condition, battery condition).",
    106:  "Task registered. A new scheduled task was added to the task "
          "store — common persistence mechanism.",
    107:  "Task triggered on schedule. The time-based trigger fired and "
          "initiated task execution.",
    108:  "Task triggered by event. The task's event-based trigger fired.",
    109:  "Task triggered by user request. The task was run on demand.",
    110:  "Task engine received and queued a request to start the task.",
    111:  "Task stopped. The task was manually or programmatically terminated.",
    119:  "Task triggered by user (RunAs). Task launched under alternate "
          "credentials.",
    129:  "Task process launched. Records the PID of the launched process.",
    140:  "Task registration updated. An existing task definition was modified "
          "— check for altered triggers or actions.",
    141:  "Task registration deleted. A scheduled task was removed from the "
          "task store.",
    142:  "Task launch failed because the task is disabled.",
    200:  "Task action started. An individual action within a task began "
          "execution (e.g. a process launch or COM handler invocation).",
    201:  "Task action completed. Records the result code of the action.",
    202:  "Task action failed to complete successfully.",
    325:  "Task scheduler queued a new instance of the task for launch.",
    327:  "Task instance stopped by the scheduler (e.g. max runtime exceeded).",
    329:  "Task could not start — a pre-condition failed (e.g. user not logged "
          "on, network unavailable).",
    331:  "Task will not run because the security token could not be created.",
}

# ── RDP / Terminal Services labels ────────────────────────────────────────

# LocalSessionManager/Operational
_RDP_LOCAL_DESC: dict[int, str] = {
    21:  "Remote Desktop session logon succeeded. A user successfully "
         "authenticated and a session was created.",
    22:  "Shell start notification received for the RDP session — the user "
         "profile and desktop are being loaded.",
    23:  "Remote Desktop session logoff. The user explicitly ended the "
         "RDP session.",
    24:  "Remote Desktop session disconnected. The session was paused but "
         "not logged off — it remains active on the server.",
    25:  "Remote Desktop session reconnection succeeded. A previously "
         "disconnected session was resumed by the user.",
    39:  "Remote Desktop session X was disconnected by session Y. One "
         "user's session disconnected another (administrative action).",
    40:  "Remote Desktop session ended due to a reason reported by the "
         "server (idle timeout, administrator disconnect, etc.).",
}

# RemoteConnectionManager/Operational
_RDP_REMOTE_DESC: dict[int, str] = {
    65:   "Remote Desktop TCP connection accepted. A client successfully "
          "established a TCP connection to the RD listener.",
    66:   "Remote Desktop UDP connection accepted. A client connected via "
          "the UDP transport for improved performance.",
    102:  "Remote Desktop session deleted from the connection manager.",
    103:  "Remote Desktop connection failed — records the reason code.",
    131:  "Remote Desktop connection made from IP address. Records the "
          "source IP of the incoming connection attempt.",
    140:  "Remote Desktop authentication failed. The client could not "
          "authenticate (wrong credentials or NLA rejection).",
    141:  "Remote Desktop listener ended — the listening service stopped "
          "accepting new connections.",
    142:  "Remote Desktop connection was rejected because the session "
          "limit was reached.",
    1149: "Remote Desktop Services: User authentication succeeded. The "
          "client passed Network Level Authentication (NLA). Records "
          "username and source IP — useful for lateral movement detection.",
}

# ── Generic Security event descriptions ──────────────────────────────────

_GENERIC_DESC: dict[int, str] = {
    # ── Logon / Session ──────────────────────────────────────────────
    4634: "Generated when a logon session is terminated and the user logs "
          "off. Paired with a prior 4624 logon event.",
    4647: "Generated when a user explicitly initiates a logoff (Start → "
          "Sign out). More reliable than 4634 for interactive sessions.",
    4648: "Generated when a process or user authenticates using explicit "
          "credentials (e.g. RunAs, net use with /user, or WMI with "
          "alternate credentials).",
    4649: "Generated when a replay attack is detected — an authentication "
          "request used a credential that was previously captured.",
    4626: "Contains user and device claims associated with a 4624 logon event. "
          "Claims are evaluated by Dynamic Access Control (DAC) policies.",
    4627: "Contains supplemental group membership information for a 4624 logon "
          "event, generated when the token is too large to embed inline.",
    4778: "Generated when a disconnected Remote Desktop session is "
          "reconnected by the original user.",
    4779: "Generated when a Remote Desktop session is disconnected without "
          "the user logging off.",
    4800: "Generated when the workstation screen is locked (Win+L or "
          "screensaver). Paired with 4801 on unlock.",
    4801: "Generated when a locked workstation screen is unlocked.",
    4802: "Generated when a screensaver starts on the workstation.",
    4803: "Generated when the screensaver is dismissed and the desktop "
          "is returned to the user.",

    # ── Privilege / Token ────────────────────────────────────────────
    4672: "Generated when an account with administrative or sensitive "
          "privileges (SeDebugPrivilege, SeTcbPrivilege, etc.) logs on. "
          "Indicates a privileged session is now active.",
    4673: "Generated when a privileged service is called by a thread — "
          "records the specific privilege used (e.g. SeTakeOwnershipPrivilege).",
    4674: "Generated when an operation on a privileged object is attempted "
          "— records whether the privilege use succeeded or failed.",
    4703: "Generated when a user-rights token privilege is enabled or "
          "disabled during a process (e.g. SeDebugPrivilege being adjusted).",
    4704: "Generated when a user right (logon right or privilege) is "
          "assigned to an account.",
    4705: "Generated when a user right (privilege) is removed from an account.",
    4696: "Generated when a primary token is assigned to a process — "
          "typical at process creation when the user context is established.",
    4675: "Generated when SIDs were filtered during a cross-forest or "
          "cross-trust logon, preventing token bloat or privilege carry-over.",

    # ── Process ──────────────────────────────────────────────────────
    4689: "Generated when a process exits. Records the exit code and "
          "process name. Paired with a prior 4688 creation event.",
    # Legacy Windows 2000 process events (Security log)
    577:  "Privileged service called (legacy Security log format, "
          "superseded by 4673 on Vista+).",
    592:  "A new process was created (legacy Security log format, "
          "superseded by 4688 on Vista+).",
    593:  "A process exited (legacy Security log format, "
          "superseded by 4689 on Vista+).",

    # ── Account Management ───────────────────────────────────────────
    4720: "Generated when a new user account is created in the local SAM "
          "or Active Directory. Records creator and new account name.",
    4722: "Generated when a user account is enabled — e.g. after it was "
          "disabled for policy or administrative reasons.",
    4723: "Generated when a user attempts to change their own password. "
          "Result (success/failure) is recorded in the event.",
    4724: "Generated when an administrator resets another user's password. "
          "High-value: unexpected resets can indicate account takeover.",
    4725: "Generated when a user account is disabled by an administrator.",
    4726: "Generated when a user account is permanently deleted from the "
          "SAM or Active Directory.",
    4727: "Generated when a security-enabled (not distribution) global "
          "group is created in Active Directory.",
    4728: "Generated when a member is added to a security-enabled global "
          "group (e.g. Domain Admins). High-value privilege escalation "
          "indicator.",
    4729: "Generated when a member is removed from a security-enabled "
          "global group.",
    4730: "Generated when a security-enabled global group is deleted.",
    4731: "Generated when a security-enabled local group is created on "
          "this machine or in AD.",
    4732: "Generated when a member is added to a security-enabled local "
          "group (e.g. Administrators). Monitor for unexpected additions.",
    4733: "Generated when a member is removed from a security-enabled "
          "local group.",
    4734: "Generated when a security-enabled local group is deleted.",
    4735: "Generated when a security-enabled local group's attributes are "
          "changed (description, name, scope).",
    4737: "Generated when a security-enabled global group's attributes are "
          "changed.",
    4738: "Generated when a user account's properties are changed — "
          "includes password-never-expires, disabled, logon hours, etc.",
    4740: "Generated when a user account is automatically locked out due "
          "to repeated failed logon attempts. Common indicator of "
          "brute-force or credential spray.",
    4741: "Generated when a new computer account is created in Active "
          "Directory (machine join or manual creation).",
    4742: "Generated when a computer account's properties are changed.",
    4743: "Generated when a computer account is deleted from Active "
          "Directory.",
    4744: "Generated when a distribution (non-security) local group is "
          "created. Distribution groups do not affect access control.",
    4745: "Generated when a distribution local group's attributes are changed.",
    4746: "Generated when a member is added to a distribution local group.",
    4747: "Generated when a member is removed from a distribution local group.",
    4748: "Generated when a distribution local group is deleted.",
    4749: "Generated when a distribution global group is created.",
    4750: "Generated when a distribution global group's attributes are changed.",
    4751: "Generated when a member is added to a distribution global group.",
    4752: "Generated when a member is removed from a distribution global group.",
    4753: "Generated when a distribution global group is deleted.",
    4754: "Generated when a security-enabled universal group is created in AD.",
    4755: "Generated when a security-enabled universal group's attributes "
          "are changed.",
    4756: "Generated when a member is added to a security-enabled universal "
          "group (e.g. Enterprise Admins). High-value escalation indicator.",
    4757: "Generated when a member is removed from a security-enabled "
          "universal group.",
    4758: "Generated when a security-enabled universal group is deleted.",
    4764: "Generated when a group's type is changed — e.g. from distribution "
          "to security-enabled, or from local to global scope.",
    4765: "Generated when SID History is added to an account. SID History "
          "is used for account migration; misuse enables privilege escalation.",
    4766: "Generated when an attempt to add SID History to an account failed.",
    4767: "Generated when a locked user account is manually unlocked by "
          "an administrator.",
    4781: "Generated when an account's name (sAMAccountName or UPN) is "
          "changed.",
    4782: "Generated when the password hash of an account was accessed — "
          "may indicate a password extraction or DCSync-style attack.",
    4793: "Generated when the Password Policy Checking API was called — "
          "tools enumerating the password policy to craft conformant passwords.",
    4798: "Generated when a local user's group membership is enumerated — "
          "can indicate reconnaissance (whoami /groups, net user).",
    4799: "Generated when a local group's membership is enumerated. "
          "Typical during post-exploitation discovery.",

    # ── Object Access ────────────────────────────────────────────────
    4656: "Generated when a handle to an object (file, registry key, "
          "mutex) is requested with specific access rights. Precedes "
          "4663 if the handle is granted.",
    4657: "Generated when a registry value is modified. Recorded only "
          "when SACL auditing is enabled on the key.",
    4658: "Generated when an open object handle is closed.",
    4660: "Generated when an audited object (file or registry key) is "
          "deleted. Paired with the preceding 4656 handle open.",
    4670: "Generated when the permissions (DACL/SACL) on an object are "
          "changed. Indicates privilege escalation or tamper attempts.",
    4907: "Generated when the audit policy (SACL) on an object is changed "
          "— modifying what access events are logged for that object.",

    # ── Policy / Audit ───────────────────────────────────────────────
    4616: "Generated when the system clock is changed. Unexpected changes "
          "can break Kerberos authentication or obscure a timeline.",
    4618: "Generated when a monitored security event pattern (defined in "
          "audit policy) is detected.",
    4646: "Generated when IKE denial-of-service prevention mode started "
          "due to excessive Main Mode negotiation requests.",
    4650: "Generated when an IPsec Main Mode security association was "
          "established using a pre-shared key.",
    4651: "Generated when an IPsec Main Mode security association was "
          "established using a certificate.",
    4713: "Generated when Kerberos policy settings are changed on the "
          "domain controller — e.g. ticket lifetime or clock skew tolerance.",
    4714: "Generated when the data recovery agent policy for EFS is changed.",
    4719: "Generated when the system-level audit policy is changed — "
          "e.g. disabling process creation logging. High-value tamper "
          "indicator.",
    4817: "Generated when auditing settings on an object are changed.",
    4820: "Generated when a Kerberos TGT was denied because the device "
          "does not meet the access control restrictions.",
    4821: "Generated when Kerberos service ticket access was denied because "
          "the device does not meet access control restrictions.",
    4822: "Generated when NTLM authentication was denied because the user "
          "is a member of the Protected Users group (Kerberos required).",
    4823: "Generated when NTLM was attempted but the target requires device "
          "claims, which NTLM cannot provide.",
    4824: "Generated when Kerberos pre-authentication used DES or RC4 "
          "encryption on an account configured to require stronger encryption.",
    4825: "Generated when a Remote Desktop connection was denied because "
          "the user is not authorised for Network Level Authentication.",
    4826: "Generated when the Boot Configuration Data (BCD) is modified — "
          "can indicate bootkit installation or secure-boot tampering.",
    4902: "Generated when the per-user audit policy table is created at "
          "user logon.",
    4904: "Generated when a security event source attempts to register.",
    4905: "Generated when a security event source attempts to unregister.",
    4906: "Generated when the CrashOnAuditFail registry value is changed.",
    4908: "Generated when the Special Groups Logon Table is modified — "
          "controls which groups trigger 4627 group membership logging.",
    4912: "Generated when per-user audit policy is changed for a specific "
          "user account.",
    4913: "Generated when the central access policy on an object is changed.",
    4985: "Generated when the state of a Transactional NTFS (TxF) "
          "transaction changed.",

    # ── Scheduled Tasks ──────────────────────────────────────────────
    4698: "Generated when a scheduled task is created. Records task name, "
          "run-as user, and trigger/action XML. Common persistence "
          "mechanism.",
    4699: "Generated when a scheduled task is deleted.",
    4700: "Generated when a scheduled task is enabled.",
    4701: "Generated when a scheduled task is disabled.",
    4702: "Generated when a scheduled task's definition is updated.",

    # ── Kerberos ─────────────────────────────────────────────────────
    4770: "Generated when a Kerberos service ticket is renewed before "
          "expiry. Frequent renewals may indicate long-running sessions.",
    4771: "Generated when Kerberos pre-authentication fails — the client "
          "could not prove knowledge of the password. Brute-force "
          "indicator when repeated.",
    4773: "Generated when a Kerberos service ticket request fails. "
          "May indicate attempts to access service accounts or enumerate SPNs.",

    # ── NTLM ─────────────────────────────────────────────────────────
    4776: "Generated when the domain controller validates NTLM credentials "
          "(pass-through authentication). Failures indicate bad passwords "
          "or relay attacks.",
    4777: "Generated when the domain controller failed to validate NTLM "
          "credentials. Bulk failures suggest a credential spray or relay "
          "attack in progress.",

    # ── Network Shares ───────────────────────────────────────────────
    5140: "Generated when a network share object is accessed. Shows which "
          "user accessed which share and from which IP address.",
    5142: "Generated when a new network share is created on this machine.",
    5143: "Generated when a network share's settings are modified.",
    5144: "Generated when a network share is deleted.",
    5145: "Generated when a network share file/folder access-check was "
          "performed by a client accessing an object inside a share.",

    # ── Network Filtering ────────────────────────────────────────────
    5031: "Generated when the Windows Firewall blocked an application from "
          "accepting incoming connections.",
    5154: "Generated when WFP permits a process to listen on a local port.",
    5155: "Generated when WFP blocks a process from binding to a local port.",
    5156: "Generated when the Windows Filtering Platform (WFP) allows a "
          "network connection. Helps map what processes communicate where.",
    5157: "Generated when WFP blocks a network connection. Can indicate "
          "a misconfiguration or a blocked C2 callback.",
    5158: "Generated when WFP permits a process to bind to a local port.",
    5159: "Generated when WFP blocks a bind to a local port.",
    5447: "Generated when a WFP filter is added, removed, or changed — "
          "may indicate an attacker modifying firewall rules.",

    # ── System / Service ─────────────────────────────────────────────
    4697: "Generated when a new service is installed in the Windows "
          "service control manager (Security log version of 7045).",
    7023: "Service terminated with an error. Records the service name and "
          "the error code returned by the service process.",
    7024: "Service terminated with a service-specific error code. Check the "
          "code for the specific failure reason.",
    7026: "Boot-start or system-start driver failed to load during startup. "
          "May indicate a corrupted or blocked driver.",
    7031: "Service terminated unexpectedly. Records how many times this has "
          "occurred and what recovery action was taken.",
    7032: "Service Control Manager tried to take a recovery action after an "
          "unexpected service termination.",
    7034: "Service terminated unexpectedly for the Nth time — records the "
          "count of consecutive unexpected terminations.",
    7035: "Service Control Manager sent a start or stop control to a service.",
    7036: "Generated when a service enters a running or stopped state. "
          "Very high-volume and mostly informational.",
    7040: "Generated when a service's start type is changed "
          "(e.g. manual → automatic). Can be used for persistence.",
    7045: "Generated when a new service is installed in the system service "
          "control manager (System log). Common persistence mechanism.",

    # ── Event Log ────────────────────────────────────────────────────
    1100: "Generated when the Windows Event Log service shuts down. "
          "Legitimate at reboot; suspicious at other times.",
    1102: "Generated when the Security audit log is cleared. This is a "
          "critical tamper indicator — attackers clear logs to hide "
          "their tracks.",
    1104: "Generated when the Security log file reached maximum size and "
          "events were discarded (log overflow). Gaps in logging.",

    # ── System Startup / Shutdown ────────────────────────────────
    41:   "Kernel-Power: system rebooted without cleanly shutting down — "
          "indicates a crash (BSOD), power failure, or hard reset. "
          "Look for preceding BugCheck (EID 1001) or critical error events.",
    104:  "The System audit log was cleared. Investigate who cleared the "
          "log and why — paired with Security EID 1102 on the same host.",
    1000: "Application Error: a Windows process terminated unexpectedly. "
          "Records the faulting process, module, exception code, and "
          "crash address.",
    1001: "Windows Error Reporting collected a crash dump (BugCheck/BSOD "
          "or application fault). Records the stop code and faulting module.",
    1074: "A process or user initiated a system shutdown or restart. "
          "Records the process name, reason code, and any operator comment. "
          "Unexpected reboots may indicate attacker-initiated reboot after "
          "driver or implant installation.",
    6005: "The Windows Event Log service started. Use this as a system-start "
          "timestamp — it is one of the first events written after boot.",
    6006: "The Windows Event Log service stopped cleanly. Marks the end of "
          "event logging immediately before a planned shutdown.",
    6008: "The previous system shutdown was unexpected — the system did not "
          "shut down cleanly. Indicates a crash, power loss, or forced reset. "
          "The time shown is when the dirty-shutdown was detected, not when "
          "it occurred.",
    6009: "Records OS version, build number, service pack, and processor "
          "count collected at boot time. Useful for identifying the machine "
          "configuration from a log-only artifact.",
    6013: "Records total system uptime in seconds since last boot, emitted "
          "daily by the Event Log service. Helps establish last-reboot time.",

    # ── Windows Defender / Antimalware ───────────────────────────
    1116: "Windows Defender detected malware or a potentially unwanted "
          "application. Records the threat name, severity, file path, "
          "and detection source. Treat as high-priority until verified.",
    1117: "Windows Defender took an action (quarantine, remove, or block) "
          "on a detected threat. Paired with EID 1116 detection event.",
    1118: "Windows Defender antimalware remediation activity started for "
          "a detected threat.",
    1119: "Windows Defender antimalware remediation succeeded — the threat "
          "was successfully quarantined or removed.",
    1120: "Windows Defender detected malware but failed to quarantine the "
          "file (file in use, permissions issue, etc.).",
    1121: "Attack Surface Reduction (ASR) rule triggered and blocked an "
          "action. Records the rule GUID, blocked process, and target file. "
          "Common triggers: Office spawning child processes, LOLBIN abuse.",
    1122: "Attack Surface Reduction (ASR) rule triggered in audit mode — "
          "detection only, action was not blocked. Consider switching the "
          "rule to block mode once false-positives are characterised.",
    5001: "Windows Defender real-time protection was disabled. Investigate "
          "immediately — disabling RTP is a common malware evasion step.",
    5004: "Windows Defender real-time protection configuration was changed.",
    5007: "Windows Defender antimalware platform settings changed. Check "
          "for exclusion additions or protection-level downgrades.",
    5010: "Windows Defender scan for malware and other potentially unwanted "
          "software failed.",
    5012: "Windows Defender real-time protection scan failed.",

    # ── AppLocker ─────────────────────────────────────────────────
    8002: "AppLocker allowed an executable to run (enforce mode).",
    8003: "AppLocker audit: an executable would have been blocked in "
          "enforcement mode. Review to tune rules before enabling blocking.",
    8004: "AppLocker blocked an executable from running. Records the "
          "blocked file path and the rule that applied. Investigate "
          "unknown paths — may indicate malware or LOLBin abuse.",
    8005: "AppLocker allowed a Windows Installer (.msi/.msp) package.",
    8006: "AppLocker audit: a Windows Installer package would have been "
          "blocked in enforcement mode.",
    8007: "AppLocker blocked a Windows Installer package from running.",
    8020: "AppLocker allowed a script to execute.",
    8021: "AppLocker blocked a script from executing. Records the script "
          "path and the applicable rule.",
    8022: "AppLocker allowed a packaged (MSIX/AppX) application.",
    8023: "AppLocker blocked a packaged application from launching.",
    8024: "AppLocker allowed a DLL to load.",
    8025: "AppLocker blocked a DLL from loading — may indicate a DLL "
          "injection or hijacking attempt that was stopped.",
    8027: "AppLocker could not enforce rules — the Application Identity "
          "service may not be running.",
    8029: "AppLocker DLL enforcement is now active for this process.",

    # ── WMI Activity ─────────────────────────────────────────────
    5857: "WMI provider started. Records the provider name and hosting "
          "process — useful for mapping WMI attack surface.",
    5858: "WMI query error. Records the failing query text and error code.",
    5860: "WMI temporary event subscription created. Fires during the "
          "current session only; disappears on reboot.",
    5861: "WMI permanent event subscription created. Permanent subscriptions "
          "survive reboots and are a well-known persistence mechanism. "
          "All unexpected permanent subscriptions should be investigated.",

    # ── BITS Client ──────────────────────────────────────────────
    59:   "BITS transfer job created. Records the job name, URL, and "
          "local destination path. BITS is abused by malware and red teams "
          "to download payloads silently while bypassing some proxy controls.",
    60:   "BITS transfer job completed. Records the URL downloaded and the "
          "local file written.",
    61:   "BITS transfer job failed — the download did not complete. "
          "Records the job name and error code.",

    # ── Windows Firewall Rule Changes ─────────────────────────────
    2004: "Windows Firewall rule added. Records the rule name, program "
          "path, local port, and profile (domain/private/public). "
          "Attackers add rules to expose listeners or permit C2 traffic.",
    2005: "Windows Firewall rule modified.",
    2006: "Windows Firewall rule deleted.",
    2033: "All Windows Firewall rules were purged — the rule list was "
          "completely cleared. Extremely suspicious; investigate immediately.",

    # ── Active Directory Object Changes ───────────────────────────
    5136: "A directory service object attribute was modified. High-value "
          "for detecting AD privilege escalation (adminSDHolder, GPO link "
          "changes, SID History addition, group membership by LDAP write).",
    5137: "A directory service object was created in Active Directory. "
          "Monitor for rogue computer accounts, GPOs, or admin objects.",
    5138: "A previously deleted AD object was undeleted (restored from the "
          "AD Recycle Bin).",
    5139: "A directory service object was moved to a different OU or "
          "container.",
    5141: "A directory service object was deleted from Active Directory.",

    # ── Trust Relationships ────────────────────────────────────────
    4706: "A new trust relationship was created to a domain. Cross-domain "
          "trusts extend the security boundary — all new trusts should be "
          "verified against change management records.",
    4707: "A trust relationship to a domain was removed.",
    4716: "Trusted domain information was modified — attributes of an "
          "existing trust relationship changed.",

    # ── Security Subsystem Lifecycle ──────────────────────────────
    4608: "Windows security audit service started — marks the beginning "
          "of security logging after system startup.",
    4609: "Windows security audit service stopped — security logging ended "
          "before system shutdown.",
    4610: "An authentication package was loaded by the Local Security "
          "Authority (LSA). Unexpected packages may indicate credential "
          "theft tooling (e.g. patched wdigest.dll).",
    4611: "A trusted logon process registered with LSA. Should only occur "
          "at system startup — unexpected registrations are suspicious.",
    4614: "A notification package was loaded by the Security Accounts "
          "Manager (SAM). Malicious packages can intercept password changes.",
    4615: "Invalid use of LPC port by a process.",
    4621: "An administrator recovered the system from CrashOnAuditFail "
          "mode. Events may have been lost during the lockout period.",
}


# ── Main entry point ──────────────────────────────────────────────────────

def get_event_description(ev: dict) -> str | None:
    """
    Return a plain-text description sentence for *ev*, or None if the
    event ID is not in the knowledge base.

    Sub-conditions (logon type, sub-status, process name, service name,
    encryption type, etc.) are pulled from event_data and interpolated
    into the description where available.
    """
    eid  = int(ev.get("event_id", 0) or 0)
    ed   = _ed(ev)

    # ── Sysmon events (provider contains "sysmon") ────────────────────────
    if _is_sysmon(ev):
        desc = _SYSMON_DESC.get(eid)
        if desc:
            # Enrich Sysmon event 1 with image/cmdline context
            if eid == 1:
                img = _basename(_f(ed, "Image"))
                cmd = _f(ed, "CommandLine")
                if img:
                    desc = f"Process '{img}' was created. " + desc
                if cmd:
                    short_cmd = cmd if len(cmd) <= 80 else cmd[:77] + "…"
                    desc += f" Command: {short_cmd}"
            elif eid == 3:
                dst_ip   = _f(ed, "DestinationIp")
                dst_port = _f(ed, "DestinationPort")
                img      = _basename(_f(ed, "Image"))
                if img and dst_ip:
                    desc = (f"'{img}' initiated a network connection to "
                            f"{dst_ip}:{dst_port}. " + desc)
            elif eid == 8:
                src = _basename(_f(ed, "SourceImage"))
                tgt = _basename(_f(ed, "TargetImage"))
                if src and tgt:
                    desc = (f"'{src}' created a remote thread in '{tgt}'. "
                            + desc)
            elif eid == 10:
                src = _basename(_f(ed, "SourceImage"))
                tgt = _basename(_f(ed, "TargetImage"))
                if src and tgt:
                    desc = (f"'{src}' opened a handle to '{tgt}'. " + desc)
        return desc

    # ── PowerShell events ─────────────────────────────────────────────────
    if _is_powershell(ev):
        desc = _PS_DESC.get(eid)
        if desc:
            if eid == 4104:
                # Enrich with script snippet
                script = _f(ed, "ScriptBlockText")
                path   = _f(ed, "Path")
                if path:
                    desc = f"Script block from '{path}' was recorded.  " + desc
                if script:
                    snippet = script.strip().replace("\n", " ")
                    if len(snippet) > 120:
                        snippet = snippet[:117] + "…"
                    desc += f"  Preview: {snippet}"
            elif eid == 4103:
                cmd = _f(ed, "Payload", "CommandName")
                if cmd:
                    short = cmd if len(cmd) <= 80 else cmd[:77] + "…"
                    desc = f"Module pipeline output recorded.  Command: {short}  " + desc
            elif eid in (400, 403):
                host = _f(ed, "HostApplication", "HostName")
                ver  = _f(ed, "EngineVersion")
                if host:
                    action = "started" if eid == 400 else "stopped"
                    desc = f"PowerShell engine {action} via '{host}'."
                    if ver:
                        desc += f"  Version: {ver}."
        return desc

    # ── Task Scheduler events ─────────────────────────────────────────────
    if _is_tasksched(ev):
        desc = _TASKSCHED_DESC.get(eid)
        if desc:
            task = _f(ed, "TaskName", "Path")
            if task:
                action_words = {
                    106: "registered", 107: "triggered", 108: "triggered",
                    109: "triggered", 110: "queued",    111: "stopped",
                    119: "triggered", 129: "launched",  140: "updated",
                    141: "deleted",   200: "action started", 201: "completed",
                }
                verb = action_words.get(eid, "")
                if verb:
                    desc = f"Task '{task}' {verb}.  " + desc
                else:
                    desc = f"Task '{task}'.  " + desc
        return desc

    # ── RDP / Terminal Services (local session manager) ───────────────────
    if _is_rdp_local(ev):
        desc = _RDP_LOCAL_DESC.get(eid)
        if desc:
            user = _f(ed, "User", "UserName")
            addr = _f(ed, "Address", "ClientAddress")
            sid  = _f(ed, "SessionID", "Session")
            if user:
                desc = f"User '{user}' — " + desc
            if addr and addr not in ("-", "LOCAL"):
                desc += f"  Source: {addr}."
            if sid:
                desc += f"  Session ID: {sid}."
        return desc

    # ── RDP / Terminal Services (remote connection manager / gateway) ──────
    if _is_rdp_remote(ev):
        desc = _RDP_REMOTE_DESC.get(eid)
        if desc:
            user = _f(ed, "Param1", "UserName", "User")
            addr = _f(ed, "Param3", "ClientAddress", "Address", "IpAddress")
            if eid == 1149:
                # 1149: Authentication succeeded — richer context
                if user:
                    desc = f"User '{user}' authenticated via RDP.  " + desc
                if addr:
                    desc += f"  Source IP: {addr}."
            else:
                if addr:
                    desc += f"  Client IP: {addr}."
                if user:
                    desc += f"  User: {user}."
        return desc

    # ── 4624 — Successful Logon ───────────────────────────────────────────
    if eid == 4624:
        lt = _f(ed, "LogonType")
        label = _LOGON_TYPE_LABEL.get(lt, f"Type {lt}" if lt else "Unknown type")
        body  = _LOGON_TYPE_DESC.get(lt,
                    "A user or service successfully authenticated on this system.")
        user = _f(ed, "TargetUserName")
        ip   = _f(ed, "IpAddress")
        parts = [f"Successful logon ({label}).  {body}"]
        if user and not user.startswith("-"):
            parts.append(f"Account: {user}")
        if ip and ip not in ("-", "::1", "127.0.0.1", "-"):
            parts.append(f"Source IP: {ip}")
        return "  ".join(parts)

    # ── 4625 — Failed Logon ───────────────────────────────────────────────
    if eid == 4625:
        lt     = _f(ed, "LogonType")
        label  = _LOGON_TYPE_LABEL.get(lt, f"Type {lt}" if lt else "")
        user   = _f(ed, "TargetUserName")
        ip     = _f(ed, "IpAddress")
        sub    = _f(ed, "SubStatus").lower()
        reason = _SUBSTATUS_DESC.get(sub, "")
        head   = f"Failed logon attempt"
        if label:
            head += f" ({label})"
        head += "."
        parts  = [head]
        if reason:
            parts.append(reason)
        else:
            parts.append("Credentials were rejected by the system.")
        if user and user not in ("-", ""):
            parts.append(f"Account attempted: {user}")
        if ip and ip not in ("-", "::1", "127.0.0.1"):
            parts.append(f"Source IP: {ip}")
        return "  ".join(parts)

    # ── 4672 — Special Privileges Assigned ───────────────────────────────
    if eid == 4672:
        user = _f(ed, "SubjectUserName")
        privs = _f(ed, "PrivilegeList")
        desc  = _GENERIC_DESC[4672]
        if user and not user.lower().endswith("$"):
            desc = f"Account '{user}' logged on with administrative privileges.  " + desc
        if privs:
            short = privs.replace("\n", ", ")
            if len(short) > 120:
                short = short[:117] + "…"
            desc += f"  Privileges: {short}"
        return desc

    # ── 4688 — New Process Created ────────────────────────────────────────
    if eid == 4688:
        proc   = _basename(_f(ed, "NewProcessName"))
        parent = _basename(_f(ed, "ParentProcessName"))
        cmd    = _f(ed, "CommandLine", "ProcessCommandLine")
        parts  = ["A new process was created."]
        if proc:
            line = f"Process: {proc}"
            if parent:
                line += f"  (spawned by {parent})"
            parts.append(line)
        if cmd:
            short = cmd if len(cmd) <= 100 else cmd[:97] + "…"
            parts.append(f"Command: {short}")
        parts.append("Generated for every process launch when process-creation "
                     "auditing is enabled.")
        return "  ".join(parts)

    # ── 4663 — Object Access Attempt ─────────────────────────────────────
    if eid == 4663:
        obj  = _f(ed, "ObjectName")
        otype = _f(ed, "ObjectType")
        acc  = _f(ed, "AccessList", "AccessMask")
        user = _f(ed, "SubjectUserName")
        desc = "An attempt was made to access an audited object."
        if obj:
            short = obj if len(obj) <= 80 else "…" + obj[-77:]
            desc = f"Access attempted on: {short}."
        if otype:
            desc += f"  Object type: {otype}."
        if user:
            desc += f"  Actor: {user}."
        desc += ("  Generated only when a SACL is set on the object and the "
                 "access right matches.")
        return desc

    # ── 4697 — Service Installed (Security log) ───────────────────────────
    if eid == 4697:
        svc  = _f(ed, "ServiceName")
        path = _f(ed, "ServiceFileName")
        user = _f(ed, "SubjectUserName")
        desc = _GENERIC_DESC[4697]
        if svc:
            desc = f"Service '{svc}' was installed."
        if path:
            short = path if len(path) <= 80 else "…" + path[-77:]
            desc += f"  Binary: {short}."
        if user:
            desc += f"  Installed by: {user}."
        desc += ("  Unexpected services should be investigated as a "
                 "persistence mechanism.")
        return desc

    # ── 4698 — Scheduled Task Created ────────────────────────────────────
    if eid == 4698:
        task = _f(ed, "TaskName")
        user = _f(ed, "SubjectUserName")
        desc = "A scheduled task was created."
        if task:
            desc = f"Scheduled task '{task}' was created."
        if user:
            desc += f"  Created by: {user}."
        desc += ("  Scheduled tasks are a common persistence and lateral "
                 "movement technique. Review the task's action and triggers.")
        return desc

    # ── 4719 — System Audit Policy Changed ───────────────────────────────
    if eid == 4719:
        cat  = _f(ed, "SubcategoryGuid", "Category")
        user = _f(ed, "SubjectUserName")
        desc = _GENERIC_DESC[4719]
        if user:
            desc = f"Audit policy was changed by '{user}'.  " + desc
        if cat:
            desc += f"  Subcategory/Category: {cat}."
        return desc

    # ── 4728 / 4732 / 4756 — Member Added to Privileged Group ────────────
    if eid in (4728, 4732, 4756):
        member = _f(ed, "MemberName", "MemberSid")
        group  = _f(ed, "TargetUserName", "GroupName")
        actor  = _f(ed, "SubjectUserName")
        desc   = _GENERIC_DESC[eid]
        if member and group:
            desc = f"'{member}' was added to group '{group}'."
        elif group:
            desc = f"A member was added to '{group}'."
        if actor:
            desc += f"  Added by: {actor}."
        return desc

    # ── 4740 — Account Locked Out ─────────────────────────────────────────
    if eid == 4740:
        locked = _f(ed, "TargetUserName")
        caller = _f(ed, "SubjectUserName")
        src    = _f(ed, "TargetDomainName")
        desc   = _GENERIC_DESC[4740]
        if locked:
            desc = f"Account '{locked}' was automatically locked out.  " + desc
        if caller:
            desc += f"  Caller: {caller}."
        if src:
            desc += f"  Source machine: {src}."
        return desc

    # ── 4768 — Kerberos TGT Request ──────────────────────────────────────
    if eid == 4768:
        user   = _f(ed, "TargetUserName")
        result = _f(ed, "Status").lower()
        enc    = _f(ed, "TicketEncryptionType").lower()
        r_desc = _KRB_RESULT.get(result, "")
        e_desc = _KRB_ENC.get(enc, enc)
        desc   = "A Kerberos Ticket-Granting Ticket (TGT) was requested."
        if user:
            desc = f"Kerberos TGT requested for account '{user}'."
        if r_desc:
            desc += f"  Result: {r_desc}"
        if e_desc:
            desc += f"  Encryption: {e_desc}."
        desc += ("  TGT issuance is normal during logon; failures indicate "
                 "authentication problems or brute-force attempts.")
        return desc

    # ── 4769 — Kerberos Service Ticket Request ────────────────────────────
    if eid == 4769:
        svc    = _f(ed, "ServiceName")
        enc    = _f(ed, "TicketEncryptionType").lower()
        user   = _f(ed, "TargetUserName")
        e_desc = _KRB_ENC.get(enc, enc if enc else "")
        desc   = "A Kerberos service ticket (TGS) was requested."
        if svc:
            desc = f"Kerberos service ticket requested for '{svc}'."
        if user:
            desc += f"  Requested by: {user}."
        if e_desc:
            desc += f"  Encryption: {e_desc}."
        if enc in ("0x17", "0x18"):
            desc += ("  RC4 encryption on a service ticket is the hallmark "
                     "of Kerberoasting — an attacker requesting tickets to "
                     "crack offline.")
        return desc

    # ── 4771 — Kerberos Pre-Auth Failed ──────────────────────────────────
    if eid == 4771:
        user   = _f(ed, "TargetUserName")
        code   = _f(ed, "Status").lower()
        ip     = _f(ed, "IpAddress")
        desc   = _GENERIC_DESC[4771]
        if user:
            desc = f"Kerberos pre-authentication failed for '{user}'.  " + desc
        if code:
            r = _KRB_RESULT.get(code, "")
            if r:
                desc += f"  Reason: {r}"
        if ip and ip not in ("-",):
            desc += f"  Client IP: {ip}."
        return desc

    # ── 4776 — NTLM Credential Validation ────────────────────────────────
    if eid == 4776:
        user   = _f(ed, "TargetUserName")
        ws     = _f(ed, "Workstation")
        result = _f(ed, "Status").lower()
        desc   = _GENERIC_DESC[4776]
        if user:
            desc = f"NTLM credential validation for account '{user}'.  " + desc
        if ws:
            desc += f"  From workstation: {ws}."
        if result and result != "0x0":
            desc += f"  Status code: {result} — authentication failed."
        return desc

    # ── 5140 — Network Share Accessed ────────────────────────────────────
    if eid == 5140:
        share = _f(ed, "ShareName")
        user  = _f(ed, "SubjectUserName")
        ip    = _f(ed, "IpAddress")
        desc  = _GENERIC_DESC[5140]
        if share:
            desc = f"Network share '{share}' was accessed."
        if user:
            desc += f"  User: {user}."
        if ip:
            desc += f"  Source IP: {ip}."
        desc += ("  Admin shares (C$, ADMIN$, IPC$) are commonly used during "
                 "lateral movement.")
        return desc

    # ── 5145 — Network Share Object Access Check ──────────────────────────
    if eid == 5145:
        share = _f(ed, "ShareName")
        name  = _f(ed, "RelativeTargetName")
        user  = _f(ed, "SubjectUserName")
        desc  = _GENERIC_DESC[5145]
        if share and name:
            desc = f"Access to '{name}' inside share '{share}' was checked."
        if user:
            desc += f"  User: {user}."
        return desc

    # ── 7023 / 7024 / 7026 / 7031 / 7032 / 7034 / 7035 — Service Failures ─
    if eid in (7023, 7024, 7026, 7031, 7032, 7034, 7035):
        svc  = _f(ed, "param1")
        code = _f(ed, "param2")
        desc = _GENERIC_DESC.get(eid, "A service lifecycle event occurred.")
        if svc:
            desc = f"Service '{svc}': " + desc
        if code:
            desc += f"  Error/detail: {code}."
        return desc

    # ── 7045 — New Service Installed (System log) ─────────────────────────
    if eid == 7045:
        svc  = _f(ed, "ServiceName")
        path = _f(ed, "ImagePath")
        acct = _f(ed, "AccountName")
        desc = "A new service was installed in the system service control manager."
        if svc:
            desc = f"New service installed: '{svc}'."
        if path:
            short = path if len(path) <= 80 else "…" + path[-77:]
            desc += f"  Binary path: {short}."
        if acct:
            desc += f"  Runs as: {acct}."
        desc += ("  Unexpected services — especially those in non-standard "
                 "paths — are a common persistence and privilege escalation "
                 "technique.")
        return desc

    # ── 7036 — Service State Changed ─────────────────────────────────────
    if eid == 7036:
        svc   = _f(ed, "param1")
        state = _f(ed, "param2")
        desc  = _GENERIC_DESC[7036]
        if svc and state:
            desc = f"Service '{svc}' entered the {state.lower()} state."
        return desc

    # ── 7040 — Service Start Type Changed ────────────────────────────────
    if eid == 7040:
        svc  = _f(ed, "param1")
        old  = _f(ed, "param2")
        new  = _f(ed, "param3")
        desc = _GENERIC_DESC[7040]
        if svc:
            desc = f"Start type of service '{svc}' was changed."
        if old and new:
            desc += f"  Changed from '{old}' to '{new}'."
        return desc

    # ── 1102 — Audit Log Cleared ──────────────────────────────────────────
    if eid == 1102:
        user = _f(ed, "SubjectUserName")
        desc = _GENERIC_DESC[1102]
        if user:
            desc = f"Security audit log was cleared by '{user}'.  " + desc
        return desc

    # ── 4634 — Account Logoff ─────────────────────────────────────────────
    if eid == 4634:
        user = _f(ed, "TargetUserName")
        ltype = _f(ed, "LogonType")
        desc = _GENERIC_DESC[4634]
        if user:
            desc = f"'{user}' logged off."
        if ltype:
            label = _LOGON_TYPE_LABEL.get(ltype, ltype)
            desc += f"  Logon type: {label}."
        return desc

    # ── 4648 — Explicit Credentials Logon ────────────────────────────────
    if eid == 4648:
        actor   = _f(ed, "SubjectUserName")
        target  = _f(ed, "TargetUserName")
        server  = _f(ed, "TargetServerName")
        proc    = _basename(_f(ed, "ProcessName"))
        desc    = _GENERIC_DESC[4648]
        parts   = []
        if actor:
            parts.append(f"'{actor}'")
        if proc:
            parts.append(f"via '{proc}'")
        if target:
            parts.append(f"authenticated as '{target}'")
        if server and server not in ("localhost", "127.0.0.1", "-"):
            parts.append(f"to '{server}'")
        if parts:
            desc = " ".join(parts) + ".  " + desc
        return desc

    # ── 1074 — System Shutdown / Restart Initiated ───────────────────────
    if eid == 1074:
        proc    = _basename(_f(ed, "param1", "ProcessName"))
        reason  = _f(ed, "param3", "Reason")
        comment = _f(ed, "param5", "Comment")
        desc    = _GENERIC_DESC[1074]
        if proc:
            desc = f"Shutdown/restart initiated by '{proc}'.  " + desc
        if reason:
            desc += f"  Reason: {reason}."
        if comment:
            short = comment if len(comment) <= 80 else comment[:77] + "…"
            desc += f"  Comment: {short}."
        return desc

    # ── 6008 — Unexpected Shutdown ────────────────────────────────────────
    if eid == 6008:
        ts   = _f(ed, "param1", "StopTime")
        date = _f(ed, "param2", "StopDate")
        desc = _GENERIC_DESC[6008]
        if ts and date:
            desc += f"  Last recorded time before shutdown: {date} {ts}."
        elif ts:
            desc += f"  Last recorded time: {ts}."
        return desc

    # ── 1116 — Windows Defender Malware Detection ─────────────────────────
    if eid == 1116:
        threat  = _f(ed, "Threat Name", "ThreatName", "threat name")
        path    = _f(ed, "Path", "Detection Path")
        action  = _f(ed, "Action", "Remediation")
        sev     = _f(ed, "Severity Name", "Severity")
        desc    = _GENERIC_DESC[1116]
        if threat:
            desc = f"Threat detected: '{threat}'."
        if sev:
            desc += f"  Severity: {sev}."
        if path:
            short = path if len(path) <= 100 else "…" + path[-97:]
            desc += f"  Location: {short}."
        if action:
            desc += f"  Action taken: {action}."
        return desc

    # ── 5136 — AD Object Modified ─────────────────────────────────────────
    if eid == 5136:
        obj   = _f(ed, "ObjectDN", "ObjectClass")
        attr  = _f(ed, "AttributeLDAPDisplayName")
        actor = _f(ed, "SubjectUserName")
        desc  = _GENERIC_DESC[5136]
        if obj:
            short = obj if len(obj) <= 80 else "…" + obj[-77:]
            desc = f"AD object '{short}' was modified."
        if attr:
            desc += f"  Attribute changed: {attr}."
        if actor:
            desc += f"  Modified by: {actor}."
        return desc

    # ── 5156 / 5157 — WFP Connection Allowed / Blocked ───────────────────
    if eid in (5156, 5157):
        proc  = _basename(_f(ed, "Application"))
        dip   = _f(ed, "DestAddress")
        dport = _f(ed, "DestPort")
        proto = _f(ed, "Protocol")
        action = "allowed" if eid == 5156 else "blocked"
        desc   = _GENERIC_DESC.get(eid, "")
        if proc and dip:
            desc = f"WFP {action} connection from '{proc}' to {dip}:{dport}."
        elif dip:
            desc = f"WFP {action} connection to {dip}:{dport}."
        if proto:
            proto_name = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(proto, proto)
            desc += f"  Protocol: {proto_name}."
        return desc

    # ── 59 — BITS Transfer Job Created ───────────────────────────────────
    if eid == 59:
        job  = _f(ed, "jobTitle", "Id")
        url  = _f(ed, "url", "RemoteName")
        dest = _f(ed, "localName", "LocalName")
        desc = _GENERIC_DESC[59]
        if job:
            desc = f"BITS job '{job}' created."
        if url:
            short = url if len(url) <= 100 else url[:97] + "…"
            desc += f"  URL: {short}."
        if dest:
            short = dest if len(dest) <= 80 else "…" + dest[-77:]
            desc += f"  Destination: {short}."
        return desc

    # ── 2004 — Firewall Rule Added ────────────────────────────────────────
    if eid == 2004:
        rule    = _f(ed, "RuleName", "ruleName")
        prog    = _basename(_f(ed, "ApplicationPath", "ModifyingApplication"))
        profile = _f(ed, "Profiles")
        desc    = _GENERIC_DESC[2004]
        if rule:
            desc = f"Firewall rule '{rule}' was added."
        if prog and prog not in ("-", ""):
            desc += f"  Application: {prog}."
        if profile:
            desc += f"  Profile(s): {profile}."
        return desc

    # ── 4706 — New Domain Trust ───────────────────────────────────────────
    if eid == 4706:
        domain = _f(ed, "TargetDomainName", "DomainName")
        actor  = _f(ed, "SubjectUserName")
        desc   = _GENERIC_DESC[4706]
        if domain:
            desc = f"New trust created to domain '{domain}'."
        if actor:
            desc += f"  Created by: {actor}."
        desc += ("  Verify this trust was authorised — trusts extend "
                 "the security boundary.")
        return desc

    # ── Generic fallback from static table ───────────────────────────────
    return _GENERIC_DESC.get(eid)
