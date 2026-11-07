# Profiles

The source contains **32 built-in JSON profiles** under `evtx_tool/profiles/defaults`. Custom profiles load from `profiles/` relative to the working directory; a custom name can override a built-in name. Listing counts can therefore differ from the built-in file count.

## Applying profiles

GUI: select profile checkboxes in the left panel and click **Apply Profiles**. Ticking alone does not apply. **New Profile** / **Edit Profile** open editing. GUI profiles filter already loaded events; they are not parse-time input selection.

CLI: --profile accepts a name, a JSON path, repeated selections, or all. A missing/unknown name/path produces a visible error and exit 2 before parsing. A JSON path can be used directly without importing it into the persistent custom store.

```powershell
py -3.12 evtx_tool.py profiles list
py -3.12 evtx_tool.py profiles show "Process Creation and Termination"
py -3.12 evtx_tool.py parse .\logs --profile "Process Creation and Termination" --no-tui -o .\processes.json
```

## Matching rules

A profile's event IDs, sources and channels remain one group. Within a group, each nonempty restriction must match; across selected profiles an event can match any whole group. Thus one profile's event ID cannot borrow another profile's provider to match. Sources are case-insensitive substring matches against provider/channel; channels match channel. Built-ins use full provider names, but the matching operator is not strict string equality.

Base filter restrictions intersect the selected profiles. Groups from a loaded filter remain additional AND restrictions (profile_groups_also) when another selection is applied. Clearing restrictions is an explicit action, not a side effect of changing a checkbox.

Extended profile computers/users/levels are merged by the combiner and apply outside the per-profile ID/source/channel alternatives when not already constrained by the base. Conditions likewise combine outside those groups. Keywords are not an additional restriction in the combined-profile path; do not rely on them for content filtering. Use Advanced Filter or --search for text restrictions.

## JSON example

Save the following synthetic configuration as process-profile.json. It is a configuration example, not event evidence:

```json
{
  "name": "Example process selection",
  "description": "Security process creation only",
  "event_ids": [4688],
  "sources": ["Microsoft-Windows-Security-Auditing"]
}
```

```powershell
py -3.12 evtx_tool.py parse .\logs --profile .\process-profile.json --no-tui -o .\processes.json
```

Profile management subcommands are list, show, create, delete, export, export-all and import; inspect --help for the required arguments. There is no validate subcommand. Retain a copy before overwriting a custom profile.

## Built-in inventory

The counts below are the IDs configured in each JSON file, not a guarantee that every ID appears in a collection. Follow each file for its exact provider/channel restrictions and description.

| Profile | Configured IDs | Definition |
|---|---:|---|
| User Account Management | 46 | [01_user_account_management](../evtx_tool/profiles/defaults/01_user_account_management.json) |
| Logon/Logoff Activity | 22 | [02_logon_logoff](../evtx_tool/profiles/defaults/02_logon_logoff.json) |
| Privilege Escalation | 9 | [03_privilege_escalation](../evtx_tool/profiles/defaults/03_privilege_escalation.json) |
| RDP Activity | 29 | [04_rdp_activity](../evtx_tool/profiles/defaults/04_rdp_activity.json) |
| PowerShell Execution | 17 | [05_powershell_execution](../evtx_tool/profiles/defaults/05_powershell_execution.json) |
| Process Creation and Termination | 6 | [06_process_creation](../evtx_tool/profiles/defaults/06_process_creation.json) |
| Network Connections | 9 | [07_network_connections](../evtx_tool/profiles/defaults/07_network_connections.json) |
| File System Activity | 14 | [08_file_system_activity](../evtx_tool/profiles/defaults/08_file_system_activity.json) |
| Registry Modifications | 10 | [09_registry_modifications](../evtx_tool/profiles/defaults/09_registry_modifications.json) |
| Scheduled Tasks | 23 | [10_scheduled_tasks](../evtx_tool/profiles/defaults/10_scheduled_tasks.json) |
| Service Install and Changes | 14 | [11_service_changes](../evtx_tool/profiles/defaults/11_service_changes.json) |
| Defender and AV Alerts | 27 | [12_defender_av_alerts](../evtx_tool/profiles/defaults/12_defender_av_alerts.json) |
| Application Crashes | 4 | [13_application_crashes](../evtx_tool/profiles/defaults/13_application_crashes.json) |
| USB and Removable Media | 25 | [14_usb_removable_media](../evtx_tool/profiles/defaults/14_usb_removable_media.json) |
| Firewall Changes | 25 | [15_firewall_changes](../evtx_tool/profiles/defaults/15_firewall_changes.json) |
| Security Policy Changes | 16 | [16_security_policy_changes](../evtx_tool/profiles/defaults/16_security_policy_changes.json) |
| Lateral Movement Indicators | 9 | [17_lateral_movement](../evtx_tool/profiles/defaults/17_lateral_movement.json) |
| Windows Update and Patch Activity | 16 | [19_windows_update](../evtx_tool/profiles/defaults/19_windows_update.json) |
| System Boot and Shutdown Events | 13 | [20_boot_shutdown](../evtx_tool/profiles/defaults/20_boot_shutdown.json) |
| Log Clearing and Anti-Forensics | 5 | [21_log_clearing_anti_forensics](../evtx_tool/profiles/defaults/21_log_clearing_anti_forensics.json) |
| System Time Changes | 2 | [22_system_time_changes](../evtx_tool/profiles/defaults/22_system_time_changes.json) |
| Kerberos and NTLM Authentication | 9 | [23_kerberos_ntlm_authentication](../evtx_tool/profiles/defaults/23_kerberos_ntlm_authentication.json) |
| Credential Access | 7 | [24_credential_access](../evtx_tool/profiles/defaults/24_credential_access.json) |
| WMI Activity and Persistence | 8 | [25_wmi_activity](../evtx_tool/profiles/defaults/25_wmi_activity.json) |
| WinRM and Remote PowerShell | 8 | [26_winrm_remote_powershell](../evtx_tool/profiles/defaults/26_winrm_remote_powershell.json) |
| Active Directory Changes | 14 | [27_active_directory_changes](../evtx_tool/profiles/defaults/27_active_directory_changes.json) |
| Driver and Code Integrity | 10 | [28_driver_code_integrity](../evtx_tool/profiles/defaults/28_driver_code_integrity.json) |
| BITS Jobs | 7 | [29_bits_jobs](../evtx_tool/profiles/defaults/29_bits_jobs.json) |
| AppLocker and WDAC Blocks | 12 | [30_applocker_wdac](../evtx_tool/profiles/defaults/30_applocker_wdac.json) |
| WiFi Connections | 11 | [31_wifi_connections](../evtx_tool/profiles/defaults/31_wifi_connections.json) |
| Printing | 5 | [32_printing](../evtx_tool/profiles/defaults/32_printing.json) |
| Sysmon (All Events) | 0 | [33_sysmon_all](../evtx_tool/profiles/defaults/33_sysmon_all.json) |

Use [Advanced Filter](06-advanced-filter.md) to load/save filter configurations; these are distinct from profile definitions.
