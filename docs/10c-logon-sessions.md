# View Logon Sessions

## What It Is

**View Logon Sessions** reconstructs every Windows logon session present in the loaded EVTX files and presents them in a browsable table. It correlates Security log events across the full parsed dataset — sessions, process spawns, privilege assignments, and logoffs — into per-session rows showing who logged on, from where, when, how long, and what they did.

Clicking a session row filters the main events table to only the events that belong to that session.

> **Note:** View Logon Sessions is a GUI-only feature. It is not available from the CLI.

---

## How to Open It

**Analysis → View Logon Sessions** in the menu bar.

EventHawk scans the full unfiltered event set and opens the session browser. The scan is instant — it reuses the events already in memory.

---

## Events Used

EventHawk builds sessions from six Security log event IDs:

| Event ID | What It Records |
|----------|-----------------|
| 4624 | Logon — the primary session creation event |
| 4634 | Logoff (session termination by system) |
| 4647 | User-initiated logoff |
| 4648 | Explicit credentials used (RunAs / network pivot) |
| 4672 | Special privileges assigned to new logon |
| 4688 | Process creation (linked to session via SubjectLogonId) |

> **Tip:** For best results, load Security log EVTX files (`Security.evtx`). Sessions can still be partially reconstructed from other logs containing 4688 or 4648 events.

---

## The Session Browser

### Columns

| Column | Description |
|--------|-------------|
| User | Domain\Username from the logon event |
| Computer | Hostname that recorded the logon |
| Type | Logon type number and label (see below) |
| Session ID | LogonId (LUID) — Windows-assigned session identifier |
| Start | Timestamp of the EID 4624 logon event |
| End | Timestamp of the logoff (EID 4634/4647). **Not logged** when the log holds no logoff for the session |
| Duration | Logon to logoff. Shown only when both are in the log; otherwise **Unavailable** (see Duration Notes) |
| Procs | Number of EID 4688 process-create events attributed to this session |
| Priv Events | Number of EID 4672 special-privilege events |
| Last Activity | Timestamp of the last event seen for the session (activity, not proof that it ended) |

Columns are sortable. Duration and numeric columns sort numerically, not lexicographically.

### Logon Types

| Type | Label | Meaning |
|------|-------|---------|
| 2 | Interactive | Local console logon |
| 3 | Network | SMB, mapped drive, net use |
| 4 | Batch | Scheduled task |
| 5 | Service | Windows service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Network logon with cleartext credentials (e.g. IIS basic auth) |
| 9 | NewCredentials | RunAs with /netonly flag |
| 10 | RemoteInteractive | RDP session |
| 11 | CachedInteractive | Cached credentials — domain controller unreachable, local account, or Microsoft account sign-in |
| 12 | CachedRemoteInteractive | Cached RDP |
| 13 | CachedUnlock | Cached credentials unlock |

### Session ID Tooltip

If a session is part of a **linked split-token pair** (see below), hovering over the Session ID cell shows the sibling session's LogonId. The filter includes both sessions.

---

## Filtering the Events Table

Click any session row and click **Filter to this session** (or double-click the row) to apply a session filter. The main events table immediately narrows to only events belonging to that session.

The filter is **host-scoped and time-scoped**: it matches the selected session's computer name and time window so that a later session on the same host that reuses the same LogonId (LUID) is never included.

The active filter is shown as a badge in the toolbar. Click **Clear All Filters** or the badge itself to remove it.

---

## Linked Split-Token / UAC Session Pairs

When a user with administrator rights logs on, Windows creates **two sessions simultaneously**:

- A **filtered-token session** (standard user rights)
- An **elevated-token session** (full admin rights)

Each session's EID 4624 carries a `TargetLinkedLogonId` field pointing to the other session. EventHawk detects these pairs and links them automatically.

When you filter to a linked session, **both sessions are included** in the filter. The Session ID cell tooltip identifies the sibling. The filter window spans the union of both sessions' time ranges so no events from either session are missed.

---

## Toolbar Controls

### Search

The search box filters the session browser by any text — username, computer, logon type, session ID, or timestamp. Filtering is instant as you type.

### Hide Service Sessions

Tick **Hide service sessions** to suppress logon-type-5 (Service) rows. On busy servers, service sessions can dominate the list and obscure the interactive and remote sessions you care about. This filter does not affect the events-table filter — if a service session is already selected as an active filter, its events remain visible in the main table.

---

## Session Identity and LUID Reuse

Windows LogonIds (LUIDs) are locally unique per boot — they reset after a reboot and can be reused by a later session on the same host. EventHawk prevents false merges by:

1. Scoping each session to the host that recorded it (`Computer` field)
2. Scoping each session to a concrete time window built from its own 4624/4634 sequence
3. Using the exact session instance (not just the LUID) when resolving linked sibling pairs

This means multi-host and multi-reboot captures can be loaded together without sessions from different machines or different boot cycles being merged.

---

## Duration Notes

A duration is shown only when the log proves both ends of the session: its logon and its logoff. EventHawk never derives one from the last event seen or the next logon, because a session can stay open long after its last logged event. The **Last Activity** column shows the last event seen for the session, so the observed span is still visible, labelled as what it is.


- **Unavailable (no logoff in log)** — the logon is known but no logoff was recorded. The session may still be open, or the logoff event was not captured.
- **RDP sessions (Type 10)** show `(wall clock)` appended to the duration. RDP sessions can have disconnect gaps (the session persists but the user is disconnected). Without EID 4778/4779 reconnect events, only wall-clock time can be reported.
- **Unavailable (no logon in log)** — the session is known only from later events (its logon is not in the loaded logs).

---

## Both Modes

View Logon Sessions works in both **Normal Mode** and **Juggernaut Mode**. The session browser is rebuilt from the in-memory events (Normal Mode) or the Arrow table (Juggernaut Mode). The session-filter applied to the main table uses the same mode-appropriate filter mechanism — proxy model filters in Normal Mode, Arrow table + Parquet key filter in Juggernaut Mode.

---

## Limitations

- Session reconstruction depends on the presence of EID 4624 in the loaded files. Sessions only seen via 4688 (process creates with no corresponding logon event) will appear as partial rows.
- If the logoff is in an EVTX file that was not loaded, the duration reads Unavailable; load that file to get it.
- Type-5 (Service) sessions represent Windows service accounts, not human users. Hide them with the checkbox to reduce noise.
- LUID reuse across reboots on the same host is handled automatically (see Session Identity above), but if logoff events are missing, the time-window boundary is estimated from the last seen event, which may be slightly imprecise.
- View Logon Sessions is GUI-only — not available from the CLI.

---

## Related Docs

- [Advanced Filter](06-advanced-filter.md) — clear or combine the session filter with other conditions
- [Analysis Tabs](09-analysis-tabs.md) — ATT&CK, IOC, and attack-chain analysis
- [Missing Record ID Analysis](09b-missing-record-ids.md) — detect log tampering via sequence gaps
- [PowerShell History Extraction](10b-ps-extract.md) — reconstruct PS sessions and commands
