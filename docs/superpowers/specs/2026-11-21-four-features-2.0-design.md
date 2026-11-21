# EventHawk 2.0: Process Dossier, Network Provenance, Persistence, Case Dossier (design)

Dated 2026-11-21. Status: proposal, waiting for approval. No real host, user or log data appears here; corpus
figures are counts only. Revision 2 takes in an independent review by Codex (ten findings, six High, all about
the proposal: evidence keys, coverage claims, process fallback, Juggernaut scale, case lifecycle, non-event
notes); each change below says where it came from.

## 1. Verification of the facts the request relied on

| Claim | Verdict | What the code says |
|---|---|---|
| `_GuidIndex` indexes only 1 and 4688 | **Partly wrong** | `_PROC_EIDS = {1, 4688}`, but a record without `ProcessGuid` is skipped before the ID test. 4688 has no GUID, so it never enters: the index is Sysmon 1 only. It also checks no provider. Sysmon 7/10/11 attach to nothing (confirmed). |
| Sysmon 22 has a description, `T1071.004`, a label in profile 07; `QueryName` / `QueryResults` unread | Confirmed | No reference to either field in `evtx_tool/` or `sentinel/`. |
| Sysmon 3 tagged `T1071`, IOC extractor reads `DestinationIp`, no join | Confirmed | |
| IOC extractor reads `Image`, `CommandLine`, `TargetFilename`, `TargetObject`, Sysmon 7 DLLs, 17/18 pipes | Confirmed | Its free-text IP/domain scan stops at 2,000 characters per value and 4,000 per event (no IOC missed in the corpus, but a lead could be). |
| Sentinel reads only Sysmon 1, 5, 8, 10 and 4688, 4689 | Confirmed | With a provider check per ID. |
| Case notes not wired; `pdf_exporter.py` unchecked | **Worse than stated** | `export_html(..., **_)` accepts and silently ignores a `case=` argument. `pdf_exporter.export_pdf` promises a cover page with case name and analyst and a "Case Notes" section in its docstring but has no `case` parameter, and the `exporters.export_pdf` wrapper forwards only events, path, `attack_summary`, `iocs` and `chains`. Juggernaut offers no PDF export today. |
| Bookmarks session-only, `(source_file, record_id)` | Confirmed | Cleared by `_clear_results` (every reset / re-parse) and by "Clear All". |
| Profiles 01, 09, 10, 11, 25, 28, 29, 33 hold the persistence IDs | Confirmed | Each is scoped by provider (`sources`), so BITS 3 is not Sysmon 3. |
| Joins to reuse | Partly | The Logon Sessions builder is an instance method inside `main_window.py` (`_LogonSessionDialog._build_sessions`), not an `analysis/` module, so a dossier cannot call it without extracting it first. The PowerShell session builder matches by `HostId`, then `ProcessID`. |

Other points where the request and the code differ:

- **4688 has no `ParentProcessId`.** The creator is `ProcessId` (hex) and the new process `NewProcessId` (hex);
  `ParentProcessName` exists from Windows 10. The inferred link uses those.
- **Sysmon 10 spells `SourceProcessGUID` / `TargetProcessGUID`**, Sysmon 8 `SourceProcessGuid` /
  `TargetProcessGuid` (checked on corpus logs). Field lookup must ignore case.
- **`QueryResults` format** (corpus, values masked): `;`-separated entries, CNAMEs as `type:  5 <name>`, IPv4 as
  plain or IPv4-mapped `::ffff:<ipv4>`, IPv6 plain. A trailing `;` is normal.
- **`run_suite.py` collects every `tests/test_*.py` by itself**; nothing needs registering.
- **Packaging (corrected by Codex):** `EventHawk.spec` analyses only the thin `launcher.py`;
  `build_standalone.ps1` copies the application packages whole and `EventHawk.iss` installs them recursively. New
  modules ship by being in the package, and must be proven in the copied runtime and the installed build.
- **Corpus coverage of the inputs** (logs of 20 MB or less plus the mid-size set): Sysmon 1 1,824, 3 **51**, 22
  **28** (one host), 7 76,580, 11 39,573, 12/13 ~145,000, 17/18 ~2,100, 6 3, 19/20/21 **0**. Security 4688 3,280,
  of which the small-log set has no command line in any of its 688 (field absent or empty). **No 4697, 4698-4702,
  5156 or 5158 anywhere.** TaskScheduler 106/140/141, 7045, 7040, 5861, BITS and account events present.
  Network Provenance and several persistence mechanisms therefore cannot be proven on the corpus as it stands.

## 2. Shared foundations

### 2.1 Coverage

One pure module, `evtx_tool/analysis/coverage.py`, answers "what does this dataset contain" without loading
events in Juggernaut.

- `Coverage` holds, per host (the `HostIdentity` group, the same grouping the joins use; a blank Computer is
  never one shared machine, it is keyed per source file), per provider (lower case) and event ID: raw rows,
  records counted once (copies collapsed), and first and last UTC time, kept **separately per source and ID**,
  never as one union span. Per host it holds the 4688 total and how many have an empty or absent `CommandLine`.
- It is built from the **input inventory and parse outcomes** as well as the events, in both modes: files that
  loaded zero events, files that failed or were truncated, and files whose records were skipped (Juggernaut reuses
  the parse-integrity results the engine already records). A file that yielded nothing still appears.
- Normal mode: `Coverage.from_events(events, inventory)`. Juggernaut: `Coverage.from_rows(rows, inventory)` over one
  aggregate query (raw `count(*)` and a count of distinct record identities, min and max time, `GROUP BY` provider,
  event ID, computer, source file) plus one 4688 `CommandLine` count. Both produce equal objects (parity test).
- Overlap: `overlap(sources, host)` gives the time range where every source a join needs was observed, and the
  gaps. Two sources whose ranges do not overlap give "no overlapping time" rather than Full. Presence and range
  never prove continuous logging; the wording says "observed in the loaded logs", never "complete".
- Recomputed whenever the dataset generation changes (parse, add, remove, re-parse); the window keeps one
  `Coverage` per generation.
- `need(feature, section, hosts=None)` returns `FULL`, `PARTIAL` or `UNAVAILABLE` plus the missing inputs, per
  host and per section or mechanism (each gated independently). Requirements are data in one table
  (`REQUIREMENTS`), e.g. `("network", "dns"): sysmon {22}`. "Full" means "the required event types were
  observed", and its line says so.
- Sysmon is recognised only by provider `microsoft-windows-sysmon`. An absent ID is never explained as a Sysmon
  configuration choice: the logs cannot say why it is absent.

Wording lives in `evtx_tool/analysis/coverage_text.py`: `note(feature, section, state, missing, per_host) -> str`,
keyed by feature, section, state and missing source. The GUI banner, every export and the case pack call only
this function. The texts in the matrix (section 7) are its initial content.

Banner: `evtx_tool/gui/coverage_banner.py`, a `QFrame` with an icon and plain text (`Qt.PlainText`), an
accessible name, a "Details" link that opens a per-host table, collapsible to one line, never removable, not
modal. Full state shows only the one-line "Data coverage: the event types this view uses were observed in the
loaded logs · Details".

### 2.2 Evidence reference

`evtx_tool/core/evidence_ref.py`: `EvidenceRef(kind: str, key: tuple)`, frozen, with `to_json()` /
`from_json()` producing a canonical list. One kind per thing a note or link can point at:

| kind | key | survives copies / same-named files |
|---|---|---|
| `event` | `record_identity(ev)` plus a **content digest** (SHA-1 of the System content fields `collapse_copies` compares and the canonical event data) | yes: true copies share both; two records with the same identity but different content (which `collapse_copies` keeps apart) get different refs |
| `event-file` | only when the record has no record ID: (file content digest of its first MiB + size, record offset) | yes; until the digest is computed the ref is "unresolved", never guessed |
| `process` | (host, ProcessGuid lower, no braces) | yes |
| `process-inferred` | (host, PID int, start time UTC, start event ref) | yes, labelled inferred |
| `ioc` | (type, value) | yes |
| `chain` | (rule name, sorted member `event` refs) | yes; chain IDs are not stable between runs |
| `session` | (host, LogonId lower hex, logon event ref) | yes |
| `persistence` | (host, mechanism, mechanism key: e.g. service name; task path; WMI namespace + type + name; group + member) | yes |
| `netrow` | (host, process ref, query event ref or none, connection event ref or none, window seconds) | yes: repeated lookups and different windows stay distinct |

`host` above is the raw Computer normalised by `name_key`, so a stored key does not change when the analyst
later confirms or rejects a host link; resolution maps it through the current `HostIdentity` groups.

**Resolution, for every kind** (Codex 6): `resolve(ref, ctx) -> Resolved(state, obj, matches)` with `state` one
of `loaded`, `not-loaded`, `ambiguous` (several distinct candidates) or `unresolved`. Copies of one record are one
match listed with its copies. `ctx` is one shared object holding the loaded events or the Juggernaut directory,
the process index, sessions, persistence and network results, so the case pack and every view resolve the same
way. A `process-inferred` ref that a later Sysmon parse can match one-to-one gains an alias to the `process` ref;
the alias is stored in the case, and both stay visible.

**Snapshots are typed** per kind (event: time, host, event ID, provider, file name, description; process:
image, PID, start, host; session: account, LogonId, logon time; persistence: mechanism, name, status; netrow:
domain, IP, process, times; IOC and chain: their own fields), so a note stays readable when nothing is loaded.

### 2.3 Process index

`evtx_tool/analysis/process_index.py`, a new module; `_GuidIndex` is left alone (correlation rules use it).

- `relevant(ev)` selects process starts and ends and every activity event in `FIELD_MAP`; `build(events,
  hosts) -> ProcessIndex`.
- `FIELD_MAP` (one table, keyed by (provider, event ID)) names actor and target fields. Starts: Sysmon 1, Security
  4688. Ends: Sysmon 5, Security 4689. Activity: Sysmon 2, 3, 6 (no actor), 7, 8 (actor `SourceProcessGuid`,
  target `TargetProcessGuid`), 9, 10 (`SourceProcessGUID`, `TargetProcessGUID`), 11, 12, 13, 14, 15, 17, 18, 19-21
  (no GUID; host-level), 22, 23, 24, 25, 26. PowerShell comes through an adapter (Codex 9): the extractor's
  session builder works on parsed PowerShell records and uses 400/403/600/800 as well as 4103/4104, and its
  timeline keeps only the first 4104 fragment. The adapter turns the window's event dicts into those records,
  includes the classic IDs, and keeps every fragment's event ref next to the reassembled block. The PowerShell
  section needs PowerShell logs, not Sysmon. Each entry is checked against Microsoft's Sysmon schema and the
  corpus in the plan's Task 0.
- Nodes keyed by `process` refs (Sysmon) or `process-inferred` refs (4688).
- **Lifetimes are bounded** (Codex 3): a process ends at its end event, else at the next boot marker on that host
  (Kernel-General 12, Security 4608, the markers `host_power` already reads), else it is open ("end Unavailable").
  A PID belongs to a process only from its start until that bound or the next start of the same PID, whichever is
  first.
- **Cross-source corroboration is one-to-one and labelled inferred:** a 4688 with the same host, PID and image
  as a Sysmon 1 within a candidate window (2 s, a documented choice, tested at 0 s, exact boundary, ties and a
  reused PID) is shown as "also logged as Security 4688 (inferred match)"; both events stay listed. Two candidates
  on either side: no match, and the view says "ambiguous".
- Parent links: Sysmon by `ParentProcessGuid` (exact); 4688 by creator `ProcessId` on the same host, the process
  alive with that PID at the child's start under the bounds above (inferred, labelled); several candidates give
  "parent ambiguous" with the candidates listed. A cycle is broken and reported. A parent not loaded becomes a
  placeholder "parent not in loaded logs" carrying what the child says about it (image, PID, GUID).
- **Orphan activity:** a valid GUID with activity but no loaded start becomes an orphan node (lifetime unknown)
  so its events stay inspectable. Activity with a null GUID but a usable PID tries the PID fallback (inferred)
  before it is counted as `unattributed`.
- Never across hosts; a blank Computer is its own host per source file. Copies collapsed first with
  `collapse_copies`.
- Missing or null fields, unparsable PIDs and events with no `event_data` go to a counted `unattributed` bucket,
  by reason, that the view shows; nothing raises.
- **Juggernaut at scale** (Codex 4; the documented collections reach about 1.7M and 6.6M records): the index
  in memory is compact, process starts, ends and boot markers only, read by provider and event ID with field
  access through the existing `ed_flat_json` column. Activity sections are not loaded: their counts per process
  come from one `GROUP BY` query, and a section's rows are fetched a page at a time when the user opens it. Only
  "Show all in grid" or an export asks for more, with the count and an estimated size first. The fetch worker
  follows `_jm_confirm_load`'s contract (`finished` / `fetch_error` signals and a `count_only` constructor),
  checks for cancellation between batches and interrupts DuckDB on Stop; the window holds the shard directory
  for as long as the cached index refers to it. A corpus run must show peak memory and a cancel time before the
  feature is called done.
- Normal mode builds the same structure from the in-memory events. The window caches the index per dataset
  generation, so each dossier, Network Provenance and Persistence reuse it.

## 3. Feature 1: Process Dossier with the tree

**Layout:** one non-modal Process Dossier window, like System Activity and Logon Sessions, holding one tab per
opened process (Codex: one shared window and index, not an unlimited number of windows). Left: search box and
the tree (`QTreeView`, keyboard navigable, accessible names "image, PID, start time, N children"). Right: the
details pane for the selected node, a header block (identity) and collapsible sections, one table per activity
section. Coverage banner on top. *Alternative:* a dock inside the main window; rejected because the main grid
needs its width and the other investigation tools are separate windows.

**Entry points:** event context menu "Open process dossier" (any event the index can attribute); Tools > Process
Dossier (search first); IOC process / command line pivots; Chains (per member event); Logon Sessions ("processes
in this session", by host and LogonId, needs the session builder and its helpers extracted, plan Task 8).

**Search:** image name, path fragment, command-line text, hash, PID or GUID. Results are grouped by image and by
identical command line, with counts, first and last seen, parents, users, hosts. Opening an image group shows the
aggregate dossier: instances, distinct command lines, parents, users, hosts, per-section totals, each instance
clickable.

**Details:** image, original file name, command line (copyable; `-EncodedCommand` decoded with the PowerShell
extractor's decoder, shown as decoded text next to the original), current directory, user, integrity level,
LogonId (link to its session), hashes, company, product, description, parent image and command line, start, end,
lifetime ("Unavailable: no end event in the loaded logs" when absent). Fields a Sysmon version lacks read
"Unavailable (not in this event)".

**Sections:** as listed in the request (files, registry, network, DNS, image loads, injection and access in both
directions, pipes, WMI, PowerShell, same logon session). Each shows the true count, newest first, 200 rows per
page with "next page", "Show all in grid" (filters the main grid to the section's event refs) and per row "Open
event" / "Around this event". A section whose inputs are missing shows its coverage line instead of a table.

**Badges** (text plus icon): ATT&CK tags of its events, network, injection, file writes, in a chain.

**Data model:** `ProcessNode(ref, host, image, pid, guid, start, end, parent_ref, inferred: bool,
placeholder: bool, start_ev, end_ev, sections: dict[str, list[EvidenceRef]], corroboration: list[EvidenceRef])`.

**Export:** HTML (offline, escaped) and JSON of one dossier, with the coverage lines.

## 4. Feature 2: Network Provenance

**Layout:** one non-modal window: banner, a mode switch (Chains / By process / By domain), filter chips, table,
time-window field (seconds), export buttons. *Alternative:* a section only inside the Process Dossier; rejected
because the question is fleet-wide.

**Builder:** `evtx_tool/analysis/net_provenance.py`, `relevant(ev)` and `build(index, events, window_s=300)`.

- Parse `QueryResults` into CNAMEs and IPs (IPv4-mapped IPv6 unmapped to IPv4). Unknown tokens are kept as text
  and counted, never dropped.
- Same-process match: same host, same process ref (`ProcessGuid`, else host + PID + time, inferred), connection
  destination in the query's answers, connection time in `[query, query + window]`.
- Every link kept (many-to-many). A connection matching only another process's answer on that host is a
  separate "weaker: resolved by another process" row, never merged.
- Default window 300 s, adjustable: TTL is not logged, so this is a starting choice, not a measured rule. A
  longer window links more unrelated lookups; a connection opened before the lookup can never match, whatever the
  window. A match is a time association, "connected to an address this lookup returned", not proof that the
  connection used that answer; the column says so. The window is in every export and every `netrow` key.
- Only outbound connections (`Initiated` true) are matched to lookups; inbound ones are listed but never linked.
  IPv6 and IPv4-mapped addresses are normalised on both sides before comparing.
- Rows: time, host, process (dossier link), user, domain, status, answers, connections (IP, port, protocol,
  first, last, count), delay to first connection, match kind, review priority with reasons (the IOC scorer's
  domain heuristics, exposed as a public `score_domain(value) -> (score, reasons)`).
- Filters: Resolved and connected; Resolved, no observed connection; Connected, no prior lookup observed; failed
  lookups (`QueryStatus` not 0); first seen per host. Tooltips carry the false-alarm reasons from the request
  verbatim. Rare and high-entropy names come through the priority column. Beaconing: later.
- Coverage per host: the observed ranges of Sysmon 3 and of Sysmon 22, shown separately, and their overlap. Only
  the overlap supports the two "no observed ..." filters; outside it those filters read Unavailable.

**Fallbacks:** Security 5156/5158 would give process-to-IP for hosts without Sysmon, but the corpus has none, so
2.0 ships without them; they are a 2.1 item once samples exist. DNS-Client/Operational is off by default and, as
far as the plan can tell, does not name the requesting process (to confirm on samples); 2.0 does not use it.

## 5. Feature 3: Persistence view

**Layout:** one non-modal window: banner, a coverage table per mechanism (covered / not covered / partly, with
the reason), the item list (type, name, what runs, account, first created, last changed, deleted, host, status,
priority hints), and an evidence pane for the selected item. *Alternative:* a tab of the Analysis panel;
rejected because the list needs its own filters and evidence pane.

**Builder:** `evtx_tool/analysis/persistence.py`, `relevant(ev)`, `build(events, index=None)`. Items are keyed
per mechanism; status is computed from the ordered evidence (created, modified, deleted, created and deleted) "as
of the end of the loaded logs". The view and each export state: items created before the logs begin do not
appear; "deleted" means a deletion was logged.

| Mechanism | 2.0 | Evidence | Item key | Needs |
|---|---|---|---|---|
| Services | yes | System SCM 7045, 7040; Security 4697; Sysmon 13 on `...\Services\` keys | service name | 4697: "Audit Security System Extension" |
| Scheduled tasks | yes | Security 4698-4702; TaskScheduler 106, 140, 141 | task path | 4698-4702: "Audit Other Object Access Events" |
| Accounts | yes | Security 4720, 4722, 4724, 4738 | account SID, else name | "Audit User Account Management" |
| Group membership | yes | Security 4728, 4732, 4756 | group SID + member SID | "Audit Security Group Management" |
| Autostart registry | yes | Sysmon 12, 13, 14 on a fixed key list (Run, RunOnce, Winlogon, IFEO, AppInit, services); Security 4657 | key + value | Sysmon, or registry auditing with SACLs |
| WMI subscriptions | yes | WMI-Activity 5861; Sysmon 19 (filter), 20 (consumer), 21 (binding) | namespace + type + name; binding = filter + consumer | Sysmon for 19-21 |
| Driver services | yes | 7045 with a kernel / file-system driver type | service name | none |
| Driver loads | yes, as "loaded (observed)", never "installed" | Sysmon 6 | driver path + hash | Sysmon |
| Startup folder | yes | Sysmon 11 under a Startup folder | file path | Sysmon |
| BITS jobs | yes | Bits-Client 3, 4, 5, 59, 60, 61, 16403 (profile 29) | job id | none |
| Code Integrity | later | profile 28 | | not persistence by itself |
| Baseline comparison | later | | | |

Statuses come from the ordered evidence: created, modified, deleted, created and deleted, deleted and created
again (a recreation is a new item with a link to the old one), observed (a change or load with no creation in
the logs; creation time Unavailable). Events at the same timestamp keep their log order (record ID); a tie that
cannot be ordered is shown as such.

**This table is verified before any code** (Codex 8): the plan's Task 0 checks every provider, channel, event ID,
field name and audit setting against Microsoft documentation and the corpus, and writes the result into this
section. A mechanism that fails the check, or that has no sample log by then, is either moved to "later" or
shipped with its synthetic-only status stated in its coverage line, by the user's decision. Each persistence
result is also exportable on its own (HTML, CSV, JSON, with the coverage lines), not only through the case pack.

Hints, each with its reason in words: command or image under a user-writable folder; a script host or LOLBin
in what runs (decoded when encoded); created in a network logon session (the correlator's service-after-network
logon rule as model); created shortly after failed-then-successful logons for that account.

## 6. Feature 4: Case Dossier

**Layout:** a dock widget "Case" in the main window, which can be floated beside the other tool windows (notes list grouped by kind, summary and conclusions editor,
analyst field). It stays visible while the analyst works in other windows; each view's "Add to case" adds there.
*Alternative:* a separate window; rejected because notes are written while browsing the grid.

**Case file:** `evtx_tool/case/` package. `Case` (schema version 1, name, analyst, created and updated UTC,
EventHawk version, inputs: name, size, modified time, optional SHA-256, time-zone setting, analyses run, coverage
statement at save, summary, conclusions, notes). `Note(id, ref: EvidenceRef, snapshot, text, tags, created,
edited)`. Default tags: suspicious, benign, confirmed, follow-up.

- One JSON file, written atomically (temporary file in the same folder, then `os.replace`; a failed temporary
  file is removed). A destination that is an EVTX by extension or by its file header is refused with the
  existing `_refuse_evtx_destination`, which already checks both.
- **Lifecycle** (Codex 5): a new case lives in the per-user application folder as an untitled case until "Save
  as" moves it; the dock always shows whether there are unsaved changes. Autosave runs 2 s after the last change,
  one save at a time, each carrying a revision number, so an older save can never land after a newer one. Closing
  the window, New and Open first save (or, if saving fails, ask). A failed save (read-only folder, disk full) is
  shown in the dock and the status bar, the edits stay in memory and the previous file stays intact.
- Load: a damaged file, a newer schema or a missing field shows a message and opens nothing; the app keeps
  running. Older schemas are migrated in code.
- Re-attach: on load and after every parse, every note's ref goes through `resolve` (section 2.2); in
  Juggernaut event refs are resolved in batches with one query per batch on the identity columns. Notes show
  loaded, not loaded, ambiguous or unresolved with their snapshot and are never removed.
- Bookmarks become notes with empty text; Ctrl+B and the Bookmarks tab stay, with a note column. A re-parse
  clears the bookmark highlight but never the case.
- SHA-256 of inputs only on request, in a background worker with progress and cancel.
- No "include full event data" option in 2.0: snapshots keep notes readable, and full events in a file meant to
  be passed around would copy sensitive log content. The original EVTX files remain the evidence.

**Export pack:** `export_html` and `pdf_exporter.export_pdf` gain an explicit `case: Case | None = None` parameter
(and `**_` stops swallowing it); the wrapper forwards it. With a case: header, summary and conclusions (labelled
"Analyst's notes", never as findings), a timeline of annotated and bookmarked events, notes by kind, compact
copies of referenced dossiers, persistence items and network rows (from their builders, when loaded), and the
limits section: every coverage note, and "EventHawk keeps parsed values, not original XML; preserve the original
EVTX files". Footer: "An analyst's working record, not a chain-of-custody document." Plus a JSON copy of the case.
The 500-event preview limit applies to the events table only, never to notes. The pack works in both modes,
because it is built from the case and the referenced items, not from the grid.

## 7. Coverage matrix

States per feature for a dataset holding:

| Data | Process Dossier | Network Provenance | Persistence | Case pack header |
|---|---|---|---|---|
| Sysmon with 1, 3, 22 and activity IDs, plus Security, System, TaskScheduler | Full | Full | Full | "Sysmon events: present" |
| Security 4688 with command lines, no Sysmon | Partial (P1) | Unavailable (N1) | Partial (S1, for registry, startup, Sysmon WMI, Sysmon drivers) | "Sysmon events: none in the loaded logs" |
| Security 4688 without command lines | Partial (P1 + P2) | Unavailable (N1) | as above | as above |
| Sysmon 1 only | Partial: sections show their own lines (P3) | Unavailable (N1) | Partial (S1) | "present (some event types only)" |
| Sysmon 3 only | per section | Partial (N2) | as above | as above |
| Sysmon 22 only | per section | Partial (N3) | as above | as above |
| Several hosts, Sysmon on some | Partial per host (P4) | Partial per host (N4) | per host | "partly: per host table" |
| No process starts, no Sysmon | Unavailable (P5) | Unavailable (N1) | depends on System / Security / TaskScheduler | "none" |

Initial note texts (`coverage_text`, refine freely):

- **P1:** "No Sysmon events were found in the loaded logs. This view normally uses Sysmon for file, registry,
  network, DLL and injection activity. Process starts are shown from Security 4688 instead, so this picture is
  incomplete: no hashes, no activity sections, and parent links are less reliable. If Sysmon logs exist for these
  machines, add them and parse again."
- **P2:** "Security 4688 events here carry no command line. Recording it is a separate Windows audit setting
  (Include command line in process creation events), so command lines are Unavailable, not empty."
- **P3 (per section):** "Needs Sysmon Event ID N, not in the loaded logs." (N filled per section.)
- **P4:** "Sysmon events were found for some hosts only (listed under Details). Processes on the other hosts are
  shown from Security 4688 and marked limited."
- **P5:** "No process start events (Sysmon 1 or Security 4688) were found in the loaded logs, so this view cannot
  be used. Process creation auditing is off by default on Windows; if you have Sysmon or Security logs with it,
  add them and parse again."
- **N1:** "Network Provenance needs Sysmon Event ID 3 (network connection) and 22 (DNS query). No Sysmon events
  were found in the loaded logs, so this view cannot be used. Sysmon is not enabled on Windows by default. If you
  have Sysmon logs for these machines, add them and parse again." (When Sysmon is present without 3 and 22:
  "Sysmon events were found, but none of type 3 or 22 in the loaded logs, so this view cannot be used.")
- **N2:** "No DNS query events (Sysmon 22) in the loaded logs: domain columns and both DNS-based filters are
  Unavailable. This is not evidence that no lookups happened."
- **N3:** "No network connection events (Sysmon 3) in the loaded logs: connection columns and 'Resolved, no
  observed connection' are Unavailable."
- **N4:** per host, as P4, for Sysmon 3 and 22.
- **S1 (per mechanism):** "Run keys and other autostart registry entries: needs Sysmon Event ID 12, 13 or 14, not
  in the loaded logs, so this list may miss them." / "Security 4698 not in the loaded logs; scheduled-task
  creation may be hidden unless the TaskScheduler log is loaded."
- **Always, Persistence:** "The logs show changes inside the period they cover. Items created before the logs begin
  do not appear, and 'deleted' means a deletion was logged."

## 8. Cross-cutting rules

Both modes call the same builders; Juggernaut workers only select rows. No GUI-thread work over a few
milliseconds; every worker is owned by its window, cancellable with Esc / Stop, stopped on close, and tagged with
the dataset generation so a stale result is dropped. Counts are true; large sets are asked about first. All
event text is shown as plain text in Qt and escaped in HTML / XML / PDF; CSV through `csv_cell`. Times are stored
UTC and shown through `apply_tz` and the precision setting. WCAG: every new view and banner joins
`tests/test_wcag.py` in both themes. No new dependency. No CLI command in 2.0; every builder is a pure function.

## 9. Risks

1. **A note attached to the wrong evidence, or a process history that is a guess shown as fact.** Mitigated by
   content-aware refs, explicit ambiguous / unresolved states, bounded lifetimes and "inferred" labels; the tests
   must include identical-identity-different-content and reused-PID cases.
2. **Coverage presented more confidently than the logs permit, and thin real data.** 51 connections and 28 DNS
   queries on one host; no 4697, 4698-4702 or 5156 at all. Without sample logs those parts rest on synthetic tests,
   and the coverage lines must never say more than "observed".
3. **Juggernaut memory on large collections, and the size of `main_window.py`.** Loading activity for millions of
   events would exhaust memory; the compact index plus paged sections must be measured on the corpus. Every
   feature also needs wiring in a 21,000-line file with known Qt pitfalls.

## 10. Acceptance gate before implementation

Sample logs (Codex): paired Sysmon 1/5 and Security 4688/4689 from one host; Sysmon 3 and 22 from more than one
host; WMI 19-21; Security 4697 and 4698-4702; a mixed set where only some hosts have Sysmon; a file that loads
empty, a damaged file, and Sysmon and Security ranges that do not overlap. Parts without a sample are labelled
synthetic-only in the final report, and a suite exit code of 0 is not presented as evidence validation.
