# EventHawk 2.0 Four Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Process Dossier, Network Provenance, Persistence and Case Dossier in 2.0, on shared coverage,
evidence-reference and process-index foundations, equal in Normal and Juggernaut mode.

**Architecture:** Pure builders in `evtx_tool/analysis/` (and `evtx_tool/case/`) take event dicts; Juggernaut
workers only select rows by provider and event ID and hand the same dicts to the same builders. Each feature is
a non-modal window (Case is a dock); `main_window.py` gets wiring only.

**Tech Stack:** Python 3.12, PySide6, DuckDB / PyArrow (Juggernaut), ReportLab (PDF). No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-21-four-features-2.0-design.md`

## Global Constraints

- Tests are standalone scripts (`python tests\test_x.py`, exit 0 = pass, `check(name, ok, detail)` style);
  `tests/run_suite.py` collects every `tests/test_*.py`. Qt tests set `QT_QPA_PLATFORM=offscreen`.
- Synthetic test data only, with made-up hosts (`HOST-A.example`, `HOST-B.example`) and times; no values from
  real logs. Corpus runs report counts only.
- Sysmon only by provider `Microsoft-Windows-Sysmon`; Sysmon field names looked up case-insensitively.
- Missing data reads "Unavailable" with the reason, never 0, "none" or an empty table.
- Count each record once (`collapse_copies`); group hosts via `host_identity`; store UTC, display via `apply_tz`.
- Event text is untrusted: Qt plain text only, HTML/XML/PDF escaped, CSV through `exporters.csv_cell`.
- No GUI-thread work on event sets; workers owned by their window, cancellable, stopped on close, results tagged
  with the dataset generation and dropped when stale; Juggernaut asks first via `_jm_confirm_load`.
- WCAG 2.2 AA in Light and Dark, meaning never by colour alone; every new view in `tests/test_wcag.py`.
- New modules imported by name (PyInstaller `hiddenimports=[]`).
- Commits: by the user's git identity, no AI trailers, message file without BOM, `git commit -F`, files staged by
  name, on `beta`, never pushed without the user's yes.

## Review Focus

1. **Copies of a log and same-named files in different folders:** counts, trees and note re-attachment treat a
   copied record once and two different files as two. Tests in Tasks 3, 4, 5.
2. **Very large Sysmon sets (tens of thousands of image loads per process):** Juggernaut asks first; sections page
   with true totals; nothing silently capped. Tests in Tasks 4 and 11.
3. **Hostile event text** (`<b>`, `=cmd|`, `</script>`, control characters, right-to-left marks) in command lines,
   domains, task names: shown literally in every view and export. Tests in Tasks 7, 9, 11, 14.
4. **The dataset changes while a window or worker is open** (re-parse, add file, mode switch): no stale result,
   no crash, the window says it is out of date. Tests in Tasks 2, 9, 11, 14.
5. **Time zone or precision changed with a window open, and DST:** every time shown follows the setting; stored
   times never move. Tests in Tasks 9 and 11.

Revision 2 takes in an independent review of revision 1: content-aware
evidence refs with typed resolution, coverage from the input inventory with per-source ranges, bounded process
lifetimes, a compact Juggernaut index with paged sections, a case-file lifecycle, a PowerShell adapter, and the
schema verification moved before any code (Task 0).

---

### Task 0: Verify the event schemas and collect samples (S, no code)

**Files:**
- Modify: `docs/superpowers/specs/2026-11-21-four-features-2.0-design.md` (sections 2.3 and 5 tables)

- [ ] **Step 1:** for every (provider, event ID) in the process `FIELD_MAP` and the persistence table, check the
  channel, field names (with spelling per Sysmon version) and the audit setting against Microsoft documentation,
  and count it in the corpus (scratch harness, counts only). Write the source and the count into the spec tables.
- [ ] **Step 2:** list what has no sample in the corpus and ask the user for it (spec section 10). Mechanisms the
  user decides to ship without samples are marked "synthetic-only" in their coverage line.
- [ ] **Step 3:** commit the spec update ("2.0 spec: event schemas verified").

### Task 1: Coverage model and wording (M)

**Files:**
- Create: `evtx_tool/analysis/coverage.py`, `evtx_tool/analysis/coverage_text.py`
- Test: `tests/test_coverage.py`

**Interfaces:**
- Produces: `State` enum (`FULL`, `PARTIAL`, `UNAVAILABLE`); `Inventory(files: list[FileOutcome(path, size,
  events, skipped, truncated, error)])`; `Coverage.from_events(events, inventory, hosts: HostIdentity) ->
  Coverage`; `Coverage.from_rows(rows: list[tuple[provider, event_id, computer, source_file, raw_count,
  unique_count, min_ts, max_ts]], cmdline: dict[host, (total, empty)], inventory, hosts) -> Coverage`;
  `Coverage.has(provider, eid, host=None) -> bool`; `Coverage.span(provider, eid, host) -> (first, last) | None`
  (one source and ID, never a union); `Coverage.overlap(sources, host) -> (ranges, gaps)`;
  `Coverage.hosts() -> list[str]`;
  `need(cov, feature, section) -> Need(state, missing: list[str], per_host: dict[str, State])`;
  `REQUIREMENTS: dict[(feature, section), Requirement]`; `coverage_text.note(feature, section, need) -> str`.

- [ ] **Step 1: Write `tests/test_coverage.py`** with five synthetic datasets built by a local `ev(provider, eid,
  host, ts, **ed)` helper: (a) full Sysmon 1/3/22/7/11 + Security + System + TaskScheduler; (b) Security 4688
  only, with command lines; (c) no usable source (System 7036 only); (d) Sysmon 1 only; (e) HOST-A with Sysmon,
  HOST-B Security only. Assert for each, for features `process`, `network`, `persistence`: the state, the missing
  list, and `note()` text equal to the spec section 7 strings (P1-P5, N1-N4, S1). Also: a Sysmon event ID under
  provider `Microsoft-Windows-Security-Auditing` does not count as Sysmon; a 4688 with empty and with absent
  `CommandLine` both count as empty (P2 appears); `Coverage.from_rows` built from the same data's aggregate equals
  `from_events` (compare `hosts()`, `has()`, `span()` for every key); a host spelled `HOST-A`, `host-a.` and
  `Host-A` is one host; two events with a blank Computer from two files are two hosts; a file that loaded zero
  events and a failed file appear in the coverage details; a copied log doubles `raw_count` but not
  `unique_count`; Sysmon 3 from 10:00-11:00 and 22 from 12:00-13:00 give no overlap and the network "no
  observed" filters read Unavailable; no note text contains "complete" or names a Sysmon configuration as the
  cause of an absence.
- [ ] **Step 2: Run** `python tests\test_coverage.py`. Expected: ImportError / FAIL.
- [ ] **Step 3: Implement** both modules. `coverage_text` holds every string from spec section 7 in one dict keyed
  `(feature, section, state, missing_key)`; `note` fills event IDs and host lists.
- [ ] **Step 4: Run** the test. Expected: all PASS.
- [ ] **Step 5: Commit** "Coverage: what each view can see in the loaded logs".

Back-out: revert the commit; nothing else imports it yet.

### Task 2: Coverage banner and Juggernaut aggregate (M)

**Files:**
- Create: `evtx_tool/gui/coverage_banner.py`, `evtx_tool/gui/coverage_worker.py`
- Modify: `evtx_tool/gui/main_window.py` (dataset generation counter `self._dataset_gen`, bumped in
  `_clear_results` and after every parse; `current_coverage()` cache), `tests/test_wcag.py`
- Test: `tests/test_coverage_banner.py`

**Interfaces:**
- Consumes: Task 1.
- Produces: `CoverageBanner(QFrame)` with `set_need(feature, section, need)` and `collapsed` property;
  `CoverageAggregateWorker(QThread)` with `done = Signal(object, int)` (Coverage, generation) and
  `failed = Signal(str)`; `MainWindow.current_coverage(callback)` (Normal: computed in a worker thread from the
  event list; JM: the aggregate SQL `COVERAGE_SQL` over the manifest's shards).

- [ ] **Step 1: Write the test:** banner text equals `note()` for FULL / PARTIAL / UNAVAILABLE; text format is
  `Qt.PlainText` (a note containing `<b>x</b>` renders those characters); `accessibleName()` is non-empty;
  collapsing keeps a one-line label and cannot hide the widget; a JM synthetic Parquet (pattern of
  `tests/test_system_activity_gui.py::write_jm`) gives a `Coverage` equal to `from_events` on the same events; a
  result tagged with an older generation is ignored (Review Focus 4). Add the banner in all three states to
  `tests/test_wcag.py` in Light and Dark.
- [ ] **Step 2: Run** both tests. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** both tests. Expected: PASS.
- [ ] **Step 5: Commit** "Coverage banner and Juggernaut coverage query".

Back-out: revert; the generation counter is inert without consumers.

### Task 3: Evidence reference (S)

**Files:**
- Create: `evtx_tool/core/evidence_ref.py`
- Test: `tests/test_evidence_ref.py`

**Interfaces:**
- Consumes: `record_identity`, `host_identity.name_key`.
- Produces: `EvidenceRef(kind: str, key: tuple)` (frozen dataclass, hashable); `content_digest(ev) -> str`;
  `ref_for_event(ev) -> EvidenceRef` (`event` = identity + digest; `event-file` when no record ID, "unresolved"
  until the file digest exists); `ref_for_process(host, guid=None, pid=None, start=None, start_ref=None)`;
  `ref_for_ioc(type, value)`; `ref_for_chain(rule, member_refs)`; `ref_for_session(host, logon_id,
  logon_ref)`; `ref_for_persistence(host, mechanism, mech_key: tuple)`; `ref_for_netrow(host, proc_ref,
  query_ref, conn_ref, window_s)`; `to_json() -> list`, `EvidenceRef.from_json(list)` (raises `ValueError`);
  `snapshot(kind, obj) -> dict` (typed per kind, spec 2.2); `ResolveContext` and `resolve(ref, ctx) ->
  Resolved(state: "loaded" | "not-loaded" | "ambiguous" | "unresolved", obj, matches)`, with resolvers for later
  kinds registered by their tasks through `register_resolver(kind, fn)`.

- [ ] **Step 1: Write the test:** the same record in `Security.evtx` and `Security - Copy.evtx` gives one ref and
  resolves to one match with its copy listed; same-named files in two folders with different records give two
  refs; two records with the same identity and different event data give two refs, and resolving each finds its
  own (Codex 1); an event without a record id gives an `event-file` ref that resolves "unresolved" until the file
  digest is supplied; GUIDs `{ABC...}` and `abc...` give one process ref; the null GUID gives no `process` ref;
  LogonId `0x3E7` and `0x3e7` equal; two lookups of one domain by one process give two `netrow` refs, and the same
  pair at window 300 and 600 gives two; JSON round trip equal for every kind; `from_json` on `[]`, `["event"]`,
  `["x", 1]` raises `ValueError`; a chain ref is independent of member order; a kind with no registered resolver
  resolves "unresolved", never raises.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** "One evidence reference for events, processes, IOCs, chains, sessions and items".

Back-out: revert.

### Task 4: Process index (L)

**Files:**
- Create: `evtx_tool/analysis/process_index.py`, `evtx_tool/gui/process_index_worker.py`
- Modify: `evtx_tool/analysis/ps_extractor/event_parsers.py` (expose `decode_encoded_command(text) -> str | None`
  as a public alias of `_decode_b64_command` usage)
- Test: `tests/test_process_index.py`, `tests/test_process_index_parity.py`

**Interfaces:**
- Consumes: Tasks 1, 3; `collapse_copies`.
- Produces: `FIELD_MAP: dict[(provider_lc, eid), FieldSpec(role, actor_guid, actor_pid, target_guid, target_pid,
  section)]` (from Task 0's verified table); `relevant_core(ev) -> bool` (starts, ends, boot markers) and
  `CORE_SQL`; `section_counts_sql()` and `section_page_sql(section, proc_ref, offset, limit)` for Juggernaut;
  `build(core_events, activity_events=None) -> ProcessIndex`; `ProcessIndex.nodes: dict[EvidenceRef,
  ProcessNode]`, `.children(ref)` (time order), `.ancestors(ref)`, `.section_count(ref, name) -> int`,
  `.section_page(ref, name, offset, limit) -> list[EvidenceRef]` (Normal: from memory; JM: a query),
  `.unattributed: Counter` by reason; `ProcessNode` as in spec 3 with `lifetime_bound: "end" | "boot" |
  "next-start" | "open"`, `orphan: bool`, `ambiguous_parent: list[EvidenceRef]`;
  `ProcessIndexWorker(QThread)` honouring `_jm_confirm_load`'s contract: constructor `(parquet_dir, parent=None,
  count_only=False)`, signals `finished = Signal(object, bool)`, `fetch_error = Signal(str, str)`,
  `counted = Signal(object)`; cancellation checked between batches, `con.interrupt()` on Stop.
- Also: `evtx_tool/analysis/ps_adapter.py`, `to_ps_records(events) -> list` and `ps_sections(index, events)`
  that feed the PowerShell extractor's session builder from window events (400/403/600/800/4103/4104) and keep
  every fragment's event ref (Codex 9).

- [ ] **Step 1: Write `tests/test_process_index.py`:** a synthetic tree (root > shell > child x2) in Sysmon 1 with
  matching 5s gives exact parents, lifetimes and time-ordered children; Sysmon 3/7/11/22 attach to the actor;
  Sysmon 8 and 10 attach to both actor (`as_actor`) and target (`as_target`) under both field spellings; a child
  whose parent start is missing gets a placeholder parent holding the child's `ParentImage` / PID; activity with a
  GUID and no start gives an orphan node; activity with a null GUID and a PID uses the PID fallback (inferred);
  4688-only data links by creator `ProcessId` (hex) with `inferred=True`; a reused PID picks the process alive at
  the child's start, and a boot marker between ends the earlier process (`lifetime_bound == "boot"`); two equally
  valid parents give `ambiguous_parent` with both; a parent cycle is broken and counted; corroboration: a 4688 at
  0 s, at exactly 2 s and at 2.001 s; two 4688s for one Sysmon 1 and one 4688 for two Sysmon 1 both give
  "ambiguous", never a match; the same GUID on two hosts gives two nodes; two blank-Computer files give two hosts;
  a copied log does not duplicate nodes or section entries (Review Focus 1); events with no `event_data` and PID
  `"abc"` land in `unattributed` by reason and nothing raises; a node with 30,000 Sysmon 7 events reports
  `section_count == 30000` and pages of 200 (Review Focus 2). `tests/test_ps_adapter.py`: a 3-fragment 4104
  block keeps three fragment refs; a 400/403 pair gives one session; PowerShell-only data fills the PowerShell
  section with no Sysmon present.
- [ ] **Step 2: Write `tests/test_process_index_parity.py`:** the same synthetic events through Normal `build()`
  and through a JM Parquet + `CORE_SQL` + paged section queries give identical node refs, parents, section counts
  and the first two pages of each section; the worker passes `_jm_confirm_load`'s count step; Stop during a fetch
  ends the worker within 2 s (subprocess, return code 0).
- [ ] **Step 3: Run all three.** Expected: FAIL.
- [ ] **Step 4: Implement** the modules and worker (count first, `_jm_confirm_load` above the System Activity
  threshold; the window caches the index per `_dataset_gen` and holds the shard directory while it does).
- [ ] **Step 5: Run all three.** Expected: PASS.
- [ ] **Step 6: Corpus check** (scratch harness): build the index on the Sysmon corpus logs in both modes; report
  node count, share of Sysmon 1 with a found parent, orphan and unattributed counts per reason, and per-section
  totals against an independent DuckDB / Get-WinEvent count by `ProcessGuid` (every total must match). On the
  largest documented collection in Juggernaut, record peak memory and the time from Stop to idle.
- [ ] **Step 7: Commit** "Process index: compact, bounded lifetimes, every process event attributed or counted".

Back-out: revert; `_GuidIndex` is untouched.

### Task 5: Case model and file (M)

**Files:**
- Create: `evtx_tool/case/__init__.py`, `evtx_tool/case/model.py`, `evtx_tool/case/store.py`,
  `evtx_tool/case/attach.py`
- Test: `tests/test_case_store.py`

**Interfaces:**
- Consumes: Task 3; `exporters._refuse_evtx_destination`.
- Produces: `Case`, `Note` dataclasses (spec 6, with `aliases: dict[ref, ref]`), `SCHEMA_VERSION = 1`;
  `save(case, path, revision) -> None` (atomic; refuses EVTX by extension or header; removes a failed temporary
  file); `load(path) -> Case` raising `CaseFileError(message)` for damaged, newer-schema or invalid files;
  `CaseSaver` (one save at a time, drops a save whose revision is older than the last written, reports
  `saved(revision)` / `save_failed(message)`); `attach(case, ctx: ResolveContext) -> dict[note_id, Resolved]`
  (all kinds through `resolve`; Juggernaut event refs in batches).

- [ ] **Step 1: Write the test:** save then load is equal; the write goes through a temporary file and
  `os.replace` (patch `os.replace` to raise: the old file is intact and the temporary file is gone); a `.evtx`
  destination and a file named `.json` that starts with the EVTX header both raise; a read-only destination
  gives `save_failed` and the case in memory is unchanged; three quick saves where the first finishes last leave
  the newest revision on disk; truncated JSON, a JSON list, schema 2 and a note without `ref` each raise
  `CaseFileError` with a readable message; notes re-attach to a loaded copy of their log and to an excerpt
  (header number differs, EventRecordID same); a note whose event is not loaded resolves `not-loaded` and stays
  after save/load; two same-named files in different folders attach to the right one; a note on a
  `process-inferred` ref keeps resolving after a Sysmon log is added and gains an alias; Normal and Juggernaut
  `attach` agree on a synthetic Parquet.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** "Case file: notes on evidence, saved atomically, re-attached on load".

Back-out: revert; nothing uses it yet.

### Task 6: Case dock, bookmarks as notes, "Add to case" on existing views (M)

**Files:**
- Create: `evtx_tool/gui/case_dock.py`
- Modify: `evtx_tool/gui/main_window.py` (File menu: New / Open / Save case; event context menu, IOC rows, chain
  rows, Logon Session rows: "Add to case"; Bookmarks tab note column; `_clear_results` keeps the case and
  re-attaches after parse), `tests/test_wcag.py`
- Test: `tests/test_case_gui.py`

**Interfaces:**
- Consumes: Tasks 3, 5.
- Produces: `CaseDock(QDockWidget)` with `add(ref, snapshot)`, `case` property, `changed = Signal()`;
  autosave 2 s after `changed`; `MainWindow.add_to_case(ref, snapshot)` for later tasks.

- [ ] **Step 1: Write the test** (offscreen, synthetic events in Normal and in a JM Parquet): Ctrl+B creates a note
  with empty text; adding from an event, an IOC row, a chain and a session creates notes of the right kind; a
  re-parse keeps every note and re-attaches them; opening a damaged case shows a message and the window stays
  usable; autosave writes once after several quick edits; a new case autosaves to the per-user folder as
  untitled until "Save as"; the unsaved-changes marker shows and clears; closing the window 0.5 s after an edit
  still saves it; New and Open with unsaved edits save first, and if that save fails they ask; the analyst name
  is asked once per case; note text with `<img src=x>` shows literally; the dock floats and docks; it passes
  `test_wcag` in both themes.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run,** plus `tests/test_bookmark*.py` and `tests/test_detail_refresh_and_bookmark_clear.py`.
  Expected: PASS.
- [ ] **Step 5: Commit** "Case dock: notes and bookmarks saved with the case".

Back-out: revert; bookmarks return to session-only.

### Task 7: Case export pack (M)

**Files:**
- Create: `evtx_tool/output/case_sections.py` (section data shared by HTML and PDF)
- Modify: `evtx_tool/output/exporters.py` (`export_html(..., case=None)`, the `export_pdf` wrapper forwards
  `case`), `evtx_tool/output/pdf_exporter.py` (`export_pdf(..., case=None)`), `evtx_tool/gui/case_dock.py`
  (Export pack button: HTML, PDF, JSON)
- Test: `tests/test_case_pack.py`

**Interfaces:**
- Consumes: Tasks 1, 5, 6.
- Produces: `case_sections.build(case, ctx: ResolveContext, coverage) -> list[Section]`; `export_case_pack(case,
  ctx, dir, formats) -> list[path]`; later tasks register item renderers with `case_sections.register(kind, fn)`.
  A note whose ref is not loaded, ambiguous or unresolved is exported with its snapshot and its state, never left
  out; the test adds one of each.

- [ ] **Step 1: Write the test:** HTML pack has header, summary labelled "Analyst's notes", timeline, notes by
  kind, limits section with every coverage note and the "preserve the original EVTX files" line, and the footer
  text; it contains no `http://` / `https://` resource reference and no `<script src`; notes, tags, case name and
  analyst with `</script><b>` and `=cmd|' /C calc'!A0` are escaped; a case with 1,000 notes lists 1,000 in the PDF
  (the 500 limit applies only to the events table); a CJK and Arabic note draws in the PDF (font path of
  `pdf_exporter`); `export_html` without `case` produces byte-identical output to before (golden from the current
  code); JSON copy loads with `store.load`.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run,** plus `tests/test_export*.py`. Expected: PASS.
- [ ] **Step 5: Commit** "Case pack: HTML, PDF and JSON with notes, coverage and limits".

Back-out: revert; `case=None` keeps exports as before.

### Task 8: Logon session builder out of the window (S)

**Files:**
- Create: `evtx_tool/analysis/logon_sessions.py`
- Modify: `evtx_tool/gui/main_window.py` (`_LogonSessionDialog._build_sessions` calls the module)
- Test: existing `tests/test_logon*.py`, `tests/test_session*.py`; new `tests/test_logon_sessions_module.py`

**Interfaces:**
- Produces: `build_sessions(events) -> list[dict]` (same dicts as today); `session_for(sessions, host, logon_id,
  at) -> dict | None`.

- [ ] **Step 1: Write the test:** three synthetic collections (plain logon/logoff, logoff missing, a reboot in
  between) with the expected sessions written out by hand; the module gives exactly those, and the existing
  session tests pass unchanged on the pre-move commit and after.
- [ ] **Step 2: Move** the builder together with the instance helpers it calls (`_calc_duration` and the
  others it reaches), keeping boot-barrier and precision behaviour; the dialog keeps thin wrappers.
- [ ] **Step 3: Run** the new and existing session tests. Expected: PASS.
- [ ] **Step 4: Commit** "Logon sessions: builder in its own module".

Back-out: revert.

### Task 9: Persistence builder and window (L)

**Files:**
- Create: `evtx_tool/analysis/persistence.py`, `evtx_tool/gui/persistence_window.py`
- Modify: `evtx_tool/gui/main_window.py` (Tools > Persistence; JM fetch through the shared row-select worker),
  `tests/test_wcag.py`, `evtx_tool/output/case_sections.py` (register `persistence`)
- Test: `tests/test_persistence.py`, `tests/test_persistence_parity.py`, `tests/test_persistence_gui.py`

**Interfaces:**
- Consumes: Tasks 1-8.
- Produces: `MECHANISMS` table (spec 5, only verified rows enabled); `relevant(ev)`, `RELEVANT_SQL`;
  `build(events, index=None, sessions=None) -> PersistenceResult(items: list[Item], coverage: dict[mechanism,
  Need])`; `Item(ref, host, mechanism, name, runs, account, first_created, last_changed, deleted, status, hints:
  list[str], evidence: list[EvidenceRef], actor: EvidenceRef | None)`.

- [ ] **Step 1:** take the mechanism table from the spec as verified in Task 0; only verified rows are enabled.
- [ ] **Step 2: Write `tests/test_persistence.py`:** per mechanism, created / modified / deleted / created and
  deleted / deleted and recreated sequences give the right status and times; a change with no creation in the
  logs reads "observed", creation Unavailable; two events at one timestamp keep record-ID order; 7045 with a
  kernel-driver type is a driver service, and a Sysmon 6 alone reads "loaded (observed)", never "installed";
  a WMI binding keys on filter + consumer, two consumers with one name in two namespaces are two items; adding
  one account to two groups gives two membership items; BITS 5 and 16403 are evidence of their job;
  TaskScheduler 106 and Security 4698 for one task are one item with two evidence events; registry hints only on
  the autostart key list; hints fire with their reason text for a user-writable path, an encoded PowerShell
  command (decoded), a network-logon session; coverage per mechanism for datasets (a)-(e) of Task 1, including
  "Security 4698 not in the loaded logs" with TaskScheduler present and absent; a task name `=HYPERLINK(...)`
  round-trips literally.
- [ ] **Step 3: Write the parity test** (Normal vs JM synthetic Parquet: identical items) and the GUI test (opens
  with no Sysmon and shows S1 lines; "No items found" and "not covered" render differently in text, not only
  colour; evidence click selects the event in the grid; Around this event opens; Add to case adds a
  `persistence` note; the window's own HTML, CSV and JSON exports carry the coverage lines and the "changes inside
  the period" statement, CSV formula-safe, HTML offline; time zone change re-renders times (Review Focus 5); a
  re-parse marks the window out of date (Review Focus 4)).
- [ ] **Step 4: Run all three.** Expected: FAIL.
- [ ] **Step 5: Implement.**
- [ ] **Step 6: Run all three and `tests/test_wcag.py`.** Expected: PASS.
- [ ] **Step 7: Corpus check:** items per mechanism against an independent DuckDB count of the evidence events.
- [ ] **Step 8: Commit** "Persistence view: services, tasks, accounts, autostart, WMI, drivers, BITS".

Back-out: revert; remove the menu entry.

### Task 10: Process search (S)

**Files:**
- Modify: `evtx_tool/analysis/process_index.py`
- Test: `tests/test_process_search.py`

**Interfaces:**
- Produces: `search(index, query: str) -> list[Group(image, cmdline, instances: list[EvidenceRef], first, last,
  parents, users, hosts)]`.

- [ ] **Step 1: Write the test:** `rundll32.exe` matches every instance case-insensitively by image name, grouped
  by identical command line with correct counts; a path fragment, a SHA-256 from `Hashes`, a decimal and a hex
  PID and a GUID with braces each find their process; a query of only spaces returns nothing, not everything.
- [ ] **Step 2-4:** run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** "Process search".

### Task 10b: Per-program summary (S, may wait)

**Interfaces:**
- Produces: `aggregate(index, image) -> Aggregate(instances, cmdlines, parents, users, hosts, first, last,
  section_totals)`; the dossier window shows it when an image group is opened (Task 11 checks for it and falls
  back to the instance list when absent).

- [ ] **Step 1: Write the test** in `tests/test_process_search.py`: aggregate totals equal the sum over
  instances; copies counted once.
- [ ] **Step 2-4:** run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** "Per-program summary in the Process Dossier".

### Task 11: Process Dossier window (L)

**Files:**
- Create: `evtx_tool/gui/process_dossier.py`
- Modify: `evtx_tool/gui/main_window.py` (event context menu "Open process dossier", Tools menu, IOC process and
  command-line pivots, chain members, Logon Sessions "Processes in this session"), `tests/test_wcag.py`,
  `evtx_tool/output/case_sections.py` (register `process`)
- Test: `tests/test_process_dossier_gui.py`

**Interfaces:**
- Consumes: Tasks 1-4, 6, 8, 10.
- Produces: `ProcessDossierWindow(QWidget)`, one per main window, one tab per opened process, with
  `open_ref(ref)`, `open_search(text)`; `export_dossier(node, index, path, fmt)` (HTML, JSON); a `process`
  resolver registered with `evidence_ref.register_resolver`.

- [ ] **Step 1: Write the test** (offscreen; Normal and JM): opening from a Sysmon 3 event selects its actor;
  arrow keys move, Left / Right collapse and expand, every node has an accessible name; the placeholder parent
  reads "parent not in loaded logs"; a 4688-only dataset shows P1, links marked inferred, every activity section
  showing its "needs Sysmon Event ID N" line; P2 appears for a 4688 without command line; a 30,000-row section
  shows 200 rows, "page 1 of 150" and the total (Review Focus 2); a command line with `<b>` and an RLO character
  shows literally (Review Focus 3); the encoded command is shown decoded beside the original; "Show all in grid"
  filters the grid to exactly the section's events; time zone change re-renders (Review Focus 5); closing the
  window during a JM build stops the worker without a Qt abort (subprocess run, return code 0); a re-parse marks
  it out of date (Review Focus 4); the exported HTML has no network reference and the coverage lines.
- [ ] **Step 2: Run.** Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, plus `tests/test_wcag.py`.** Expected: PASS.
- [ ] **Step 5: Commit** "Process Dossier: tree and details in one window".

Back-out: revert; remove the menu and context entries.

### Task 12: Network Provenance builder (M)

**Files:**
- Create: `evtx_tool/analysis/net_provenance.py`
- Modify: `evtx_tool/analysis/ioc_scorer.py` (public `score_domain(value) -> tuple[int, list[str]]` over the
  existing heuristics)
- Test: `tests/test_net_provenance.py`, `tests/test_net_provenance_parity.py`

**Interfaces:**
- Consumes: Tasks 1, 3, 4.
- Produces: `parse_query_results(s) -> QR(cnames: list[str], ips: list[str], unknown: list[str])`;
  `build(index, events, window_s=300) -> NetResult(rows: list[Row], by_process, by_domain, coverage, spans:
  dict[host, (first, last)])`; `Row` fields per spec 4 with `match: "same-process" | "same-process-inferred" |
  "other-process" | "dns-only" | "connection-only"`.

- [ ] **Step 1: Write the test:** `parse_query_results` on `type:  5 a.example;::ffff:192.0.2.1;192.0.2.2;`,
  on IPv6, on an empty string and on `garbage;;` (unknown kept); one query and two connections inside the window
  link both; a connection at exactly 300 s links and one at 300.001 s does not at the default, but does at
  `window_s=600`; a connection before the lookup never links; an inbound connection (`Initiated` false) is listed
  and never linked; `::ffff:192.0.2.1` in the answer matches `192.0.2.1` as destination and the reverse; a copied
  log gives no duplicate rows; outside the overlap of the 3 and 22 ranges the "no observed" filters are
  Unavailable; the match column reads as an association, not as proof; one IP answered
  for two names gives two links; another process's answer gives an `other-process` row and never a
  `same-process` one; Sysmon 3 only marks DNS columns Unavailable (N2) and Sysmon 22 only marks connection
  columns Unavailable (N3); failed lookups (`QueryStatus` 9003) filter; domain `<script>` and `=1+1` survive
  literally; per-host spans equal the min/max of that host's 3 and 22 events. Parity test: Normal vs JM equal rows.
- [ ] **Step 2-4:** run (FAIL), implement, run (PASS).
- [ ] **Step 5: Corpus check:** rows per match kind on the corpus Sysmon log against an independent DuckDB join.
- [ ] **Step 6: Commit** "Network Provenance: DNS query to connection to process".

### Task 13: Network Provenance window (M)

**Files:**
- Create: `evtx_tool/gui/net_provenance_window.py`
- Modify: `evtx_tool/gui/main_window.py` (Tools menu; Threat Intel handoff), `tests/test_wcag.py`,
  `evtx_tool/output/case_sections.py` (register `netrow`)
- Test: `tests/test_net_provenance_gui.py`

- [ ] **Step 1: Write the test:** with no Sysmon the window shows N1 and no table; mode switch changes grouping
  only; text search and each column filter narrow the rows to the expected set; "Around this event" opens an
  Around tab at the row's query or connection; each filter's tooltip carries the spec's false-alarm text; the process cell opens its dossier; CSV export
  is formula-safe, HTML escaped and offline, JSON carries the coverage lines and window; Threat Intel receives the
  selected domain; Add to case adds a `netrow` note; out-of-date marking on re-parse; WCAG both themes.
- [ ] **Step 2-4:** run (FAIL), implement, run (PASS).
- [ ] **Step 5: Commit** "Network Provenance window".

### Task 14: Docs, packaging, full verification (M)

**Files:**
- Create: `docs/10g-process-dossier.md`, `docs/10h-network-provenance.md`, `docs/10i-persistence.md`,
  `docs/10j-case-dossier.md`
- Modify: `README.md`, `docs/02-gui-overview.md`, `docs/09-analysis-tabs.md`, `docs/11-exporting.md`,
  `docs/22-testing.md`, `tests/test_version_doc_drift.py` if it lists guides

- [ ] **Step 1:** write the guides in the existing tone ("review priorities, not proof"), with the coverage
  wording and no performance claims.
- [ ] **Step 2:** build the portable and the installer (`build_standalone.ps1`), and in both the extracted copy and
  the installed copy open each view on a log without Sysmon and on a Sysmon log (smoke script, subprocess return
  code 0). The final report lists every part proven only on synthetic data.
- [ ] **Step 3:** full suite `python tests\run_suite.py` with the corpus variables set. Expected: every file OK.
- [ ] **Step 4:** corpus runs from Tasks 4, 9, 12 repeated on the final commit; counts in the WORKLOG.
- [ ] **Step 5: Commit** "Guides for the four 2.0 views".

## What ships in 2.0 and what waits

Ships: Tasks 0-14. Waits for 2.1: Security 5156 and DNS-Client fallbacks (5158 is a local bind permission, not a
connection, so it is not a fallback at all), beaconing, Code Integrity as a persistence mechanism, baseline
comparison, "include full event data" in the case file, CLI commands.

**Cut line if 2.0 cannot hold all four:** drop Tasks 12-13 (Network Provenance) whole, first: it is Sysmon-only and
the corpus has 51 connections and 28 lookups on one host, so it is the least provable. Next drop Task 10b (the
per-program summary; search stays, because the dossier needs it). Foundations, Case, Persistence and the Dossier
stay: Persistence and Case work on default Windows logs. A feature is never shipped half-built: its window and
menu entry arrive in the same task as its full behaviour.

**Build order changed from the request:** Case (Tasks 5-7) comes before the views, because the evidence key is
ready after Task 3 and each later view then adds its own "Add to case" in its own task instead of a final pass
over every window. Persistence comes before the Dossier because it works without Sysmon and exercises the
coverage component on the most common data.

Every task is one or two commits on `beta`. Backing out works in reverse dependency order: a view task (9, 11, 13)
reverts alone, since nothing imports a window; a foundation task (1-5) reverts only after every task that uses it.
Each menu entry is added in the task that builds its window, so a reverted view leaves no dead entry, and the
`case_sections.register` / `register_resolver` calls live in the view's own task, so reverting a view also
removes its renderer.

Dependencies: 0 → 1 → 2; 3 → 5 → 6 → 7; 1, 3 → 4; 4, 8 → 9, 10 → 11; 10 → 10b; 4 → 12 → 13; all → 14.
