# "Around this event" pivot and host identity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Right-click any event to open the events around it (this host, this host + suggested names, or all hosts) in a new tab, in Normal and Juggernaut mode, with "this host" meaning every name the machine logged under.

**Architecture:** A pure-logic `HostIdentity` (no Qt) groups a machine's Computer names from EID 6011 renames, the domain suffix, and (as suggestions) shared local log files; Computer Normalisation is rebuilt on it. A pure-logic `time_window` module owns timestamp parsing and inclusive UTC bounds. `MainWindow` adds the menu, the dialogs and an "around" tab that follows the chain-tab pattern in Normal mode (`EventTableModel` over references to existing event dicts) and the per-file-tab pattern in Juggernaut mode (`ArrowTableModel` with `fixed_where`).

**Tech Stack:** Python 3.12, PySide6, pyarrow, DuckDB, pyevtx-rs (`evtx`). Tests are standalone scripts in `tests/` using the repo's `check(name, cond, detail)` / "N/N checks passed" / exit-code convention.

**Spec:** `docs/superpowers/specs/2026-10-23-time-window-pivot-and-host-identity-design.md`

## Global Constraints

- Both modes: every behaviour exists in Normal and Juggernaut (JM) mode, and the same pivot gives the same rows in both.
- Bounds are computed in UTC from the stored timestamps: `[anchor − before, anchor + after]`, inclusive at both ends; sub-second precision kept.
- Display in the analyst's display time zone via `models.apply_tz` (DST rule of each event's own date); never today's offset.
- No row cap in either mode.
- Custom window: before and after separately, each a number and a unit (minutes, hours, days), from 0 up to 365 days.
- Presets: ±1 min, ±5 min, ±15 min, ±1 hour, ±1 day.
- `(unknown)` (blank Computer) is never linked to anything; IPv4/IPv6 literals are never split on dots and never linked by suffix.
- `same_file` links are suggestions only, and never come from a forwarded file (`is_forwarded_source`).
- Confirm/reject of suggestions is session-scoped (not persisted).
- JM query failures are shown with `MainWindow._warn_blocking`; no tab opens.
- JM models are closed (filter thread stopped) on tab close, new parse and Clear; a test process that opens JM tabs exits with code 0.
- Commits: author only (Mihir-Choudhary), no Claude co-author trailer, messages written to a BOM-less file and committed with `git commit -F`.
- Real-data tests read `EVTX_TEST_LOGS_ONLINE` (the `nextron` folder, e.g. `D:\Test_logs_Bulk\online\nextron`) and print "skipped" and exit 0 when it is absent.

## Review Focus

1. **Blank Computer anchor** — an event whose Computer is empty: "On this host" must mean only blank-Computer events (group `(unknown)`), never "everything". Test in Task 5.
2. **Very large window on a large dataset** — ±365 days over 500k events must not freeze the GUI thread in Normal mode beyond one linear pass (< 3 s), and JM must run through its filter thread. Test in Task 5.
3. **Anchor from a chain tab** — chain-tab events are correlator copies, not the table's own dicts; the anchor must still be found by `(source_file, record_id)`. Test in Task 5.
4. **Timestamp shapes** — 7 fractional digits, no fraction, `Z` vs `+00:00`, JM's `YYYY-MM-DD HH:MM:SS.ffffff`: all parse to the same instant. Test in Task 4.
5. **Zero-width custom window (0 before, 0 after)** — shows the events at exactly the anchor's timestamp (at least the anchor), never an empty tab. Test in Task 4 (bounds) and Task 6 (dialog accepts 0).

---

### Task 1: Host identity core

**Files:**
- Create: `evtx_tool/core/host_identity.py`
- Modify: `evtx_tool/gui/main_window.py:6036-6048` (`_is_forwarded_source` becomes a re-export of the core function)
- Test: `tests/test_host_identity.py`

**Interfaces:**
- Produces (all in `evtx_tool/core/host_identity.py`):
  - `UNKNOWN = "(unknown)"`
  - `is_ip_literal(s: str) -> bool` — `ipaddress.ip_address` succeeds after stripping `[]`.
  - `name_key(raw: str) -> tuple[str, str]` — `(full_key, short_key)`: strip whitespace and one trailing dot, casefold; blank → `(UNKNOWN, UNKNOWN)`; IP literal → `(ip, ip)`; else short = part before first dot.
  - `is_forwarded_source(source_file: str) -> bool` — body moved verbatim from `main_window._is_forwarded_source`.
  - `parse_rename(event_data) -> tuple[str, str] | None` — reads `{"Data": {"#text": [old, new]}}`; returns `None` unless exactly two non-empty strings.
  - `@dataclass(frozen=True) NameStat(name: str, source_file: str, count: int, first_ts: str, last_ts: str)`
  - `@dataclass(frozen=True) Rename(old: str, new: str, ts: str, source_file: str, record_id: int)`
  - `@dataclass(frozen=True) Link(kind: str, a: str, b: str, evidence: tuple, state: str)` — `kind` in `"rename" | "domain_suffix" | "same_file"`; `a`, `b` are full keys, ordered `a <= b`; `state` in `"auto" | "suggested" | "confirmed" | "rejected"`; equality/hash on `(kind, a, b)` only (`field(compare=False)` on `evidence` and `state`).
  - `@dataclass HostGroup(display_name: str, members: list[str], links: list[Link])` — `members` are raw names seen on events, sorted case-insensitively.
  - `class HostIdentity` with `build(names: list[NameStat], renames: list[Rename], unreadable_renames: int = 0) -> HostIdentity` (classmethod), `group_of(raw_name: str) -> HostGroup`, `suggestions_for(raw_name: str) -> list[Link]`, `groups() -> list[HostGroup]`, `confirm(link: Link) -> None`, `reject(link: Link) -> None`, attribute `unreadable_renames: int`.

- [ ] **Step 1: Write the failing tests** in `tests/test_host_identity.py` (synthetic, no Qt). Each case builds `HostIdentity` from `NameStat`/`Rename` lists and asserts on `group_of(...).members` and link kinds/states:
  - rename chain `A→B`, `B→C` (events on A and C only): `group_of("A").members == ["A", "C"]`, two `rename` links, state `auto`; the bridge `B` is not a member.
  - case-only rename `evtx-PC → EVTX-PC` with events only on `evtx-PC`: one group, member `["evtx-PC"]`, no error.
  - cycle `A→B`, `B→A`: one group `["A", "B"]`.
  - domain suffix one domain: names `WS01`, `WS01.corp.local` → one group, link kind `domain_suffix`, state `auto`.
  - two domains: `WS01`, `WS01.a.local`, `WS01.b.local` → `WS01` alone; `suggestions_for("WS01")` has two `domain_suffix` links with state `suggested`; `WS01.a.local` and `WS01.b.local` never linked to each other.
  - same file: names `HOSTA`, `HOSTB` in `C:\x\System.evtx` → separate groups; one `same_file` suggestion whose evidence names the file.
  - forwarded file: same two names only in `C:\x\ForwardedEvents.evtx` → no suggestion.
  - IP literals: `10.0.0.5` and `10.0.0.6` stay separate groups and keep their full text; `name_key("10.0.0.5") == ("10.0.0.5", "10.0.0.5")`; `name_key("fe80::1") ` full stays `fe80::1`.
  - blank: `name_key("  ") == ("(unknown)", "(unknown)")`; a blank name in a shared file with `HOSTA` produces no suggestion and `group_of("")` members `[""]`.
  - unreadable 6011: `parse_rename({"Data": {"#text": ["only-one"]}}) is None`; `HostIdentity.build(..., unreadable_renames=2).unreadable_renames == 2`.
  - confirm / reject: confirming the `HOSTA`/`HOSTB` suggestion makes `group_of("HOSTA").members == ["HOSTA", "HOSTB"]` and the link state `confirmed`; rejecting it again splits them and `suggestions_for("HOSTA") == []`.
  - display name: the member with the latest `last_ts` (`DESKTOP-A8CALR3` over `WIN-VR474TJ38H3`).

- [ ] **Step 2: Run** `python tests/test_host_identity.py` — Expected: FAIL (`ModuleNotFoundError: evtx_tool.core.host_identity`).

- [ ] **Step 3: Implement `evtx_tool/core/host_identity.py`.** Nodes are full keys; raw event names map to their node; groups are connected components (union-find) over `auto` and `confirmed` links. Rename links compare `name_key(old)[0]` and `name_key(new)[0]`; renames of `UNKNOWN` or IP literals are ignored; a 6011 from a forwarded file still counts (it is the machine's own statement), so renames are never filtered by `is_forwarded_source`. Domain-suffix: for each bare node (no dot, not IP, not `UNKNOWN`) collect FQDN nodes with the same short key; exactly one distinct domain → `auto`, more → one `suggested` link per FQDN. Same-file: per non-forwarded `source_file`, every pair of non-`UNKNOWN` nodes not already in one automatic component → one `suggested` link per pair, evidence = sorted tuple of the files they share. Rejected links are excluded from components and from `suggestions_for`.

- [ ] **Step 4: Point `main_window._is_forwarded_source` at the core function** (`from evtx_tool.core.host_identity import is_forwarded_source as _is_forwarded_source`, keep the old name importable).

- [ ] **Step 5: Run** `python tests/test_host_identity.py` — Expected: `N/N checks passed`, exit 0.

- [ ] **Step 6: Commit** — "Add host identity: one machine's Computer names, with evidence".

---

### Task 2: Host identity inputs from both modes, proven on real collections

**Files:**
- Modify: `evtx_tool/core/host_identity.py` (add the Normal builder)
- Create: `evtx_tool/core/heavyweight/host_inputs.py`
- Test: `tests/test_host_identity_real.py`

**Interfaces:**
- Consumes: `NameStat`, `Rename`, `parse_rename`, `HostIdentity` (Task 1).
- Produces:
  - `inputs_from_events(events: Iterable[dict]) -> tuple[list[NameStat], list[Rename], int]` in `host_identity.py` — one pass; `ts` normalised to ISO `YYYY-MM-DDTHH:MM:SS.ffffffZ`; renames are `event_id == 6011` with `provider` equal to `"EventLog"` (case-insensitive); third value = unreadable 6011 count.
  - `inputs_from_jm(table: "pa.Table", parquet_dir: str) -> tuple[list[NameStat], list[Rename], int]` in `host_inputs.py` — names from DuckDB `GROUP BY computer, source_file` over the registered Arrow `table` with `count(*)`, `min/max(timestamp_utc)` converted to the same ISO-Z form; renames from `parquet_scan` of the manifest shards (`_MANIFEST_FILENAME`) `WHERE event_id = 6011 AND lower(provider) = 'eventlog'`, selecting `timestamp_utc, source_file, record_id, event_data_json`.

- [ ] **Step 1: Write the failing test** `tests/test_host_identity_real.py`. Reads `EVTX_TEST_LOGS_ONLINE`; skip when absent. For each collection parse all `*.evtx` under it with `HeavyweightEngine(parquet_dir=tmp).run(files)` + `load_arrow_table`, build with `inputs_from_jm`, and assert the groups:
  - `win10-client`: `{"DESKTOP-A8CALR3", "WIN-VR474TJ38H3"}` one group, display `DESKTOP-A8CALR3`, link kind `rename`.
  - `win11-client`: `{"DESKTOP-6D0DBMB", "WIN-KPO4DDU11AB"}` one group, `rename`.
  - `win11-client-2023`: `{"WinDevEval", "WinDev2310Eval"}` one group (`rename`); `WIN-OQ6R0RVA4NF` its own group with a `same_file` suggestion to that group.
  - `win2022-0-20348-azure`: `{"Agamemnon", "WIN-06FB45IHQ35"}`, `rename`.
  - `win7-x86`: `{"37L4247D28-05", "evtx-PC"}` one group via a chain through `WIN-DQ6SQUGKQRD` (not a member); three renames read, 0 unreadable.
  - `win2022-ad`: `{"WIN-FPV0DSIC9O6", "WIN-FPV0DSIC9O6.sigma.fr"}`, `domain_suffix`.
  - `win2022-evtx`: `{"WIN-TKC15D7KHUR"}` alone, no suggestions.
  - Parity: for `win7-x86`, `win10-client`, `win2022-ad`, `inputs_from_events` over `evtx_tool.core.parser.iter_events` of the same files equals `inputs_from_jm` (compare `sorted` lists of `NameStat`/`Rename`).
  - Every JM test window closes its tables; process exit code 0.

- [ ] **Step 2: Run** `python tests/test_host_identity_real.py` — Expected: FAIL (`ImportError: inputs_from_events`).

- [ ] **Step 3: Implement `inputs_from_events` and `inputs_from_jm`** as specified in Interfaces.

- [ ] **Step 4: Run** the test with `EVTX_TEST_LOGS_ONLINE=D:\Test_logs_Bulk\online\nextron` — Expected: all checks pass, exit 0; and without the variable: "skipped", exit 0.

- [ ] **Step 5: Commit** — "Build host identity from both modes, checked on seven real machines".

---

### Task 3: One host identity per dataset; Computer Normalisation moves onto it

**Files:**
- Modify: `evtx_tool/gui/main_window.py` — `_ComputerNormalisationDialog` (~6463), `_on_show_computer_norm` / `_on_computer_norm_jm_ready` / `_open_computer_norm_dialog` / `_apply_computer_norm_filter` (~12480-12670), `_norm_computer_key` (~6017, removed once unused), dataset reset points: `_on_parse_clicked` (~11107), `_launch_juggernaut_mode` (~9698), `_clear_results` (~15031)
- Test: `tests/test_computer_norm_identity.py`

**Interfaces:**
- Consumes: `HostIdentity`, `inputs_from_events`, `inputs_from_jm`.
- Produces:
  - `MainWindow._host_identity() -> HostIdentity` — built on first call for the current dataset (Normal: `inputs_from_events(self._events)`; JM: `inputs_from_jm(self._hw_model._full_table, self._hw_db_path)`), under `_busy_wait("Please Wait — Host Names", "Working out host names…", rows=<event count>, min_rows=self._LOGON_BUSY_MIN_ROWS)`, cached in `self._host_identity_cache`.
  - `MainWindow._reset_host_identity() -> None` — sets the cache to `None`; called at each dataset reset point listed above.
  - `_ComputerNormalisationDialog(identity: HostIdentity, counts: list[dict], on_filter_fn, on_identity_changed, parent=None)` — `counts` keeps the existing `{"computer", "source_file", "n"}` rows; one table row per `HostGroup`; new last column "Evidence" (`rename at <apply_tz(ts)>` / `domain suffix` / `suggested: shared file <basename>`); context actions "Confirm suggested link" and "Reject suggested link" call `identity.confirm/reject` then `on_identity_changed()`, which rebuilds the rows.
  - "Filter Events to This Computer" passes `group.members` to `on_filter_fn`.

- [ ] **Step 1: Write the failing test** `tests/test_computer_norm_identity.py` (offscreen Qt, synthetic events through `EventTableModel`/`MainWindow` Normal path): names `WS01`, `ws01.corp.local`, `10.0.0.5`, `10.0.0.6`, plus a 6011 renaming `OLD-NAME → WS01`:
  - the dialog shows one row for `WS01` covering `WS01`, `ws01.corp.local`, `OLD-NAME`, with evidence containing `rename at` and `domain suffix`;
  - `10.0.0.5` and `10.0.0.6` are two rows (the old `_norm_computer_key` merged them into `10`);
  - the filter action filters the view to exactly the events of the group's members;
  - confirming a `same_file` suggestion merges two rows; rejecting splits them back.
  Also run it against the pre-change build where the IP and rename checks fail.

- [ ] **Step 2: Run** `python tests/test_computer_norm_identity.py` — Expected: FAIL.

- [ ] **Step 3: Implement** the cache, the reset calls, and the dialog change. The JM path keeps `_ComputerNormJMWorker` for `counts` and calls `self._host_identity()` when it finishes.

- [ ] **Step 4: Run** the new test plus `tests/test_view_integrity.py` and `tests/test_gui_launch_smoke.py` — Expected: all pass.

- [ ] **Step 5: Commit** — "Group Computer Normalisation by host identity (renames, and IPs kept whole)".

---

### Task 4: Time window logic

**Files:**
- Create: `evtx_tool/core/time_window.py`
- Test: `tests/test_time_window.py`

**Interfaces:**
- Produces:
  - `parse_event_ts(raw: str) -> datetime | None` — UTC-aware; accepts `...Z`, `+00:00`, a space instead of `T`, 0–7 fractional digits (7th truncated); `None` for empty/unparseable.
  - `window_bounds(anchor: datetime, before: timedelta, after: timedelta) -> tuple[datetime, datetime]` — `(anchor - before, anchor + after)`.
  - `in_window(ts: datetime | None, start: datetime, end: datetime) -> bool` — inclusive; `None` → `False`.
  - `jm_bound(dt: datetime) -> str` — `"YYYY-MM-DD HH:MM:SS.ffffff"` (JM `timestamp_utc` form) for `BETWEEN` comparison.
  - `PRESETS: list[tuple[str, timedelta]]` = `[("±1 min", 1 min), ("±5 min", 5 min), ("±15 min", 15 min), ("±1 hour", 1 h), ("±1 day", 1 day)]`.
  - `MAX_SIDE = timedelta(days=365)`.

- [ ] **Step 1: Write the failing tests:** the four timestamp shapes of Review Focus 4 parse to one instant; `parse_event_ts("") is None`; events exactly at `anchor ± 5 min` are in, `± (5 min + 1 µs)` are out; a zero window `(0, 0)` contains the anchor itself; `jm_bound` of `2022-02-07 10:54:25.366021+00:00` is `"2022-02-07 10:54:25.366021"` and string comparison with JM-form timestamps agrees with `in_window` on 1,000 random instants.

- [ ] **Step 2: Run** `python tests/test_time_window.py` — Expected: FAIL (module missing).

- [ ] **Step 3: Implement `evtx_tool/core/time_window.py`.**

- [ ] **Step 4: Run** — Expected: all pass.

- [ ] **Step 5: Commit** — "Add time-window helpers for the around pivot".

---

### Task 5: The "around" tab in both modes

**Files:**
- Modify: `evtx_tool/gui/main_window.py` — new methods near the chain-tab builder (~14380); the 13 `startswith("__chain__")` checks at ~7222, 8813, 8934, 8945, 10414, 10435, 10477, 11604, 11705, 11714, 11776, 11791, 15281
- Modify: `evtx_tool/gui/models.py` — `EventFilterProxyModel`
- Modify: `evtx_tool/gui/heavyweight_model.py` — `ArrowTableModel`
- Test: `tests/test_around_pivot.py`

**Interfaces:**
- Consumes: `HostIdentity`/`MainWindow._host_identity()` (Tasks 1–3); `parse_event_ts`, `window_bounds`, `in_window`, `jm_bound` (Task 4).
- Produces:
  - module function `_is_pivot_tab_key(key: str) -> bool` — `key.startswith(("__chain__", "__around__"))`; replaces every one of the 13 checks (chain tabs and around tabs are excluded from global filter propagation and the filter-target list, and get the chain-tab tree/close handling).
  - `EventFilterProxyModel.has_any_filter_active() -> bool` — returns `self._any_filter_active`.
  - `ArrowTableModel.has_any_filter_active() -> bool` — any of `_base_where_sql`, `_text_where_sql`, `_quick_where_sql`, `_record_id_where_sql` non-trivial, or `_conditions_cfg` / `_text_search_cfg` non-empty (`_fixed_where_sql` does not count).
  - `ArrowTableModel.find_row(source_file: str, record_id: int) -> int | None` and `ArrowTableModel.nearest_row(ts_utc: str) -> int | None` on `_display_table`.
  - `MainWindow._open_around_tab(anchor: dict, before: timedelta, after: timedelta, scope: str, filtered_from=None) -> None` — `scope` in `"host" | "host+suggested" | "all"`; `filtered_from` is `None` (all loaded events) or the clicked table's proxy (Normal) / `ArrowTableModel` (JM) to snapshot.
  - Tab key `f"__around__{uuid4().hex}"`; label `⏱ <display name> ±<window> <anchor hh:mm:ss>` / `⏱ All hosts …`, custom windows `-<before>/+<after>`; tooltip lines exactly as spec §3.4 (anchor time/ID/host/file/record ID; window start and end via `apply_tz`; host names and why; "All loaded events" or "Filtered snapshot"; row count; "N events without a timestamp not included").
  - Normal: `EventTableModel` over references to matching existing dicts (source = `self._events`, or the snapshot proxy's accepted rows), `EventFilterProxyModel`, stored as `FileTabState` like chain tabs (tree item, close button, bar un-collapse).
  - JM: `ArrowTableModel(source_table, parquet_dir=self._hw_db_path, fixed_where="timestamp_utc BETWEEN ? AND ?" [+ " AND computer IN (…)" for host scopes], fixed_params=[jm_bound(start), jm_bound(end), *names])`, `source_table` = `self._hw_model._full_table` or the snapshot model's `_display_table`; appended to `self._jm_file_models`; wrapped in `_JMProxyShim`; stored in `self._file_tabs`. Query errors → `_warn_blocking`, no tab.
  - Anchor selection: after load (Normal immediately; JM on the model's first `busy_finished`), select and centre the anchor's `(source_file, record_id)` row; if absent select `nearest_row` and set status "Anchor event is not in this tab; nearest event selected."

- [ ] **Step 1: Write the failing tests** in `tests/test_around_pivot.py` (offscreen; run each block in Normal and JM; close windows before exit):
  - synthetic dataset: events at anchor ± 5 min exactly are included, ± (5 min + 1 µs) excluded; all-hosts vs this-host vs this-host+suggested give the expected row sets; Normal and JM row sets `(source_file, record_id)` are identical;
  - DST: display zone `Europe/Berlin`, a ±1 hour window around 2026-03-29 01:30 UTC includes events by UTC instant and the tooltip shows the start and end with offsets +01:00 and +02:00 respectively;
  - filtered snapshot: with a quick filter active, `filtered_from` gives exactly the source tab's visible rows within the window; with no filter the snapshot equals all events; a snapshot that matches nothing still opens a tab whose tooltip says "0 events" and why;
  - a Quick Filter applied inside the around tab changes only that tab's rows (the main table's count is unchanged), and a bookmark toggled there shows in the Bookmarks list;
  - anchor row is selected; nested pivot from an around tab works; a chain-tab anchor (Review Focus 3) is found;
  - blank-Computer anchor (Review Focus 1) shows only blank-Computer events in "This host";
  - Normal ±365 days over 500k synthetic events builds in < 3 s (Review Focus 2);
  - real data, if `EVTX_TEST_LOGS_ONLINE` is set: load `win10-client\Logs_Client\Security.evtx` and `System.evtx`, anchor = the System EID 6011 at `2022-02-07T10:54:25.366021Z`, ±5 min "This host": row count equals an independent `iter_events` count of all events in both files within the window, and includes the 255 `WIN-VR474TJ38H3` events (exact-name matching would drop them), in both modes;
  - JM: closing the tab, a new parse and Clear stop the around models' filter threads; the process exits 0.

- [ ] **Step 2: Run** `python tests/test_around_pivot.py` — Expected: FAIL (`_open_around_tab` missing).

- [ ] **Step 3: Implement** `_is_pivot_tab_key` and replace the 13 checks; add the two `has_any_filter_active` methods, `find_row`, `nearest_row`; implement `_open_around_tab` per Interfaces.

- [ ] **Step 4: Run** the test, then `tests/test_jm_teardown.py`, `tests/test_view_integrity.py`, `tests/test_filter_sort_matrix.py` — Expected: all pass.

- [ ] **Step 5: Commit** — "Open the events around any event in a new tab, in both modes".

---

### Task 6: Menu, custom window and the filter question

**Files:**
- Modify: `evtx_tool/gui/main_window.py` — `_on_table_context_menu` (~11982; serves the main, per-file, chain and around tables); new `_AroundCustomDialog` class next to other small dialogs
- Test: `tests/test_around_menu.py`

**Interfaces:**
- Consumes: `_open_around_tab`, `has_any_filter_active`, `PRESETS`, `MAX_SIDE`, `parse_event_ts`, `MainWindow._host_identity()`.
- Produces:
  - Menu, inserted before "Copy Row as Text": `⏱ Around this event ▸ On this host (N names) ▸ presets + Custom…`, `▸ On this host + K suggested names ▸ (same)` only when `K > 0`, `▸ On all hosts ▸ (same)`. "On this host (N names)" tooltip lists each member and why (link kind and evidence). Anchor with unparseable timestamp → whole item disabled, tooltip "This event has no readable timestamp."
  - `_AroundCustomDialog(parent) -> exec()`; `.values() -> tuple[timedelta, timedelta]`: before and after, each a `QSpinBox` (0–525,600) + unit `QComboBox` (minutes/hours/days); OK disabled while either side exceeds `MAX_SIDE`.
  - `MainWindow._ask_around_filter_scope(source) -> str | None` — shown only when `source.has_any_filter_active()`; returns `"all"` (default button "Include all loaded events"), `"filtered"` ("Only events that pass the current filters") or `None` (cancel).

- [ ] **Step 1: Write the failing tests:** menu entries and counts for a group with 3 names and 1 suggestion; no "+ suggested" item when K = 0; disabled item and tooltip for a no-timestamp anchor; the custom dialog accepts (0, 0), rejects 366 days, returns `timedelta`s; the filter question appears only with an active filter (Normal quick filter, JM quick filter) and "filtered" passes the clicked table's model to `_open_around_tab`.

- [ ] **Step 2: Run** `python tests/test_around_menu.py` — Expected: FAIL.

- [ ] **Step 3: Implement** the menu, `_AroundCustomDialog`, `_ask_around_filter_scope`.

- [ ] **Step 4: Run** the test — Expected: pass.

- [ ] **Step 5: Commit** — "Add the Around this event menu, custom window and filter question".

---

### Task 7: Documentation and whole-feature verification

**Files:**
- Create: `docs/09c-around-this-event.md` (what it does, the three scopes, the filter question, why one machine has several names, Computer Normalisation evidence/confirm)
- Modify: `README.md` (one feature-table row linking the doc), `docs/02-gui-overview.md` (right-click menu list)
- Modify: `STATE.md` (local journal)

- [ ] **Step 1:** Write the doc and README row.
- [ ] **Step 2:** Run the full suite (`tests/test_*.py`, each in its own process, 900 s timeout) and `pytest sentinel/tests` — Expected: every file passes, no hangs.
- [ ] **Step 3:** Real-data check in the GUI, both modes, on `win10-client` and `win2022-ad`: open Computer Normalisation (one row per machine, evidence shown) and an around tab at the rename; compare Computer Normalisation with the pre-change build on `D:\Test_logs_Bulk\Logs` — the only differences allowed are rename merges and IP literals kept whole.
- [ ] **Step 4: Commit** — "Document the Around this event pivot and host identity". Do not push until the user says so.
