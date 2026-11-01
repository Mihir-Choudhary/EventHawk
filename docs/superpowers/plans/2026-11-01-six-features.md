# Six Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Date-tree chevrons + hour level, drag and drop, per-tab column filters, custom columns, whole-event text
search and a searchable export file picker with one-file / per-file export, in Normal and Juggernaut (JM) mode.

**Architecture:** Each feature extends an existing seam: `ColumnFilterPopup` (main_window.py) for the tree, the
`MainWindow` drag/drop events plus `_add_path`, a per-tab `_col_filters` map, a new pure module
`evtx_tool/core/custom_columns.py` evaluated identically in both modes, the shared search haystack in
`core/filters.py` + a `description` Parquet column, and `_ExportScopeDialog` reused by the JM export.

**Tech Stack:** Python 3.12, PySide6, pyarrow, DuckDB, pyevtx-rs. Tests are standalone scripts
(`python tests\test_x.py`, exit 0 = pass, `QT_QPA_PLATFORM=offscreen`).

**Spec:** `docs/superpowers/specs/2026-11-01-six-features-design.md` (approved 2026-11-01, rulings R-1..R-9).

## Global Constraints

- Interpreter `C:\Users\Czar\AppData\Local\Programs\Python\Python312\python.exe`; no new dependencies.
- Normal and JM give the same answer for the same action; one shared implementation wherever possible.
- Never fabricate a value, never silently drop evidence or input; every error and skip is surfaced.
- Large-corpus bar: 1.71M events (`D:\Test_logs_Bulk\Logs`); GUI stays responsive (no freeze > 2 s).
- Tests use synthetic data only and may assert counts on the real corpus, never log values.
- Every task: failing test first (watched failing), then code, then the test passing, then a commit authored by
  Mihir-Choudhary only (`git commit -F <file>`, no trailers), files staged by name.
- Each feature is also proved visibly on the real corpus through real widgets (scratchpad driver `real_ui.py`
  style), with screenshots; results go to the WORKLOG.

## Review Focus

1. Date tree with many days and a partially checked day: the filter must be exact at hour level and never fall
   back to "show all" (Task 2 adds a 400-day synthetic case).
2. Drop of a folder that contains no `.evtx`, and of a path that vanished between drag and drop: a message, no
   crash, nothing added silently (Task 3).
3. Per-tab filters after closing a tab and re-opening the file / switching view mode merged↔separate: no stale
   state leaks into another tab (Task 6).
4. Custom column on a field whose value contains the template's braces or a backslash, and on 1.7M rows in JM
   while the user keeps scrolling: values exact, GUI responsive (Tasks 9, 11).
5. Export "One file per EVTX" with two selected files of the same base name from different folders: two distinct
   outputs (the existing `_separate_export_paths` guarantee), in both modes (Tasks 4, 5).

---

### Task 1: Date-tree chevrons visible regardless of OS colour scheme

**Files:**
- Create: `evtx_tool/resources/images/chevron_closed.svg`, `chevron_open.svg` (12×12, fill `#1e1a14`; hover
  variants `chevron_closed_hover.svg`, `chevron_open_hover.svg` fill `#7a5c1e`)
- Modify: `evtx_tool/gui/main_window.py` `ColumnFilterPopup._build_date_tree` / `_apply_popup_style`; the
  PyInstaller spec's data list (`*.spec` at repo root) to include the four SVGs
- Test: `tests/test_date_tree_chevrons.py`

**Interfaces:** Produces `ColumnFilterPopup._tree` styled with `::branch:closed:has-children`,
`::branch:open:has-children` (and `:hover`) image rules; `_chevron_url(name: str) -> str` (absolute, forward-slash
path usable in QSS).

- [ ] Step 1: test — build a popup for `timestamp_date` with values `{"2024-05-14": 3, "2025-01-02": 1}`;
  assert the tree stylesheet contains `chevron_closed.svg` and `chevron_open.svg` for `has-children` branches and
  the files exist; assert a year item `childIndicatorPolicy`/`childCount()>0`; simulate a click on the branch
  indicator rect (`QStyle.SE_TreeViewDisclosureItem`) → `isExpanded()` toggles True then False; `QTest.mouseDClick`
  on the row text toggles too; render `tree.grab()` with `QGuiApplication.styleHints().setColorScheme(Dark)` and
  `Light` and assert the chevron pixel region contains the `#1e1a14` colour in both.
- [ ] Step 2: run → FAIL (no chevron images in stylesheet).
- [ ] Step 3: implement; branch click relies on Qt's default branch toggling; keep `setExpandsOnDoubleClick(True)`.
- [ ] Step 4: run → PASS; Step 5: commit "Show expand chevrons in the date filter tree".

### Task 2: Hour level under each day (R-1)

**Files:**
- Modify: `evtx_tool/gui/main_window.py` (`ColumnFilterPopup` tree build/apply, `_show_col_filter_popup`,
  `_on_col_filter_applied`), `evtx_tool/gui/models.py` (quick-filter virtual key), `evtx_tool/gui/jm_col_worker.py`
  (`_timestamp_hour_expr`, Normal `_ev_val`), `evtx_tool/gui/heavyweight_model.py` (`_quick_col_info`)
- Test: `tests/test_date_tree_hours.py`

**Interfaces:**
- Produces quick-filter key `"timestamp_hour"`, value `"YYYY-MM-DD HH"` in the display time zone, both modes.
- `display_hour(raw_ts: str) -> str` in `models.py` beside `display_date` (same memo/tz rules).
- `_timestamp_hour_expr() -> str` in `jm_col_worker.py` (same tz strategy as `_timestamp_date_expr`, format
  `%Y-%m-%d %H`).
- `ColumnFilterPopup(..., hour_provider: Callable[[str], dict[str, int]] | None = None)`: called with
  `"YYYY-MM-DD"` on a day's first expand, returns `{"HH": count}` for the events visible in that tab.
- Emission rule: if every checked day is fully checked, emit as today on `timestamp_date`; if any day is partially
  checked, emit every selection at hour level (full days expand to their 24 `"D HH"` values) and
  `_on_col_filter_applied` stores key `timestamp_hour` (derived when the date column's values have length 13).
- `_col_filters[tab][col] = (mode, values, key)`.

- [ ] Step 1: test — synthetic events across 3 days and several hours (and a 400-day set for Review Focus 1);
  Normal proxy and JM SQL (`ArrowTableModel` on a synthetic Arrow table + DuckDB) each: uncheck one hour of one
  day → count equals an independent Python count; uncheck a whole day → `timestamp_date` path unchanged; day node
  shows a child indicator before expansion (placeholder child) and loads hours via `hour_provider` once.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Add an hour level to the date filter tree".

### Task 3: Drag and drop of files and folders (R-2, R-3)

**Files:** Modify `evtx_tool/gui/main_window.py` (`MainWindow.__init__` `setAcceptDrops(True)`,
`dragEnterEvent`, `dragMoveEvent`, `dragLeaveEvent`, `dropEvent`, `_DropOverlay(QWidget)`); Test
`tests/test_drag_drop.py`.

**Interfaces:** `MainWindow._paths_from_drop(urls: list[QUrl]) -> tuple[list[str], list[str]]` (accepted, skipped
with reason); `_DropOverlay.show_over(widget)` / `hide()`.

- [ ] Step 1: test — temp dirs with `a.evtx`, `sub/b.EVTX`, `notes.txt`, empty folder, nested folder; send
  `QDragEnterEvent`/`QDropEvent` built from `QMimeData.setUrls`: file only, folder only, mixed, duplicate, `.txt`,
  vanished path, during parse (`_btn_parse` disabled / `_worker` set). Assert file-list contents (folders added
  as folder entries, files as files, no duplicates), status-bar message names the skipped count, overlay visible
  after enter and hidden after leave/drop, nothing added during parse and a message shown. A folder with no
  `.evtx` anywhere is added? — no: skipped with "no .evtx files inside" (Review Focus 2).
- [ ] Step 2: FAIL; Step 3: implement (folder check with `Path.rglob("*.evtx")` short-circuiting on first hit);
  Step 4: PASS; Step 5: commit "Accept dropped EVTX files and folders".

### Task 4: Export file picker search and one-file / per-file choice (Normal)

**Files:** Modify `evtx_tool/gui/main_window.py` `_ExportScopeDialog`, `_on_export_clicked`; Test
`tests/test_export_file_picker.py`.

**Interfaces:** `_ExportScopeDialog` gains `_inp_file_search: QLineEdit`, `_lbl_file_count: QLabel`, buttons
"Select shown" / "Clear shown", radios `_rb_specific_one` / `_rb_specific_each`; `specific_separate() -> bool`.
`_on_export_clicked`: scope `specific` + separate → `self._export_separate(sorted(specific_files))`.
`_export_separate` reports per file "no events" instead of writing an empty file (R-9).

- [ ] Step 1: test — dialog with 30 paths incl. two `Security.evtx` in different folders: typing filters rows
  (case-insensitive substring of the base name), hidden rows keep their check state across filter changes,
  "Select shown"/"Clear shown" touch only visible rows, count label text, `specific_separate()` follows the radio;
  end-to-end on synthetic per-file data: per-file export writes one file per selected source with the right event
  counts and distinct names; a selected file with zero events is reported, not written.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Search and split the specific-files export".

### Task 5: Juggernaut export gets the same scope dialog (R-10)

**Files:** Modify `evtx_tool/gui/main_window.py` `_export_juggernaut`; Test `tests/test_jm_export_scope.py`.

**Interfaces:** Consumes `_ExportScopeDialog` from Task 4. Scopes map to `_JMExportWorker` runs: view = today;
combined = full table, no filter; separate / specific-each = one run per source file with
`where source_file = ?` and `_separate_export_paths` names; specific-one = `source_file IN (...)`.

- [ ] Step 1: test — JM on 2–3 small real-format EVTX fixtures generated in the test via the existing synthetic
  helpers (or the `EVTX_TEST_LOGS` skip pattern): each scope writes the expected files with row counts equal to an
  independent DuckDB count per file.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Give Juggernaut export the scope chooser".

### Task 6: Column filters belong to the tab they were set in (R-4)

**Files:** Modify `evtx_tool/gui/main_window.py` (`_col_filters`, `_on_col_filter_applied`,
`_apply_quick_filter`, `_clear_quick_filters`, `_update_header_indicators`, `_update_quick_filter_badge`,
`_show_col_filter_popup`, tab-close and view-mode switch handlers); Test `tests/test_col_filters_per_tab.py`.

**Interfaces:** `MainWindow._filter_tab_key() -> str` (`self._active_file_tab` or `"__all__"`);
`self._col_filters: dict[str, dict[int, tuple[str, list[str], str]]]`; `_filter_target_for_tab(key) -> model|proxy`.
The `_FilterTargetDialog` prompt is no longer used by column/quick filters. "Clear All Filters" clears every tab;
the badge / popup clear only the active tab. Closing a tab or switching view mode drops that state.

- [ ] Step 1: test — separate view, both modes, synthetic multi-file load: filter tab A (popup path and
  "filter by this value" path) → B's count unchanged; change and clear in B → A unchanged; popup in each tab shows
  its own checks; header ▼ indicators per tab; no modal dialog opened (assert `_FilterTargetDialog` never
  constructed); Clear All → every tab back to its total; close + reopen (Review Focus 3) → no stale filter.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Keep column filters per tab".

### Task 7: Search haystack covers the whole event (Normal, parse-time)

**Files:** Modify `evtx_tool/core/filters.py` (`adv_search_haystack`), `evtx_tool/gui/filter_dialog.py` (label
"Text (anywhere in the event)" + tooltip listing the scope); Test `tests/test_search_whole_event.py`.

**Interfaces:** `adv_search_haystack(ev) -> str` now = every non-`event_data` key's value (sorted keys, skipping
`None`/""), both timestamp renderings, the EventData/UserData values and JSON (unchanged), every `*_desc` value,
`get_event_description(ev)` text, and the System element/attribute names as words
(`SYSTEM_XML_NAMES` constant: Provider Name Guid EventSourceName EventID Qualifiers Version Level Task Opcode
Keywords TimeCreated SystemTime EventRecordID Correlation ActivityID Execution ProcessID ThreadID Channel Computer
Security UserID).

- [ ] Step 1: test — synthetic events with a marker string placed in: a System field outside the old list
  (`processor_id`, `session_id`), an EventData value, an EventData name, a nested UserData leaf, a `*_desc` value,
  and the description wording of a known event ID (4624's "logged on"); each found by Normal proxy text filter
  and by `passes_filter`; an absent marker found nowhere.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Search the whole event, including its
  description".

### Task 8: JM searches the same scope (description column)

**Files:** Modify `evtx_tool/core/heavyweight/engine.py` (`_make_schema` + `_extract_and_filter` append
`description`; not loaded into Arrow), `evtx_tool/core/heavyweight/filter_sql.py` (`_SEARCH_TEXT_RAW_FULL` adds
`description` and every System column not yet in it); Test: extend `tests/test_search_whole_event.py` with the JM
leg + `tests/test_export_parity.py` must stay green (description is not exported as a column).

- [ ] Step 1: test JM leg (HeavyweightEngine on a synthetic EVTX is not possible; use the existing pattern that
  parses `EVTX_TEST_LOGS` and skips without it, plus a SQL-level synthetic table check of the expression).
- [ ] Step 2: FAIL; Step 3: implement; measure JM parse time on `D:\Test_logs_Bulk\Logs` before/after (stop and
  report if > +5%); Step 4: PASS + timing recorded; Step 5: commit "Search event descriptions in Juggernaut".

### Task 9: Custom-column evaluator (pure core)

**Files:** Create `evtx_tool/core/custom_columns.py`; Test `tests/test_custom_columns_eval.py`.

**Interfaces (Produces):**
- `class CustomColumnError(ValueError)`.
- `@dataclass CustomColumnSpec: col_id: int; title: str; template: str; eid_expr: str = ""; providers:
  tuple[str, ...] = (); kind: str = "text"` (`"text"|"int"`).
- `compile_spec(spec) -> CompiledColumn` — parses tokens `{Element}`, `{Element[Attr]}`, `{Data[Name]}`,
  `{Data[n]}` (1-based), `{UserData[Name]}`; `\{`/`\}` escape literal braces; raises `CustomColumnError` with
  "EventHawk does not keep <name>" for System names not in `SYSTEM_TOKENS`, and for syntax errors / `n < 1`.
- `SYSTEM_TOKENS: dict[str, str]` token → event-dict key (`EventID`→`event_id`, `EventID[Qualifiers]`→`qualifiers`,
  `Version`, `Level`, `Task`, `Opcode`, `Keywords`, `TimeCreated[SystemTime]`→`timestamp`,
  `EventRecordID`→`record_id`, `Correlation[ActivityID]`→`correlation_id`, `Execution[ProcessID]`→`process_id`,
  `Execution[ThreadID]`→`thread_id`, `Channel`, `Computer`, `Security[UserID]`→`user_id`, `Provider[Name]`→
  `provider`, `Provider[Guid]`→`provider_guid`, `Provider[EventSourceName]`→`event_source_name`).
- `CompiledColumn.applies(ev: dict) -> bool` (Event ID expression via `parse_event_id_expression`, providers
  case-insensitive exact); `CompiledColumn.value(ev: dict) -> str` ("" when the event is outside the filter or
  every token is missing); `CompiledColumn.hits: Counter[str]` updated per token found (for the zero-match warning).
- `int_sort_key(value: str) -> tuple` — `(0, int)` for decimal/`0x` hex, `(1, value.lower())` otherwise.
- `field_catalog(ev: dict) -> list[tuple[str, str, str]]` — (token, label, value) for System fields present,
  then EventData/UserData leaves by name with their 1-based index.

- [ ] Step 1: tests for every token form, literal + escaped braces, backslash in values, `{Data[n]}` on named
  and unnamed (`{"Data": [...]}`) EventData, nested UserData leaves, missing → "", refused System name, bad
  syntax, filters, `int_sort_key` ordering (`9 < 0x10 < 100 < "abc"`), `hits` counts, `field_catalog` order.
- [ ] Step 2: FAIL (module missing); Step 3: implement; Step 4: PASS; Step 5: commit "Add the custom-column
  evaluator".

### Task 10: Custom columns in the Normal model

**Files:** Modify `evtx_tool/gui/models.py` (`EventTableModel`: `add_custom_column(compiled) -> int`,
`update_custom_column(col_id, compiled)`, `remove_custom_column(col_id)`, `custom_columns() -> list`,
`custom_value(row: int, col_id: int) -> str`; `columnCount`/`headerData`/`data`/sort aware; proxy quick-filter
key `f"cc{col_id}"` resolves via `custom_value`), `evtx_tool/gui/jm_col_worker.py` (`NormalColValueWorker` handles
`cc*` keys), `main_window.py` (`ColumnFilterPopup` key lookup through `MainWindow._col_key_for(index) -> str`);
Test `tests/test_custom_columns_normal.py`.

- [ ] Step 1: test — synthetic tab: add a `{Data[LogonType]}` int column → values exact per row, sort ascending
  numeric, popup values/counts exact, include/exclude filter counts exact, edit template → values recomputed,
  remove → column gone and its quick filter dropped; two tabs keep separate columns; 200k-event timing < 3 s.
- [ ] Step 2: FAIL; Step 3: implement (values computed once on a worker thread with the busy indicator, stored as
  a list per column); Step 4: PASS; Step 5: commit "Show custom columns in Normal mode".

### Task 11: Custom columns in JM

**Files:** Modify `evtx_tool/gui/heavyweight_model.py` (`ArrowTableModel.add_custom_column(compiled) -> int`
etc. with the same names as Task 10; Arrow columns `cc{id}` string and, for `int`, `cc{id}_n` int64 used for
ORDER BY; `_quick_col_info` maps `cc{id}`), a `_CustomColumnWorker(QThread)` streaming
`source_file, record_id, <System columns>, event_data_json` from the shards in 65,536-row batches and evaluating
Task 9's `CompiledColumn.value`; Test `tests/test_custom_columns_jm.py`.

- [ ] Step 1: test — parity with Task 10 on the same synthetic events loaded as a JM table; on `EVTX_TEST_LOGS`:
  values equal an independent extractor (pyevtx-rs JSON read directly, keyed by (source_file, record_id)), sort,
  popup, filter; 1.7M timing < 10 s with a heartbeat showing no GUI gap > 0.5 s.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Show custom columns in Juggernaut mode".

### Task 12: Custom-column dialog, field picker and header menu

**Files:** Create `evtx_tool/gui/custom_column_dialog.py` (`CustomColumnDialog(QDialog)`: title, value,
event-ID filter, provider filter, type combo, field-picker `QTreeWidget` from `field_catalog(selected_event)`,
click inserts token at the cursor; OK validates via `compile_spec` and keeps the dialog open on error;
`spec() -> CustomColumnSpec`); modify `main_window.py` header context menu ("Add Custom Column…", and on custom
headers "Edit Custom Column…" / "Remove Custom Column") and Add/Remove Columns listing; zero-match warning after
evaluation (`hits` empty for a token → `QMessageBox` "No event in this tab has a field named X" with Edit / Keep);
Test `tests/test_custom_column_dialog.py`.

- [ ] Step 1: test — real dialog widgets: type title, click a picker field (token inserted), Integer type, OK →
  column appears in the active tab only; refused System token keeps the dialog open with the message; typo token
  → warning shown, Edit reopens prefilled, Keep leaves the empty column; edit and remove from the header menu.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Add the custom column dialog".

### Task 13: Custom columns in exports (R-7)

**Files:** Modify `evtx_tool/output/exporters.py` (`export_*` accept `custom_columns: list[CompiledColumn] = ()`;
CSV/HTML add a column per title after the base columns, JSON/XML add `custom_columns: {title: value}`),
`main_window.py` (Normal export passes the active tab's columns; `_JMExportWorker` evaluates them per batch);
Test `tests/test_custom_columns_export.py`; `tests/test_export_parity.py` stays green.

- [ ] Step 1: test — every format, both modes, synthetic: the column present with exact values, empty outside
  its filter, title with comma/quote/`<` escaped correctly; no custom columns → byte-identical output to before.
- [ ] Step 2: FAIL; Step 3: implement; Step 4: PASS; Step 5: commit "Export custom columns".

### Task 14: Proof, suite, hand-off

- [ ] Visible real-widget runs on the real corpus for every feature (both modes), screenshots, counts vs
  independent oracles; timings for Tasks 2, 8, 10, 11 on the 1.71M corpus.
- [ ] Full suite (claim the test slot); fix anything red with a failing test first.
- [ ] WORKLOG entry (rulings R-1..R-10, numbers, screenshots folder), overview update (new features, new
  tests), release claims; then launch Codex (gpt-6.1-sol, high, visible interactive window) to audit and to
  restart the dynamic test plan from Phase A with the visible/real-widget method.
