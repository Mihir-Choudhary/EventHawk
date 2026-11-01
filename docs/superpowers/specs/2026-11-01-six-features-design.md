# Six features: date-tree chevrons, drag and drop, per-tab column filters, custom columns, whole-event search, export file picker

Date: 2026-11-01. Base: `beta` 9845d67 plus the same-field condition fix. Requested by the user (prompt of
2026-11-01, quoted in each section). Implemented by Claude; audited afterwards by Claude and Codex.

Global constraints (from the user's prompt and the standing rules):
- Do not break existing features; keep performance good on large EVTX sets (the 1.71M-event corpus is the bar).
- Normal mode and Juggernaut (JM) mode must give the same answers.
- Forensic integrity: never fabricate a value, never silently drop evidence or input; surface every error.
- Every feature is proved dynamically on the real corpus through the real, visible GUI (real widgets), plus
  automated tests that fail before the change and pass after.

Rulings (where the prompt left a choice) are marked **R-n**; each says what it costs if wrong.

---

## 1. Timestamp filter tree: visible chevrons, and a Time level

User: "Add a chevron/arrow (▶ collapsed, ▼ expanded) to every expandable node (year, month, day). Single click
on the arrow should expand/collapse. Keep double-click working. ... clearly visible in dark mode and light mode."

Finding: the popup's tree already has expandable rows (`setRootIsDecorated(True)`), but the branch indicator is
drawn by the native Windows style, which follows the OS dark/light setting, on a popup whose colours are fixed
cream. In OS dark mode the arrow is drawn light-on-light, so it is effectively invisible. EventHawk itself has a
single (cream) theme; there is no app dark mode.

Design:
- Explicit chevron images for the tree's `::branch` states (closed / open, plus hover), drawn as small SVGs
  shipped in `evtx_tool/resources/images/` (and in the PyInstaller data list), in the theme's dark-brown text
  colour, so they are visible whatever the OS setting. Hover and checked/selected colours are set explicitly in
  the popup's stylesheet; nothing is left to the OS palette.
- A single click on the chevron toggles expand/collapse (Qt's branch-click behaviour, kept); double-click on the
  row still toggles. A click on the row text keeps toggling its checkbox as today.
- **R-1: a Time level under each day.** The prompt describes "Year → Month → Day → Time" and asks for a chevron
  on day nodes, but days are leaves today. Each day gets hour children ("14:00–14:59", with counts). Hours load
  lazily when a day is first expanded (one grouped query for that day), so the popup's 1,000-value cap is never
  spent on hours and a 3-year log does not build 26,000 rows up front. Filtering: a fully checked day keeps
  filtering by date as today; a partially checked day filters by the checked hours (new quick-filter key
  `timestamp_hour`, value `YYYY-MM-DD HH`, in display time zone, both modes). Hour is the finest level; finer
  windows stay in the Advanced Filter's date/time fields. Cost if wrong: one extra tree level to remove.

Tests: a widget test that the branch stylesheet carries the chevron images and colours; the day node has an
expand indicator before expansion; one click on the indicator expands, a second collapses, double-click still
works; partial-hour selection filters exactly the checked hours in both modes against an independent count;
screenshots with Qt's colour scheme forced to dark and to light inside the app process (`QStyleHints`), so the
Windows setting itself is never changed.

## 2. Drag and drop of files and folders

User: "Allow dragging and dropping individual .evtx files ... entire folders (recursively load all .evtx files
inside). Both must work separately and also mixed in one drop. Show a visual drop-zone highlight while dragging."

Design:
- The main window accepts drops. On drag-enter, the drop is accepted when at least one URL is a local `.evtx`
  file or a local folder; a translucent overlay with a dashed border and "Drop EVTX files or folders" covers the
  window until drop or leave.
- On drop, each item goes through the existing add-path code (`_add_path`), which already resolves folders
  recursively; files and folders mixed in one drop are all added. Duplicates already in the list are not added
  twice.
- **R-2:** dropped items that are not `.evtx` files or folders are not added, and the status bar says how many
  were skipped and why (never silent). Drops while a parse is running are refused with a message (adding to the
  list mid-parse would show a file list that does not match what was parsed). Cost if wrong: a message to relax.
- Dropping only adds to the file list, exactly like Add Files / Add Folder; the user still presses Parse.
  **R-3**: no auto-parse on drop (parsing can take minutes and pick a mode; it should stay a deliberate action).

Tests: synthetic `QDropEvent`s with file, folder, nested folder, mixed, non-EVTX and duplicate URLs: exact file
lists; overlay shown on enter, hidden on leave and drop; refused during parse. Visible real run: drag and drop
driven through the window.

## 3. Column filters apply to the tab they were set in

User: "Change it so the filter applies only to the tab where it was applied. Each tab keeps its own independent
filter state. Clearing or changing a filter in one tab must not affect other tabs. No prompt asking which tabs to
apply to is needed."

Finding: in the separate (per-file tabs) view, the column popup and "filter by this value" ask which tabs to
target, and the column-filter bookkeeping (`_col_filters`) is one window-wide dict, so a filter set in one tab is
rebuilt into the others.

Design:
- Column-filter state is kept per tab: `_col_filters` becomes keyed by the tab (All Events, each file tab, each
  pivot tab), and every quick-filter action (column popup OK, "filter by this value", the header ▼ indicators,
  the quick-filter badge) reads and writes only the active tab's state. The target-tabs prompt is removed for
  column/quick filters. Pivot tabs already work this way; the merged view has one main tab, so nothing changes
  there except the shared code path.
- **R-4:** "Clear All Filters" keeps its meaning of resetting everything in every tab (its name says all), while
  clearing column filters from a tab's own popup or badge clears only that tab. The Advanced Filter and profiles
  are not column filters and keep their current scope. Cost if wrong: Clear All becomes per-tab.

Tests: separate view, both modes: filter tab A, tab B unchanged; change and clear in B, A unchanged; switch tabs,
the popup shows each tab's own checks and header indicators; Clear All clears all; no dialog appears. Counts vs
an independent predicate per tab.

## 4. Custom columns (Event Log Explorer style)

User: "Add an 'Add Custom Column' feature ... Column title ... Value: the field to extract from the event's full
XML ... {EventID}, {TimeCreated[SystemTime]}, {Data[LogonType]} or {Data[IpAddress]} (by name), {Data[3]} (by
index). A field picker ... Optional Event ID / Provider filter ... Optional type: Text or Integer ... sortable,
filterable, and included in exports ... per-tab, and the user can remove or edit them."

Finding: EventHawk does not keep the raw XML. The parser (pyevtx-rs JSON) keeps every System value it maps
(provider name/GUID/EventSourceName, EventID and Qualifiers, Version, Level, Task, Opcode, Keywords, SystemTime,
EventRecordID, Correlation ActivityID, Execution ProcessID/ThreadID, Channel, Computer, Security UserID) and the
whole EventData or UserData content, in document order. Normal mode holds it per event; JM holds System values
in the Arrow table and EventData/UserData as `event_data_json` in the Parquet shards.

Design:
- **Expression.** A value is a template: literal text plus tokens, so `{Data[TargetDomainName]}\{Data[TargetUserName]}`
  works. Tokens: `{Element}` and `{Element[Attribute]}` for System (`{EventID}`, `{TimeCreated[SystemTime]}`,
  `{Execution[ProcessID]}`, `{Security[UserID]}`, `{Provider[Name]}` ...); `{Data[Name]}` by field name (EventData
  `Data Name=` fields and UserData leaf elements, nested-aware); `{Data[n]}` by position, **R-5: 1-based** as in
  XPath and Event Log Explorer; `{UserData[Name]}` as an alias of `{Data[Name]}` for UserData events.
- **R-6: fields EventHawk does not keep are refused, not shown empty.** A token naming a System element or
  attribute the parser does not keep (e.g. `Correlation[RelatedActivityID]`) is rejected in the dialog with
  "EventHawk does not keep <name>" so an empty column can never be mistaken for "the log has no value". A
  kept field that an event simply lacks gives an empty cell. And when a token matches **no event in the tab**
  (typically a typo such as `{Data[IpAdress]}`), the user is warned "No event in this tab has a field named
  IpAdress" and can edit or keep the column, so an all-empty column is never silent. Cost if wrong: extend the
  parser for that field. (User, 2026-11-01: R-5 left to Claude, kept 1-based; R-6 confirmed with this
  clarification; R-1 to R-4 and R-7 to R-9 approved.)
- **One evaluator for both modes**: a pure-Python module `evtx_tool/core/custom_columns.py` (parse template →
  compiled spec; evaluate on an event dict). Normal evaluates over the in-memory events; JM streams the needed
  columns plus `event_data_json` from the shards in batches on a worker thread and evaluates the same code, then
  attaches the result to the tab's Arrow table as a new column. Same code, same answers.
- **Filter**: optional Event ID expression (same syntax as the Advanced Filter: lists, ranges, `!` excludes) and
  optional Provider list (comma-separated, case-insensitive exact names). Non-matching events get an empty cell.
- **Type**: Text (default) or Integer. Integer accepts decimal and `0x` hex (Windows writes PIDs and logon IDs as
  hex) and sorts numerically; a value that is not an integer is still shown exactly as found and sorts after the
  numbers (never coerced, never dropped).
- **Dialog**: Title, Value, Event ID filter, Provider filter, Type, and a field picker: a tree of every field of
  the currently selected event (System with attributes; EventData by name with its index; UserData leaves) showing
  each field's value; clicking a field inserts its token at the cursor. With no event selected the picker lists
  the System fields only and says to select an event for EventData fields. Validation errors keep the dialog open.
- **Placement**: header right-click → "Add Custom Column…"; on a custom column's header also "Edit Custom
  Column…" and "Remove Custom Column"; the same three under the existing column menu. Columns are per tab, not
  saved between runs.
- **Behaviour as a normal column**: appended after the built-in columns of that tab; sortable (numeric for
  Integer); filterable through the column popup (value list with counts) and quick filters; included in exports
  (**R-7**: the custom columns of the tab the export is started from are added to every export scope and format —
  CSV/HTML columns, JSON/XML fields named by the column title; events outside a column's filter get an empty
  value). Shown in Add/Remove Columns so it can be hidden like any column.
- **Performance**: Normal computes values once per column (one pass, worker thread, busy indicator, cached per
  row); JM streams in batches of ~64k rows. Target on the 1.71M corpus: a `{Data[Name]}` column in under 10 s in
  JM and proportionally in Normal, GUI responsive throughout (heartbeat test as in the audit-4 timing harness).

Tests: evaluator unit tests on synthetic events (every token form, template literals, index 1-based, nested
UserData, missing field → empty, refused fields, Integer hex/decimal/non-numeric, Event ID and Provider filters);
Normal/JM parity on the real corpus against an independent extractor reading the same events with pyevtx-rs
directly; sort, popup filter, edit, remove, per-tab isolation; export contains the column in each format; timing.

## 5. Text search covers the whole event

User: "It must search all content of each event: the System section ..., EventData/UserData fields, the
rendered description, and the raw XML ... Index or cache the searchable text per event so search stays fast."

Finding: the only event text search is the Advanced Filter's "Text in description". On `beta` it already searches
every mapped System field, every EventData/UserData value and the field names (one haystack shared by Normal,
parse-time and JM, cached per event in Normal and pre-built in JM). Gaps: (a) the rendered description
(`get_event_description`, shown in the details pane) is not searched; (b) the System fields are a fixed list, so
a field added later is silently unsearchable (e.g. processor/session/kernel-time columns today); (c) the label
says "description", which understates and confuses the scope; (d) `main` (public) has the older, narrower scope.

Design:
- The haystack becomes: every key the event dict holds except `event_data` (no fixed list), both timestamp
  renderings, every EventData/UserData value and name (unchanged), the semantic `*_desc` texts, and the rendered
  description. **R-8: no raw XML text.** EventHawk does not keep the XML; every value the XML carries is in the
  haystack, and element/attribute names of System are added as words, so an IOC found in the XML is found here.
  Cost if wrong: store the XML (large) — only if a real search misses something.
- Normal: the per-event cache already exists; it gains the description (computed once per event when the cache
  is first built). JM: the description is computed in the parse workers and stored as a `description` column in
  the shards, and the Parquet text scan includes it. Measured parse-time cost must stay under 5% on the corpus;
  if not, the plan stops and reports before shipping.
- The field is relabelled "Text (anywhere in the event)" with a tooltip listing the scope.

Tests: synthetic events with an IOC placed in each location (System field, EventData value, field name, UserData
leaf, description wording) found in Normal, JM and parse-time; a field not in the old list found; real corpus
parity Normal = JM = independent count; timing before/after.

## 6. Export: search the file checklist; one file or one per EVTX

User: "add a search bar above the checklist that filters the file list by file name as you type ... Selections
must stay checked when the filter changes ... 'Select all filtered' / 'Clear' buttons. Add a choice for how
selected EVTX files are exported: one combined file or separate files (one per EVTX)."

Design:
- Under "Specific files": a search box above the checklist filters by file name (case-insensitive substring)
  as you type; hidden rows keep their check state; a count label "12 of 340 shown, 5 selected". Buttons: "Select
  shown", "Clear shown" (act on the visible rows) and the existing All / None (all rows).
- Two radio buttons under the list: "Into one file" (today's behaviour) and "One file per EVTX" (reuses the
  existing per-source export path, which already guarantees distinct output names).
- **R-9:** the export summary names exactly which files were written; if a selected file has no events in scope,
  it is listed as "no events" rather than an empty file being written silently. Cost if wrong: write empty files.

- **R-10: Juggernaut gets the same export dialog.** Found while planning: JM export has no scope chooser at all;
  it always exports the active tab's current view, so "Specific files" (and this item) existed only in Normal
  mode. JM now opens the same `_ExportScopeDialog` (current view, all combined, all separate, specific files with
  the search and the one-file / per-file choice), each scope run by the existing JM export worker. Cost if wrong:
  JM keeps view-only export.

Tests: dialog unit tests (filter, persistence of checks across filter changes, select/clear shown, counts);
export runs for both choices in both modes with output files compared to an independent count per source file.

---

## Order of work and re-testing

1, 2, 6 (independent, small) → 3 (filter state) → 5 (search scope; touches parse in JM) → 4 (largest; builds on
the per-tab state from 3 and the column popup). Every item: failing test first, then code, then its real-corpus
visible proof. After all six: full suite, then the dynamic test plan restarts from Phase A (filters, columns,
search and export all changed), with Codex auditing and Claude fixing.
