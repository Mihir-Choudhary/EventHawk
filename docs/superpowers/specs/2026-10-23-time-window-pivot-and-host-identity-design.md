# Time-window pivot ("Around this event") and host identity — design

Status: approved in conversation 2026-10-23; awaiting written-spec review.
Scope: two units that ship together. Host identity is shared infrastructure the
pivot needs, and that Collection Health and entity pages will reuse.

## 1. Purpose

An analyst who finds one interesting event almost always asks next: *what else
happened on this machine (or anywhere) just before and after?* Today that takes a
manual date filter plus a host filter, and the host filter is subtly wrong,
because one machine records more than one Computer name.

### 1.1 Finding that drives host identity (measured, not assumed)

Seven public single-machine `winevt\Logs` collections (NextronSystems
evtx-baseline v0.8.5) were scanned record by record. Six record more than one
Computer name. EventHawk's extracted `computer` equals the raw XML in all
seven, so this is Windows behaviour, not a parser bug:

| Collection | Names | Cause | Windows' own evidence |
|---|---|---|---|
| Win 10 | WIN-VR474TJ38H3 → DESKTOP-A8CALR3 | setup name, renamed at end of OOBE | EID 6011 |
| Win 11 | WIN-KPO4DDU11AB → DESKTOP-6D0DBMB | same | EID 6011 |
| Win 11 2023 | WIN-OQ6R0RVA4NF, WinDevEval → WinDev2310Eval | image build, re-specialise, rename | 6011 for the second only |
| Server 2022 Azure | WIN-06FB45IHQ35 → Agamemnon | image built, deployed and renamed | EID 6011 |
| Win 7 | 37L4247D28-05 → WIN-DQ6SQUGKQRD → evtx-PC (+ case-only evtx-PC → EVTX-PC) | chained renames; middle name on no event | three 6011 |
| Server 2022 AD | WIN-FPV0DSIC9O6 and WIN-FPV0DSIC9O6.sigma.fr, interleaved | not a rename: components use FQDN vs NetBIOS | none needed |
| Server 2022 | WIN-TKC15D7KHUR only | — | — |

Exact-name matching would silently drop events. For example, a ±5-minute
pivot at 10:54 on the Win 10 machine would lose the 10:52–10:53 events
written just before the rename.

The existing Computer Normalisation dialog (`_norm_computer_key`) handles case
and FQDN-versus-short-name only. It does not handle renames, its logic is
private to that dialog, and it truncates IP-address Computer values at the
first dot (`10.0.0.5` becomes `10`, merging every 10.x host).

## 2. Unit A — host identity (`evtx_tool/core/host_identity.py`)

Pure logic, no Qt. One instance per loaded dataset.

### 2.1 Input
- `names`: every distinct (Computer string, source_file) pair with its event
  count, plus the first and last timestamp per name.
- `renames`: every System EID 6011 (EventLog: "the NetBIOS and DNS name of
  this machine changed from X to Y"), with old name, new name, timestamp,
  source_file and record_id. The event data holds the two names as an
  unnamed `<Data>` pair in order (old, new). Rows whose pair cannot be read
  are skipped and counted, never guessed.

Normal mode builds the input in one pass over the in-memory events. JM builds
it with two DuckDB queries over the shards (`GROUP BY computer, source_file`,
and `event_id = 6011`).

### 2.2 Name normalisation (`name_key`)
- Strip whitespace and a trailing dot; casefold.
- Blank becomes `(unknown)`. It is never linked to anything.
- IPv4 and IPv6 literals stay whole. They are never split on dots and never
  linked by suffix.
- Otherwise the short key is the part before the first dot; the full key is
  the whole casefolded name.

### 2.3 Links
Every link records its kind and its evidence.

| Kind | Applied | Rule |
|---|---|---|
| `rename` | automatic | 6011 old → new, compared by full key, case-insensitive. Chains are followed; names that occur only inside a 6011 (never on an event) still bridge a chain. Cycles (A→B→A) are fine. A 6011 read from a ForwardedEvents log is still valid evidence, because it is the machine's own statement. |
| `domain_suffix` | automatic | A bare name `X` links with `X.<domain>` when exactly one domain occurs for that short name. If `X.a` and `X.b` (different domains) both occur, those links are **suggestions** instead: possibly two machines. Two different FQDNs are never linked to each other directly. |
| `same_file` | **suggestion** | Two names that both occur in the same *local* log file. A file is not local if `_is_forwarded_source` says so (ForwardedEvents and variants); such files produce no suggestions. |

Groups are the connected components of the automatic links plus confirmed
suggestions. The display name is the name of the group's latest event.

### 2.4 Confirmation
`confirm(link)` and `reject(link)` are kept per loaded dataset (session-scoped).
Feature 4, case notes, will persist them. Any change produces a new grouping;
consumers re-read it.

### 2.5 API (consumers rely only on this)
- `HostIdentity.build(names, renames) -> HostIdentity`
- `.group_of(name) -> HostGroup` (`display_name`, `members: list[str]`,
  `links: list[Link]`)
- `.suggestions_for(name) -> list[Link]` (unconfirmed, involving this group)
- `.groups() -> list[HostGroup]`
- `.confirm(link)`, `.reject(link)`
- `Link`: `kind`, `a`, `b`, `evidence` (`ts`, `source_file`, `record_id` or
  file list), `state` (`auto` / `suggested` / `confirmed` / `rejected`)

### 2.6 Computer Normalisation moves onto it
The dialog groups by `HostIdentity` instead of `_norm_computer_key`. Its rows
gain an "Evidence" column (rename at time X / domain suffix / suggested: shared
file) and a context action to confirm or reject a suggestion. The existing
columns and the "Filter Events to This Computer" action keep working, with the
variants coming from the group. The IP truncation bug goes away.

## 3. Unit B — "Around this event"

### 3.1 Menu
Right-clicking any events table (main, per-file, chain or around tab) shows:

```
⏱ Around this event ▸ On this host (N names) ▸ ±1 min | ±5 min | ±15 min | ±1 hour | ±1 day | Custom…
                    ▸ On this host + K suggested names ▸ (same)   [only when K > 0]
                    ▸ On all hosts ▸ (same)
```

- **Custom…** asks for before and after separately, each as a number and a
  unit (minutes, hours or days), from 0 up to 365 days.
- **"On this host (N names)"** has a tooltip listing every name and why it is
  included (the link kind and evidence).
- **An anchor with no parseable timestamp** greys the whole item, with the
  reason as a tooltip.

### 3.2 Filter question
Shown only if the clicked table has any filter active (advanced, quick,
session or record-key, tactic, or text):

- **"Include all loaded events"** (default)
- **"Only events that pass the current filters"**: a snapshot of exactly what
  that table shows at that moment. Normal mode uses the proxy's accepted rows;
  JM uses the model's current display table.

### 3.3 Window semantics
- Bounds are computed in UTC from the stored timestamps:
  `[anchor − before, anchor + after]`, inclusive at both ends.
- Shown in the analyst's display time zone. Never convert with today's
  offset; the DST rule of the event's own date applies.
- Sub-second precision is kept: the anchor's microseconds count.
- Events with no timestamp are excluded and counted in the tooltip ("N events
  without a timestamp not included").
- "This host" means the anchor's host group (members), plus the confirmed and
  (for the "+ suggested" item) the suggested names.

### 3.4 The tab
- **Label:** `⏱ <display name> ±<window> <anchor hh:mm:ss>`, or
  `⏱ All hosts …`. Custom windows show `-<before>/+<after>`.
- **Tooltip:**
  - the anchor (time, event ID, host, file, record ID);
  - the exact window start and end in the display time zone;
  - the host names included and why;
  - all events or filtered snapshot;
  - the row count;
  - the excluded-no-timestamp count.
- **Contents:** in Normal mode, an `EventTableModel` over references to the
  matching existing event dicts (no copy), with its own proxy. In JM, an
  `ArrowTableModel` sharing the full table (or the snapshot table) with
  `fixed_where` = time bounds plus `computer IN (…)` when host-scoped. No row
  cap in either mode.
- **Anchor:** after the tab is populated, the row with the anchor's
  (source_file, record_id) is selected and scrolled to the centre. If it is
  absent (for example a filtered snapshot that excluded it), the nearest
  timestamp is selected and the status bar says so.
- **Behaviour:** detail panel, Quick Filters, column popups, sort, bookmark,
  export and nested Around pivots all work, as in per-file tabs.
- **Lifetime:** JM models are tracked like `_jm_file_models`. Closing the tab,
  starting a new parse or clicking Clear stops their filter threads before
  they are dropped.

### 3.5 Errors
- **JM query failure:** shown with `_warn_blocking`, and no tab is opened.
- **Zero matching events:** cannot happen when the anchor is included. For
  the filtered snapshot the tab still opens, with "0 events" and the reason in
  the tooltip.

## 4. Testing

Each test also runs against the pre-change build where that is meaningful.

- **Host identity, synthetic:**
  - rename chain;
  - case-only rename;
  - cycle;
  - a rename through a name that appears on no event;
  - FQDN plus bare name in one domain (auto) and in two domains (suggestion);
  - same-file suggestion;
  - a forwarded file giving no suggestion;
  - IPv4/IPv6 kept whole;
  - `(unknown)` isolated;
  - unreadable 6011 skipped and counted;
  - confirm and reject regrouping.
- **Host identity, real:** all seven evtx-baseline collections, with the table
  in 1.1 as the expected groups and links. The scripts read
  `EVTX_TEST_LOGS_ONLINE` and skip if it is absent.
- **Pivot, both modes:**
  - inclusive bounds (events exactly at ±window included, ±window+1µs excluded);
  - a DST-crossing window;
  - a rename-crossing window (Win 10 at 10:54, ±5 min, includes the
    WIN-VR474TJ38H3 events);
  - all-hosts vs this-host vs plus-suggested;
  - the filter question shown only when a filter is active;
  - the snapshot equals the visible rows;
  - anchor selected;
  - nested pivot;
  - no-timestamp anchor greyed;
  - JM tab close, new parse and Clear with no QThread abort (process exit code 0);
  - Normal and JM give identical row sets for the same pivot.
- **Computer Normalisation:**
  - groups match host identity;
  - the IP case is fixed;
  - the existing filter action still filters to the group's variants.

## 5. Out of scope
- Persisting confirmations (feature 4).
- Entity pages and Collection Health UI (later specs; they reuse unit A).
- Windows message-DLL event descriptions (separate clone, later).
