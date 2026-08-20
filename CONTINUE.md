# Resume pointer

Read `STATE.md` first. Branch **`beta`**. Forensic integrity is paramount — never fabricate
a duration, never silently drop evidence.

**State as of 2026-08-20:** HEAD `bffb8d2`, working tree clean, tree compiles.
`main` was fast-forwarded to `beta` on 2026-08-11; since then `beta` is **4 commits ahead
and unpushed** (`46e348a` journal, plus the three performance commits below). Rounds 1-3 of the RDP audit are committed and
were verified at 159 checks before the test scratchpad was wiped.

Keep working on `beta` and fast-forward `main` when asked; do not commit to `main` directly.

---

## Performance work (2026-08-20) — done, and what is left

Parsing ran `cpu-1` wide; almost nothing after it did. Fixed on `beta`:
`7166ea6` JM sort off the GUI thread, `179ff54` JM export on a worker,
`219e010` normal-mode text haystack precomputed. Harnesses now live in
`tests/` (not `/tmp`): `test_jm_sort_perf.py` 24, `test_jm_export.py` 11,
`test_normal_filter_perf.py` 11.

Measured on 1,710,518 rows (JM) and 500,000 events (normal):

| Operation | Before | After |
|---|---|---|
| JM column-header sort | full-table sort, GUI blocked | 0.02–0.03 ms to return |
| JM sort by a string column | **silently unsorted** | correct (via DuckDB) |
| JM filter threads | 4 of 12 cores | `max(2, min(cpu-1, 16))` |
| JM export, 1.7M rows | 17.9 s frozen window | worker + progress + cancel |
| Normal text search, 500k | 11.4 s | ~1.6 s on repeats |

**Costs accepted, worth knowing:** the normal-mode advanced-text cache adds
**~99 MB per 500k events** (RSS 541 → 640 MB), about the same as the existing
`_search_cache` (90 MB) and only paid if an analyst actually runs an advanced
text search. It is freed and rebuilt whenever the dataset changes. Anyone
loading millions of events in normal mode is already carrying ~400 MB of event
dicts and belongs in Juggernaut mode, so this is not the binding constraint.

## Resource-utilisation audit (2026-08-20) — measured, not read

Sampled process CPU while each stage ran, on 1616 files / 1.4 GB / 1,710,518
rows, 12 cores. `100% = 1 core`.

| Stage | Wall | Avg cores | Peak |
|---|---|---|---|
| `engine.run()` (parse → Parquet) | 39.8 s | **1.1 / 12** | 2.9 |
| JM filter (single event_id) | 0.06 s | 0.8 | 0.8 |
| JM sort (timestamp / channel / eid) | 0.5–0.9 s | 3.2–3.4 | 9.7 |
| JM full-text search | 2.3 s | 1.6 | 8.0 |
| JM export, full table | 18.4 s | 1.5 | 10.3 |

Post-parse now uses the machine (peaks of 9–10 of 12 cores). **The parse stage
is the one that does not** — and it is the stage everyone assumed was already
parallel.

**Root cause, measured:** `evtx.PyEvtxParser.records_json()` does NOT release
the GIL, so the engine's `ThreadPoolExecutor` buys nothing. Raw parse of the
corpus, page-cache warm:

- 1 thread → 1.62 s, 2 → 1.63 s, 4 → 1.70 s, 8 → 1.71 s, 11 → 1.68 s (**zero
  scaling**)
- full corpus: 11 threads **7.27 s** (202 MB/s) vs 11 processes **1.59 s**
  (923 MB/s) — **4.6x** on parsing alone.

`engine.py`'s own docstring claims "ThreadPoolExecutor — no spawn overhead, no
pickle, GIL-free Rust parsing". The GIL-free half is false for this binding.

**Note the bigger number:** raw parse is 7.3 s of the 39.8 s stage, so ~32 s is
Python-side record processing (orjson decode, field extraction, tuple build) in
those same GIL-bound worker threads, plus the single-threaded Parquet writer in
the consumer. Moving to processes would parallelise that part too, so the prize
is larger than 4.6x — but so is the risk.

**Not attempted, deliberately.** Switching the heavyweight engine to
`ProcessPoolExecutor` means picklable tasks, a `multiprocessing.Queue`, and a
multiprocessing stop Event, on the core parse path of a forensic tool that has
already had two silent record-loss bugs (see [[split-evtx-record-loss-bugs]]).
Normal mode already parses with `ProcessPoolExecutor`, so there is precedent
and picklable worker functions to copy from. This wants its own session with
record-count equality asserted per source file before and after.

**Still open (deliberately not started):** filters that change the row count a
lot are dominated by `QSortFilterProxyModel`'s mapping churn plus the view's
response, not by our predicate — 500k → 24k still costs ~2 s. Fixing it means
replacing the proxy with one that computes an accepted-row list in a single
pass and resets the model. That is a subsystem change touching the main grid,
per-file tabs and several dialogs, so it wants its own scoped session.

Also note: `filterAcceptsRow` catches exceptions and returns `True`, so a bug
in the predicate shows the FULL set instead of raising. It hid a real mistake
during this work until a test caught it. Any change there needs a test that
asserts row counts, not just "no exception".

## Next concrete action

**Fix the fabricated multi-hour INBOUND durations.** (`STATE.md` → "OPEN DEFECT")

Every LocalSessionManager `SessionID` in the sample log is `"1"`, so one explicit-key bucket
stays open and swallows later unrelated logons — `_OPEN_KEY_CORR_SECS` gives an open keyed
bucket a 7-day window. Result: **42 of 48 durations correct, 6 wrong, worst ~30 h.**

This is the same defect the outbound state machine already fixed, and it violates the
user's explicit requirement that a connect never pair with another session's disconnect
"which will make it look like the rdp session went on for hours".

Approach: give the inbound path its own state machine over LSM semantics
(21 connect / 22 shell start / 23 logoff / 24 disconnect / 25 reconnect) instead of
`SessionID` + proximity. Where a pair cannot be proven, report "Unavailable" and flag it —
same contract as outbound. It is a subsystem change, so confirm scope with the user before
starting.

**Before touching it, rebuild the test env** (recipe in `STATE.md`) and restore at least the
real-log ground-truth check (7 outbound sessions, durations
`[6395, 29, 14, 16, 3, 4507, 383]`) so the inbound change is provably regression-free.
Put the harnesses in `tests/` this time — `/tmp` is not durable.

## Also open

- ~~5 commits unpushed on `beta`~~ — **done 2026-08-11.** All pushed, and `main`
  fast-forwarded to match. Note the consequence: the inbound defect above is now on the
  **public default branch**, not quarantined on `beta`. That raises its priority.
- **`STATE.md` publishes its own open defect.** The "OPEN DEFECT" and "Test infrastructure
  — LOST" sections are now on public `main`. Honest, but a reputational call the author has
  not explicitly made — offer to move the journal under `docs/` if that is not intended.
- **No user docs for this browser.** `docs/` has no page for the Remote Assistance / RDP
  session browser, so Evidence, Source Log and the whole flag vocabulary are undocumented
  for anyone but the author. `docs/10c-logon-sessions.md` is the model to follow.

## Do not redo

- Durations are `int()`-truncated; `[…, 30, 15, 4, 384]` in old notes was a `round()`
  artefact. The code is right.
- JM inbound = **53** sessions, not 109. The 109 came from a test parser that dropped
  `<UserData><EventXML>`. Both modes agree at 53.
- RdpCoreTS stays excluded from outbound classification (it is destination-side; including
  it inverts direction).
