# Resume pointer

Read `STATE.md` first. Branch **`beta`**. Forensic integrity is paramount — never fabricate
a duration, never silently drop evidence.

**State as of 2026-08-24: SHIPPED.** `beta` and `main` are both at `bbb3e66` and both
pushed. Working tree clean, 28 suites / 437 checks green, `compileall` clean.

The 32 commits pushed today carry **no Claude attribution** — the trailers were stripped
from the 29 unpushed ones before the push (author and committer are mihir-choudhary
throughout; verified the rewrite changed messages only, code identical). 43 Claude
trailer lines remain in history at/below `971b7de` — those were already public, and
rewriting them would need a force-push of published history, which was deliberately
declined. Local safety ref `backup/pre-trailer-strip` still points at the pre-rewrite
tip; delete it once you are happy.

Any NEW commit must keep author = mihir-choudhary only, no Co-Authored-By / Claude-Session
trailers.

Keep working on `beta` and fast-forward `main` when asked; do not commit to `main` directly.

---

## Performance work (2026-08-20) — done, and what is left

Parsing ran `cpu-1` wide; almost nothing after it did. Fixed on `beta`:
`7166ea6` JM sort off the GUI thread, `179ff54` JM export on a worker,
`219e010` normal-mode text haystack precomputed. Harnesses now live in
`tests/` (not `/tmp`): `test_jm_sort_perf.py` 24, `test_jm_export.py` 11,
`test_normal_filter_perf.py` 11, `test_parse_integrity_perf.py` 8.

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

**Parse stage FIXED (`fc60634`).** It now runs on processes: **39.8 s → 15.7 s**,
**1.1 → 6.0 of 12 cores** average (peak 2.9 → 11.4), with 1,710,518 records
intact and exact per source file. Start method is forkserver, else spawn, never
plain fork (Qt threads). It degrades to the old thread path if processes cannot
start, and an unguarded caller degrades safely too.

**Callers of `HeavyweightEngine.run()` should be `if __name__ == "__main__"`
guarded** — standard multiprocessing requirement. All app entrypoints already
are (`eventhawk_gui.py`, `gui/app.py`, `evtx_tool.py` have `freeze_support()`
and guards). An unguarded script does not fork-bomb: the engine catches the
bootstrap error and falls back to threads, correct but ~4x slower.

Numbers below are the ORIGINAL audit that found the problem, kept for the
reasoning.

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

**Done in `fc60634`**, with record-count equality asserted per source file
(`tests/test_parse_integrity_perf.py`). Rows still stream through a queue —
measured at ~0.1 GB / ~1.1 s of pickling for the whole corpus, cheap enough to
keep the single-writer Parquet path and the integrity accounting unchanged.
Workers now PULL tasks, which also closed a latent hang: the consumer waits
`while done_tasks < total_tasks`, so a worker dying without emitting DONE would
have blocked the parse forever.

**Remaining headroom on parse:** 15.7 s is still above the ~7 s the raw
threaded parse alone takes, so the single-threaded Parquet writer in the
consumer is now the next bottleneck. Worth attacking only if parse latency
still matters.

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

**Commit the crash + integrity work** (details in `STATE.md`). Finished and tested,
just uncommitted:

- five signals -> `Signal(object)`, plus `EventRef` in `gui/models.py` for the second
  corruption site (`data(UserRole)` returning a bare dict);
- `_cleanup_juggernaut` cancels the mat/export workers (narrow, per-worker disconnects
  so a cancelled export still reports);
- `_safe_int` EventID `Value` fallback — closes a latent JM/normal parity gap;
- unique per-file tab labels (`unique_display_names`) so N same-named Security.evtx
  files from different DCs are distinguishable in the UI (also used in the integrity dialog);
- **warnings classified at the source** (`append_warning(msg, benign=True)`) — normal mode's
  substring whitelist was hiding "parse aborted mid-file" and "were not parsed", the two
  worst evidence-loss findings; plus elided-count text and a dialog when the integrity
  check itself fails;
- new suites: `test_signal_int_overflow` (18), `test_jm_teardown` (14),
  `test_overflow_realdata` (10), `test_overflow_soak` (6),
  `test_large_multifile_split` (10), `test_ad_same_name_large` (9),
  `test_gui_launch_smoke` (6). All proven non-vacuous by injecting the bug.
  **Full suite: 28 suites, 437/437.**

`test_large_multifile_split.py` BUILDS its own >64 MB fixtures (no such file exists in
the corpus) by replicating a real file's 64 KB chunks — so the >64 MB multi-file split
is testable on any machine with the sample logs.

**Then, the standing top defect: fix the fabricated multi-hour INBOUND durations.**
(`STATE.md` → "OPEN DEFECT")

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

Restore the real-log ground-truth check (7 outbound sessions, durations
`[6395, 29, 14, 16, 3, 4507, 383]`) so the inbound change is provably regression-free.

## Known, deliberately not fixed

- **CSV formula injection** — a cell starting with `=` (e.g. `=cmd|'/c calc'!A1`, which
  can legitimately appear in a logged command line) is exported verbatim and Excel will
  evaluate it. The usual mitigation prefixes such cells with an apostrophe, which ALTERS
  exported evidence — against this project's core rule. Needs the author's decision:
  fidelity vs. safe-to-open-in-Excel. Flagged, not silently changed.

- **`except Exception: ed = {}`** in `_JMAnalysisMaterializeWorker` — a malformed
  `event_data_json` silently becomes empty event_data with no flag. 0 occurrences across
  334,390 real rows, so latent, but it is a fail-silent path in evidence handling and
  deserves an explicit marker instead of an empty dict.
- **Worker classes shadow `QThread.finished`** with their own result-carrying signal.
  Now worked around (reap by liveness, never `finished.connect(deleteLater)` — see
  `_reap_finished_workers`), but the shadowing itself remains a trap for the next person:
  renaming those signals to `rows_ready`/`data_ready` would remove it, at the cost of
  touching every connect site.

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
