# Resume pointer

Read `STATE.md` first. Branch **`beta`**. Forensic integrity is paramount — never fabricate
a duration, never silently drop evidence.

**State as of 2026-08-20:** HEAD `219e010`, working tree clean, tree compiles.
`main` was fast-forwarded to `beta` on 2026-08-11; since then `beta` is **4 commits ahead
and unpushed** (`46e348a` journal, plus the three performance commits below). Rounds 1-3 of the RDP audit are committed and
were verified at 159 checks before the test scratchpad was wiped.

Keep working on `beta` and fast-forward `main` when asked; do not commit to `main` directly.

---

## Performance work (2026-08-20) — done, and what is left

Parsing ran `cpu-1` wide; almost nothing after it did. Fixed on `beta`:
`7166ea6` JM sort off the GUI thread, `179ff54` JM export on a worker,
`219e010` normal-mode text haystack precomputed. Harnesses now live in
`tests/` (not `/tmp`): `test_jm_sort_perf.py` 16, `test_jm_export.py` 11,
`test_normal_filter_perf.py` 11.

Measured on 1,710,518 rows (JM) and 500,000 events (normal):

| Operation | Before | After |
|---|---|---|
| JM column-header sort | full-table sort, GUI blocked | 0.02–0.03 ms to return |
| JM sort by a string column | **silently unsorted** | correct (via DuckDB) |
| JM filter threads | 4 of 12 cores | `max(2, min(cpu-1, 16))` |
| JM export, 1.7M rows | 17.9 s frozen window | worker + progress + cancel |
| Normal text search, 500k | 11.4 s | ~1.6 s on repeats |

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
