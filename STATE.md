# EventHawk — master journal

Single source of truth for in-flight work. Read this first when resuming.
Resume pointer: `CONTINUE.md`.

**Repo:** github.com/Mihir-Choudhary/EventHawk · **Branch: `beta`** (all work goes here;
do NOT merge to `main` until stable).

**Standing constraint — forensic integrity is paramount.** Never fabricate data, never
silently hide or lose evidence, always surface uncertainty. A duration the log does not
prove must read "Unavailable", not a plausible-looking number. This overrides tidiness,
row counts, and looking finished.

---

## Current work: RDP / Remote Assistance session reconstruction

Subject: `_RemoteAssistanceDialog` in `evtx_tool/gui/main_window.py`. Its
`_build_sessions()` is a `@staticmethod` shared by BOTH operating modes, which is why
mode parity is testable at all.

Reference: SANS 508.2 Intrusion Analysis, "RDP Logs — Source System"
(~pp. 66-69). Courseware is not redistributable; consult your own copy.

### Commits (all on `beta`, 2026-07-21 → 2026-07-28)

| Commit | What it did |
|---|---|
| `bd17cc8` | New session type "RDP (Outbound)" for source-side RDP; direction-aware peer extraction; "Remote IP" column |
| `4b04646` | Replaced time-proximity bucketing with the RDPClient state machine; added Evidence + Source Log columns |
| `6cee66f` | Audit r1: dedup, sort-key/bucket-key mismatch, `LONG_SPAN_VERIFY`, flag tooltips |
| `4df09bb` | Audit r2: 1105 demoted to a tentative end, timestamp-precision parity, `UNDATED_EVENTS` |
| `07d3325` | Audit r3: cross-file dedup, UserData payloads, proof-bounded durations, `LOCAL_CONSOLE` |

### Why the outbound rework was necessary (the reasoning that matters)

Source-side RDP lives in **TerminalServices-RDPClient/Operational**, recorded ONLY on the
initiating host: **1024** = destination host name (`Value`, Name="Server Name"), **1102** =
destination IP, **1029** = Base64(SHA256(username)), **1026** = disconnect reason,
plus 1025/1103/1105. Security **4648** counts only when `TargetInfo` contains `TERMSRV/` —
`net use`, `runas /netonly` and scheduled tasks also carry a `TargetServerName`, so gating
on that alone over-classifies.

**Direction note — do NOT revert:** RemoteDesktopServices-**RdpCoreTS** is the
DESTINATION-side stack; its EID 131 records an INBOUND connection (the IP is the *source*
client). It is deliberately excluded from outbound classification, because including it
would make any host that merely *received* RDP report an outbound connection.

**There is no session key in this log.** Checked the raw XML: `Correlation ActivityID` and
`Execution ProcessID` exist but are not stable per connection. Log sequencing is therefore
the only honest pairing basis. Measured on the real log, the old 120 s proximity window
produced **9 rows from 7 sessions** — long sessions split (connect row + orphan disconnect
with no destination) *and* sessions 5/6 merged (session 6's 1024 arrived 0.28 s after
session 5's 1026, inside the window).

**The fix — `_outbound_bucket()` state machine**, routed at the top of bucket selection so
inbound and Classic RA paths are untouched:
- **1024 always anchors a NEW session** → two 1024s can never share a row.
- **1026 is the only authoritative end.** 1105 means only that the multi-transport (UDP)
  side dropped; it can fire mid-session while the session continues over TCP. It sets a
  *tentative* end, and a later 1026 with no intervening 1024 reclaims the session at any
  gap. A 1105 that never gets a 1026 keeps its duration but is flagged `END_INFERRED`.
- **False-positive guard (the user's explicit concern):** if a 1024 arrives while one is
  still open, NEITHER may claim a later disconnect — previous gets
  `NO_DISCONNECT_LOGGED`, new gets `AMBIGUOUS_PAIRING`, both durations "Unavailable".
  Verified the ambiguity does **not** cascade: the next isolated session reports a real
  duration again.
- A Security **4648 written just BEFORE its 1024** (the normal ordering) is *adopted* by
  that 1024 via `_ob_anchored`, else every NLA logon split into two rows.
- Duration shown only when start and end are both proven and unambiguous.

### Flag vocabulary

`_FLAG_HELP` (class attr) carries hover text for every flag. **Invariant: the set of flags
`flags.append(...)` can emit must equal the `_FLAG_HELP` keys, both directions.** These
flags are the only warning an analyst gets that a duration is untrustworthy, so an
undocumented one is a warning nobody can act on.

`AMBIGUOUS_PAIRING` · `CONTROL_GRANTED` · `DISCONNECT_ONLY` · `END_INFERRED` ·
`LOCAL_CONSOLE` · `LONG_SPAN_VERIFY` · `NO_DISCONNECT_LOGGED` · `OUT_OF_ORDER` ·
`REMOTE_ACCT:<acct>` · `SINGLE_EVENT` · `UNDATED_EVENTS:<n>` · `UNFILTERABLE_EVENTS:<n>`

Second invariant: `assert len(_EXTRACTORS) == len(self._HEADERS)` in the CSV export
(currently 14 = 14). Both invariants were checked by grep on 2026-07-28 and hold.

### Ground truth for the sample log

`Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx` (local test corpus, not
in-repo) → **7 outbound sessions**, every destination populated, no flags, durations
**`[6395, 29, 14, 16, 3, 4507, 383]`** seconds.

Those are `int()`-truncated, not rounded — 29.854 s displays as "29s". An earlier note
recorded `[…, 30, 15, 4, 384]`; that came from a `round()` in a throwaway verification
script, and the tool was always right. Do not "fix" this to match the old figure.

**The corpus contains four copies of every log** (`X.evtx`, `X - Copy.evtx`,
`X - Copy (2).evtx`, `X - Copy - Copy.evtx`). This is a load-bearing test property, not
noise — see the dedup finding below.

---

## Audit findings (hypothesis → signal → outcome)

Rounds 1-3 were adversarial: tests written to *break* the code, not confirm it. Six real
defects, one self-inflicted regression caught by the existing suite.

1. **Duplicate records fabricated a session and destroyed a real one.** Every 1024 anchors
   a session, so an ingested duplicate both invented a phantom session AND tripped the
   overlap guard on the genuine one → `AMBIGUOUS_PAIRING` / "Unavailable" for a session the
   log fully proves. Round 1 keyed dedup on `(source_file, record_id)` — which does nothing
   when the copies have different NAMES. On the real corpus that meant **7 sessions rendered
   as 70 rows, every duration "Unavailable"**: failed safely, but unusable. Identity is now
   host + channel + event id + exact timestamp + record id, filename excluded. Collapsed
   copies are disclosed — Source Log lists every file a record was found in.
2. **Sort key ≠ bucket key.** Grouping stripped the Computer value, the sort did not, so a
   Computer with stray whitespace kept one host in one bucket but delivered its events out
   of chronological order — and the state machine pairs by log order. Reproduced a connect
   paired to another session's disconnect. Sort now derives the key identically and orders
   on the **parsed** timestamp (raw-string order also breaks across the two engines'
   timestamp shapes, and sorts `09:00:00.5Z` before `09:00:00Z` since `'.' < 'Z'`).
3. **1105 treated as a hard end** → a 1-hour session reported as 5 minutes plus a phantom
   orphan row. See the state machine above.
4. **Multi-day spans presented as confidently as short ones** (3 weeks → "504h 00m 00s /
   Completed", no caveat). Duration stands — it is what the log says — but now carries
   `LONG_SPAN_VERIFY` past 24 h, prompting corroboration against reboot/sleep.
5. **Timestamp-precision setting ignored** in this browser (Logon and WiFi honour it), and
   sub-second detail was discarded at build time. Sessions now carry
   `start_ts_full`/`end_ts_full` rendered via `_fmt_ts_precision`, in the table AND the CSV
   export so an export cannot disagree with the table.
6. **Unparseable timestamps** were silently grouped into a session-looking row. Kept, but
   flagged `UNDATED_EVENTS:<n>` — they cannot bound Start/End.

**Regression caught by the old tests:** making 1105 tentative split a 1105+1026 orphan
teardown (no connect in the log) into two rows. The orphan path needed the same marker.
Lesson: keep old assertions green rather than adjusting them to fit a new theory.

**A test-harness bug that masqueraded as a product bug:** JM mode reported 53 inbound
sessions vs normal mode's 109. The product was right — my hand-rolled reference parser
dropped `<UserData><EventXML>`, where LocalSessionManager stores `SessionID`. Both modes
agree at 53 once the reference parses UserData. Do not "fix" the product toward 109.

### Juggernaut-mode parity — verified end to end (2026-07-28)

Real `HeavyweightEngine` → real Parquet → the real `_RemoteAssistJMFetchWorker` SQL, on the
duplicate-laden corpus. Both modes agree exactly: 7 outbound, 53 inbound, identical
durations, destinations and evidence. Every JM event carries the `source_file`, `record_id`
and `computer` that dedup and filter-to-session depend on. Engine record fidelity checked
separately: 32446/32446 records, deterministic across three rebuilds.

Note for future SQL work: the Parquet writer stores `LogonType` as a JSON **number**
(`"LogonType":5`), so string-equality predicates on it are fragile.

---

## OPEN DEFECT — fabricated multi-hour INBOUND durations

**Not fixed. This is the top priority.** It is the same failure the outbound state machine
was built to eliminate, still live on the destination-side path.

All LocalSessionManager `SessionID` values in the sample log are `"1"`, so the explicit-key
bucket for key `"1"` stays open and absorbs later, unrelated logons.
`_OPEN_KEY_CORR_SECS = 604800.0` (7 days) is the window an already-open keyed bucket gets.
Consecutive logons therefore collapse into one row.

Measured: **42 of 48 durations match ground truth, 6 do not — worst reports ~30 h.**

Why it matters: the user's explicit requirement was that a connect from one session must
never pair with a disconnect from another "which will make it look like the rdp session went
on for hours". That requirement was never scoped to outbound only. A 30 h row for a session
that was not 30 h is the exact failure mode, whichever code path emits it.

Shape of the fix: the inbound path needs its own state machine keyed on LSM event
semantics (21 connect / 22 shell start / 23 logoff / 24 disconnect / 25 reconnect) rather
than a shared `SessionID` plus a proximity window — the same treatment 1024/1026 got. It is
a subsystem change, not a one-line fix, which is why it is documented here rather than
half-started.

---

## Test infrastructure — LOST 2026-07-28, needs rebuilding IN-REPO

Eight harnesses totalling **159 checks green** lived in a session scratchpad under `/tmp`
and were **wiped by the environment**. All code work was
already committed, so nothing shipped was lost — but verification can no longer be re-run.

Lost: `test_rdp_pairing.py` (47), `test_rdp_render.py` (21), `test_rdp_extra.py` (22),
`audit_rdp.py` (14), `audit_tips.py` (9), `audit2_rdp.py` (18), `audit3_jm.py` (15),
`diag_jm_loss.py`.

**Lesson: `/tmp` is not durable. Rebuild them under `tests/` in the repo**, and keep the
venv outside git. Highest-value checks to restore first: real-log ground truth (7 sessions,
exact durations), the overlap/ambiguity guard, dedup on the duplicate-laden corpus, the
flag-help ↔ emitted-flags parity, and JM-vs-normal mode parity.

**Venv recipe** (the system `python3` 3.14 ships a PySide6 stub *without* QtWidgets, and
`ensurepip` is unavailable — do NOT use `--system-site-packages`, the stub shadows the real
wheel):

```bash
python3 -m venv --without-pip evtxvenv
curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
./evtxvenv/bin/python get-pip.py
./evtxvenv/bin/python -m pip install PySide6 evtx orjson pyarrow duckdb psutil
```

Harnesses need `QT_QPA_PLATFORM=offscreen`.

---


## Root cause: OverflowError storm + segfault (2026-08-23)

Reported symptom: a flood of `OverflowError: int too big to convert` with
`libshiboken` in the traceback, ending in `Segmentation fault`.

**Hypothesis → action → signal → outcome**

| Hypothesis | Signal | Verdict |
|---|---|---|
| Payload too large (500k dicts) | emitted 500k dicts cleanly | ruled OUT |
| Teardown race at shutdown | control run failed without teardown | ruled OUT |
| An int in the payload exceeds signed int64 | `Signal(list)` -> `-1`; `Signal(object)` -> intact | **ruled IN** |

**Mechanism.** `Signal(list)` marshals through `QVariantList`, which coerces
every Python int to a **signed** 64-bit value. Windows event data legitimately
carries **unsigned** 64-bit sentinels: BITS writes `bandwidthLimit`,
`fileLength` and `bytesTotal` as `18446744073709551615` (2**64-1, "unlimited").
A scan of 385,792 real `event_data` blobs found 1,444 such fields
(`bandwidthLimit` x1404, `fileLength` x20, `bytesTotal` x20).

**Why this was worse than a crash.** The conversion does not fail closed. The
value silently arrives as **`-1`**. An analyst reading `bandwidthLimit: -1` is
reading a number the event log never contained.

**Blast radius, measured precisely** (do not overclaim this):
- Only the out-of-range field is corrupted. Neighbours in the same record
  (`bytesTransferred: 4194304`, `42`, `999`) still arrive **correct**.
- But every int converted after the bad one emits a **spurious** overflow
  warning -- shiboken reports "Value 42 exceeds limits of [signed] x", which is
  untrue. That is why the log had far more errors than offending fields.
- The leftover set-but-unraised exception surfaces as
  `SystemError: ... returned a result with an exception set`. Continuing into
  C++ with a live exception is the plausible route to the segfault.
- Empty tracebacks in the report are explained: shiboken raises from C++ with
  `exc_tb = None`. The excepthook was never at fault.

**Fix.** Five signals converted to `Signal(object)`, which passes the Python
object by reference and touches nothing:

Checked against what each worker actually emits, not assumed:

| Signal | Carries parsed `event_data`? | Exposure |
|---|---|---|
| `_JMAnalysisMaterializeWorker.finished_ok` | yes | **demonstrated -- the reported crash.** Rebuilds every event from Parquet, BITS records included |
| `_WifiJMFetchWorker.finished` | yes (`"event_data": ed`) | exposed by shape; scoped to WLAN-AutoConfig, where no 2**64 value was observed on this corpus |
| `_RemoteAssistJMFetchWorker.finished` | yes (`"event_data": ed`) | exposed by shape; scoped to RA/RDP channels, same caveat |
| `_ComputerNormJMWorker.finished` | **no** — `{computer: str, source_file: str, n: COUNT(*)}` | not exposed; converted for consistency only |
| `CheckableComboBox.filterApplied` | **no** — values are always `str(val)` | not exposed; precautionary |

Only the materialize worker was ever demonstrated to corrupt. Two more were
exposed by shape. Converting the last two was harmless but was not fixing a
live bug -- worth stating plainly rather than implying five live defects.

`gui/worker.py` (normal mode) already used `Signal(object, ...)`, which is why
normal mode never corrupted. Only the JM workers were written with `list`.

**Deliberately left as `Signal(dict)`, verified safe by inspection:**
- `jm_col_worker.py` (212, 333, 389, 463) -- `{value_str: count}`; keys are
  always `str(...)`, values are `COUNT(*)`, bounded by the row count.
- `ps_worker.py:47` -- `PSExtractor.run()` summary; every value is a
  `len()`/`sum()` count or a bool. No event field passes through.

Both are allowlisted in the regression test so a future edit that starts
putting raw event values in them trips the check.

### Teardown gap found while investigating (separate defect)

`_cleanup_juggernaut()` gave `_col_value_workers` a disconnect-cancel-wait "so
their finished signals don't fire into a torn-down state" -- and **skipped
`_jm_mat_worker` and `_jm_export_worker`**, which only `closeEvent()` handled.
`_cleanup_juggernaut` also runs on **"start a new parse"** (10257), **"parse
error"** (10667) and **"clear results"** (14057), and it `rmtree`s the Parquet
directory both workers read.

The forensic hazard is not the rmtree -- on Linux an unlinked file with an open
fd keeps reading. It is that a late `_JMAnalysisMaterializeWorker.finished_ok`
starts a **full AnalysisRunner over events rebuilt from the OLD dataset**, so
the IOC / Correlation tabs can show findings from the previous set of logs
while a different set is loaded. Evidence attributed to the wrong logs.

Fixed by moving a cancel-and-disconnect into `_cleanup_juggernaut` itself. The
disconnect is deliberately **narrow and per-worker**, because a blanket one
creates a second evidence problem:

| Worker | Signals dropped | Why |
|---|---|---|
| `_jm_mat_worker` | `finished_ok`, `progress` | `finished_ok` is the dangerous one -- it starts the stale-dataset AnalysisRunner. `progress` writes into the loading dialog cleanup just closed. `failed` is **kept** so a cancel still sets the status line. |
| `_jm_export_worker` | none | Its handlers touch nothing being torn down (own progress dialog + a message box). Cancelling **deletes the partial file**, so silencing `failed` would destroy an analyst's export with no notification at all. "Export was cancelled and the partial file was deleted" must still reach them. |

**The wait is 500 ms, not the 5 s `closeEvent` uses.** `_cleanup_juggernaut`
runs on the **GUI thread** from the ✕ button and from "start a new parse",
neither of which has a dialog up -- a multi-second freeze there is exactly the
"is it stuck?" behaviour this project was asked to remove. And the wait cannot
be made reliable anyway: the materialize worker checks `_cancel` only between
50k-row fetches, and its DuckDB `execute()` runs an `ORDER BY` over the whole
corpus *before* the first check, which is not interruptible at all.

So waiting is belt-and-braces, not the safety mechanism. The **disconnect** is
what closes the hole; `parent=self` keeps the QThread from being destroyed
while running, so letting it drain in the background is safe. A shard opened
after the `rmtree` just raises inside the worker, which its own error path
already handles.

Also checked, since `Signal(object)` shares the container by reference where
`Signal(list)` copied it: **no worker mutates the payload after `emit`** -- in
all four, the emit is the last statement of `run()`.

### The crash: REPRODUCED on real logs, then fixed (2026-08-23)

The earlier caveat ("plausibly downstream, not re-verified") is retired. With
the real BITS logs the whole thing reproduces on demand. Everything below was
run as a **subprocess** so a death by signal shows up in the returncode --
an in-process crash kills the test runner and tells you nothing.

`tests/test_overflow_realdata.py` -- 4 real BITS files, 4,712 rows, ground
truth taken straight from Parquet with DuckDB, then the **real**
`_JMAnalysisMaterializeWorker` on a **real** QThread:

| | pre-fix | post-fix |
|---|---|---|
| out-of-range values delivered intact | **0 of 1,444** | **1,444 of 1,444** |
| fabricated `-1` values | **1,444** | 0 |
| `OverflowError` occurrences | 31,789 | 0 |
| `index.data(UserRole)` on real events | fails | 200/200 |
| checks passed | 4/10 | **10/10** |

`tests/test_overflow_soak.py` -- 6 cycles of materialize-to-completion plus 6
cycles of cancel-mid-flight-and-tear-down:

| configuration | exit code | `OverflowError` | outcome |
|---|---|---|---|
| pre-fix (as reported) | **134 = SIGABRT** | 190,823 | **process killed** |
| signal fix only | 1 | 1 | no fatal death |
| signal + teardown fix | **0** | 0 | clean, 6/6 |

**What actually kills the process.** The last line before the abort is
`QThread: Destroyed while thread '' is still running` -- but the isolation run
shows that message alone is *not* fatal: with the signal fix in place and the
teardown fix removed, the thread is still destroyed while running and the
process exits normally. **It is the exception storm that turns it fatal.**
Fixing the signals is what stops the crash; the teardown fix is needed for the
separate forensic reason (stale-dataset analysis) and to clear the warning.

**One honest gap.** The user reported `Segmentation fault` (SIGSEGV); what
reproduces here is `SIGABRT` (exit 134). Both are fatal signal deaths out of
the same storm, and both are gone post-fix -- but this is SIGABRT observed,
not SIGSEGV, and should not be written up as if it were.

### Test-hygiene note: `test_jm_functional` is slow, not hung

It idles at 0% CPU for minutes after check 7 and looks hung. It is not — it
completes 44/44. `settle()` in that suite connects to `busy_finished` and waits
up to **300 s**, but `ArrowTableModel.sort()` early-returns without emitting
anything when the requested order is already applied (and `_invalidate()` does
the same when `where_key` is unchanged). Those early returns are correct for
the app — no `busy_started` is emitted either, so the GUI never shows a dialog
it cannot close — but the test assumes every `sort()` dispatches work, so one
no-op sort costs the full 300 s timeout.

Worth fixing so a future session does not mistake it for a deadlock: have
`settle()` connect `busy_started` too and return immediately when no work was
dispatched (`busy_started` is emitted synchronously inside the call, so after
the operation returns you already know). Not done here — it is a test change
unrelated to the crash being fixed.

**Tests.** `tests/test_signal_int_overflow.py` (18 checks) and
`tests/test_jm_teardown.py` (14). Both were confirmed non-vacuous by running
them against the pre-fix code: 18 -> 10 and 14 -> 6. The `@Slot` guard was
additionally proved live by dropping a throwaway `@Slot(list)` into the package
and watching it get named.

Full suite: **28 suites, 437/437** (adds `test_overflow_realdata` 10,
`test_overflow_soak` 6, `test_large_multifile_split` 10, `test_ad_same_name_large` 9,
`test_gui_launch_smoke` 6, `test_no_silent_errors` 16, `test_record_accounting` 10,
`test_corrupt_chunk_recovery` 8, `test_many_large_files_split` 9).

| suite | | suite | |
|---|---|---|---|
| test_analysis_partial | 22 | test_jm_sort_perf | 24 |
| test_busy_feedback | 22 | test_normal_filter_perf | 18 |
| test_col_popup_prewarm | 12 | test_parse_integrity_perf | 8 |
| test_integration_e2e | 28 | test_profile_combo | 10 |
| test_jm_export | 11 | test_ram_gates | 23 |
| test_jm_functional | 44 | test_search_coverage | 53 |
| test_jm_investigation_parity | 9 | test_signal_int_overflow | 18 |
| test_jm_teardown | 14 | test_overflow_realdata | 10 |
| test_overflow_soak | 6 | test_large_multifile_split | 10 |
| test_ad_same_name_large | 9 | test_gui_launch_smoke | 6 |
| test_no_silent_errors | 16 | test_record_accounting | 10 |
| test_corrupt_chunk_recovery | 8 | test_many_large_files_split | 9 |
| test_worker_reaping | 7 | test_timezone_dst | 8 |
| test_export_safety | 16 | test_correlation_causality | 6 |


## >64 MB multi-file splitting — re-verified on built fixtures (2026-08-23)

The user asked for proof that "multiple evtx files above 64 mb don't get parsed
properly" is really fixed, without having such files to test with. Both fixes
from 2026-07-12 are present in `core/heavyweight/engine.py`:

- `_EVTX_HDR_BLOCK = 4_096` (line 124), used for the header copy (225), the
  chunk seek (244) and the chunk count (215) — Bug 1, the 3968-byte truncation.
- `tag=str(file_idx)` at the single call site (972), shard name
  `_hw_split_{tag}_{i}_{pid}.evtx` (241) — Bug 2, the cross-file collision.

**Present is not proven, so they were re-verified empirically.** No file in the
sample corpus exceeds 64 MB (largest is 32 MB), so
`tests/test_large_multifile_split.py` BUILDS fixtures by replicating a real
file's 64 KB chunks. Replication is byte-exact, which makes ground truth exact:
records == original x reps. Four files from four DIFFERENT channels — identical
content would make a cross-file collision invisible:

| fixture | size | records |
|---|---|---|
| Big_Security.evtx | 80 MB | 122,216 |
| Big_Application.evtx | 80 MB | 154,748 |
| Big_System.evtx | 80 MB | 163,852 |
| Big_Ntfs%4Operational.evtx | 96 MB | 63,579 |

All four exceed the gate, all split 8 ways, parsed together in one run:
**504,395 rows, per-file counts exact, per-file CHANNEL breakdowns exact, 10/10.**

**The test is proven non-vacuous by reintroducing each bug:**

| injected fault | result |
|---|---|
| `tag="0"` (Bug 2) | 7/10 — totals wrong, per-file counts wrong, channels cross-contaminated |
| 128-byte header offset (Bug 1) | 5/10 — 740 records lost from Big_Security alone, 4,107 overall |
| neither (current code) | **10/10** |

Note the shard-name check still passes under the Bug 2 injection: it calls
`_split_evtx` directly with distinct tags, so it tests the *function's*
contract, while the engine-level checks test the *call site*. Both are needed —
neither alone would have caught the original bug.

**Edge case examined and dismissed.** When `n_chunks < n_parts`, `per` floors to
1 and the loop can construct a shard whose window starts past EOF. It cannot
fire from the only call site: the `size_mb > 64` gate guarantees >= 1023 chunks
against at most ~16 workers. `_split_evtx` has one caller, so this is currently
unreachable — but a future caller using `_EVTX_MIN_SPLIT` (8 chunks) directly
would hit it.

## JM correctness audit (2026-08-23)

Re-checked the "three divergent extraction impls" follow-up from
[[split-evtx-record-loss-bugs]]. **Most of it is already fixed:**

- `_safe_int` now handles the dict EventID quirk (`{"#text": N}`) — JM no longer
  reports `event_id=0` for classic-provider events.
- Qualifiers are extracted in JM (`engine.py` 359-368), previously dropped.
- `original_file` stores the FULL path, not the basename, so
  `host1/Security.evtx` and `host2/Security.evtx` keep distinct identities.

**One divergence remained and was closed.** Normal mode resolves EventID as
`#text` *then* `Value`; JM read only `#text`. Measured across 250 files /
399,738 records: 210,234 dict-shaped EventIDs, **all** carrying `#text`, none
`Value`-only. So this was a latent parity gap, not a live bug — closed anyway
in `_safe_int` so the two modes cannot diverge on a log we have not seen.

## "Are the errors fixed, or just swallowed?" — audited (2026-08-23)

A fair challenge, since the teardown fix does add `disconnect()` calls and a
`warnings.simplefilter("ignore", RuntimeWarning)`. Audited by grepping the diff
for every suppression introduced. There are exactly three, **all in
`_cleanup_juggernaut`, none in the data path**:

1. `catch_warnings() + simplefilter("ignore", RuntimeWarning)` around the
   disconnect loop. Only `getattr` and `.disconnect()` run inside; neither
   marshals data, so no overflow warning can originate there.
2. `try: _sg.disconnect() except (RuntimeError, TypeError): pass` — PySide
   raises when disconnecting a signal that has no connections, which is
   expected during defensive teardown.
3. `try: _mw.cancel() except Exception: pass` — `cancel()` only sets a bool.

**The actual fixes contain no suppression at all.** `Signal(object)` and
`EventRef` change how data is marshalled; they do not hide anything.

**Proof the suppressions are not doing the work.** Keeping every suppression,
every disconnect and `EventRef` in place, and reverting ONLY the four signal
declarations back to `Signal(list)`:

| configuration | real-data result |
|---|---|
| full fix | **10/10** |
| all suppressions kept, signals reverted | **5/10** — fails on value equality |

The suppressions cannot mask corruption because the tests assert **value
equality against independent ground truth** (1,444 values read from Parquet via
DuckDB), not the absence of errors.

**Pre-existing swallow found in the same function, reported not hidden.** The
materialize worker does:

```python
try:    ed = _json.loads(r[11]) if r[11] else {}
except Exception:  ed = {}
```

A malformed `event_data_json` silently becomes empty `event_data` — no flag, no
`failed` emit, and the analyst cannot tell "no data" from "failed to parse".
Measured on 120 files / 334,390 rows: **0 parse failures** (10,358 rows have a
legitimately NULL blob). So it is latent, not active — but it is a genuine
fail-silent path in evidence handling and should get an explicit marker rather
than an empty dict. Not changed here; it is unrelated to the crash and belongs
in its own scoped change.

## AD scenario: many >100 MB files ALL named Security.evtx (2026-08-23)

Asked directly: Security.evtx pulled from every DC in a forest — same basename,
same channel, same event types, each over 100 MB, different contents. Does JM
handle it?

This is strictly harder than `test_large_multifile_split.py`, and **that test
would not have caught a failure here**: it used four different basenames from
four different channels, and its cross-contamination check keyed on channel.
With three Security.evtx files, neither discriminator exists.

`tests/test_ad_same_name_large.py` — three 120 MB files, all named exactly
`Security.evtx`, in `DC01/`, `DC02/`, `DC03/`, each built from a different
source channel so contamination is detectable at all:

**661,224 records, per-file counts exact, no collapse, no cross-contamination,
9/9.** The DATA layer was already correct: the engine keys on the FULL path, so
`DC01/Security.evtx` and `DC02/Security.evtx` never merge.

**But the DISPLAY layer was not, and that is a real finding.** Both per-file tab
sites did `display_name = os.path.basename(filepath)`, so three DCs produced
**three tabs all labelled "Security.evtx"** with no way to tell them apart.
Correct data an analyst cannot attribute to a host is not usable evidence.

Fixed with `unique_display_names()` — each label grows leftwards along its own
path only as far as it must, giving `DC01/Security.evtx`, `DC02/Security.evtx`,
`DC03/Security.evtx`. Files with unique basenames are unchanged. The full path
was already on the tab tooltip; this is about what is readable without hovering.

**Note a vacuous check caught in my own test.** The label assertion first called
`unique_display_names()` directly, so it passed even with the tab sites reverted
to `basename` — it proved the helper worked, not that anything used it.
Rewritten to go through `MainWindow._tab_label_for()`; pre-fix it now fails 7/9
with `labels=['Security.evtx', 'Security.evtx', 'Security.evtx']`.

## GUI launch smoke test (2026-08-23)

Never done before in this project, and the gap that caused the earlier "have you
been lying to me" exchange: every suite runs headless, so none of them proves
the app starts. `scratchpad/launch_smoke.py` runs the REAL `eventhawk_gui.py`
entrypoint with `QApplication.exec` patched to pump events for 5 s and return.
Result after all the changes above: MainWindow constructed, `title='EventHawk
v1.3'`, visible, **0 uncaught exceptions, clean exit**. Promoted to `tests/test_gui_launch_smoke.py` (6 checks); also passes on a REAL
display with `QT_QPA_PLATFORM` unset, so the Qt platform plugins are fine too.

**A launch failure has one known cause: using the system Python.** Verified
here — `python3 -c "import PySide6.QtWidgets"` raises
`ModuleNotFoundError: No module named 'PySide6.QtWidgets'` (the distro package
is a namespace stub), while every other dependency imports fine. The venv has
all seven. So `python3 eventhawk_gui.py` fails and `./run.sh` works.

## "No data skipped, no silent error" — full audit (2026-08-23)

### THE FINDING: two evidence-loss warnings never reached the analyst

Normal mode filtered engine warnings with a substring **whitelist**:

```python
if ("could not be parsed" in w or "ABORTED" in w or "TRUNCATED" in w)
```

The engine writes `"parse aborted mid-file"` — **lowercase**, so `"ABORTED"`
never matched — and `"record(s) ... were not parsed"`, which is not the phrase
`"could not be parsed"`. Verified against the literal strings:

| warning | severity | reached the analyst? |
|---|---|---|
| `file appears TRUNCATED — ...` | evidence loss | yes |
| `N record(s) could not be parsed and were skipped` | evidence loss | yes |
| `parse aborted mid-file (...)` | **evidence loss** | **NO — silent** |
| `N record(s) ... were not parsed` | **evidence loss** | **NO — silent** |
| `CPU > N% — throttled` / `RAM pressure` | performance | no (correct) |

The abort case is the worst one in the system: **every record after the
failure point is missing** from the session, and the dialog said nothing. Both
went to the log only, which for a GUI user is indistinguishable from a clean
parse.

**Fix — classify at the source, not by matching text.** `append_warning(msg,
benign=True)` tags the three non-loss messages at the three call sites that
write them (`engine.py` Ctrl+C / RAM pressure / CPU throttle); the GUI shows
everything *not* tagged. A denylist fails the safe way: an unrecognised warning
is shown, never hidden. `worker.py` forwards `parse_benign_warnings`, and fails
loud — if that list cannot be read, nothing is classified benign.

### Three adjacent gaps, same class

- **`[:15]` with a bare `"…"`** in both dialogs — a loss report that silently
  truncates itself. Now `"…and N more"`.
- **`except Exception: logger.warning("Parse-integrity check failed")`** — the
  watchdog failing invisibly is worse than any one warning being dropped,
  because the analyst reads a clean parse as "nothing wrong" when in fact
  nothing was checked. Both handlers now raise a dialog saying the session is
  NOT confirmed complete.
- **`os.path.basename(k)` in the JM problem list** — three DCs' Security.evtx
  gave three identical prefixes in the one dialog that says which evidence
  failed to load. Now uses `unique_display_names`.

### Record accounting — verified, not assumed

`tests/test_record_accounting.py` on 40 real files:

- `iterated == json_errors + extract_errors + filtered + rows` balances for
  **every** file — no record leaves the pipeline without a counter;
- reported rows == rows actually in Parquet (**241,578 exact**);
- `iterated` matches pyevtx-rs ground truth per file — nothing skipped upstream.

Damaged inputs must be reported, never silently empty. All four handled:

| fixture | outcome |
|---|---|
| truncated (header over-declares) | parses 38,687 rows **and** flags `truncation` |
| non-EVTX garbage | 0 rows + `open_error` (bad magic) |
| zero-byte file | 0 rows + `open_error` |
| header-only, no chunks | 0 rows + `truncation` |

No crash on a batch of all four.

### Swallowed exceptions — swept, and they are fine

36 `except` blocks in `engine.py`, 16 bare `pass`/`continue`. Every one is in
teardown/cleanup (`rmtree`, `terminate`, `unlink`, `queue.close`, `join`,
`getsize`) or the last-resort DONE emit. **None is in the record path.**
`parser.py` has zero bare swallows.

### Tests

`test_no_silent_errors.py` (12) parses `engine.py` with `ast` and asserts every
`append_warning` call site is classified consistently with its own text — the
check that would have caught this bug — then runs the real strings through the
real classifier. Non-vacuous: 12/12 -> 8/12 with the whitelist restored.
`test_record_accounting.py` (10).

## Damaged-chunk recovery: salvage now runs on split shards (2026-08-23)

Asked whether a file that "appears truncated" can have events pulled out of it
instead of being skipped. Two separate answers, because two different things
were happening.

### Truncated files were already fully recovered — nothing was being skipped

Measured on genuinely truncated fixtures (body cut, not just a lying header):

| fixture | pyevtx | engine | flagged |
|---|---|---|---|
| cut at a chunk boundary (106 of 320 chunks) | 13,795 | **13,795** | truncation |
| cut mid-chunk | 13,795 | **13,795** | truncation |
| header + 5 KB fragment | 0 | 0 | truncation |

The engine matches the parser exactly: every intact chunk is already read, and
the truncation is reported. A partial trailing chunk is genuinely unreadable —
there is no complete record structure left to recover.

### The real loss was a corrupt chunk MID-file, on a split file

pyevtx-rs does not skip a bad chunk, it **aborts the whole parse**. One
corrupted 64 KB chunk in a 100 MB file makes all 193,435 records unreachable.

Salvage (`core/chunk_salvage.py`) isolates each chunk into its own single-chunk
file and parses it alone, so only the broken chunk is lost — but it was gated
`if stream_error and not is_split`, i.e. **off for exactly the big files that
get split**. The reasoning ("splitting already gives chunk isolation") is true
but insufficient: isolation is per-SHARD, so an abort discards the whole shard.

Measured on 100 MB / 1,600 chunks with one chunk destroyed:

| | records | lost |
|---|---|---|
| plain pyevtx | 0 | **all 193,435** (aborts) |
| split, salvage off (before) | 177,983 | 15,452 — **8.0%** |
| split + salvage (now) | **193,342** | 93 — **0.05%** |

**15,359 records recovered** that were previously discarded. The remaining 93
live inside the destroyed chunk itself.

Salvage is safe on a shard: it reads the chunk index of the file it is GIVEN,
isolates chunks from that file, and dedupes against `already_emitted` by record
ID — none of which needs the shard to be a whole log. The original objection was
about expected-vs-actual ACCOUNTING, which is a **different gate** and is still
`not is_split` (a shard's header declares the original file's ranges, so
`expected_record_count` would compare against the wrong total).

Recovery does not hide the damage: `stream_error` is still reported, and the
test asserts recovered <= intact so salvage cannot double-count.

`tests/test_corrupt_chunk_recovery.py` (8). Non-vacuous: 8/8 -> 5/8 with the
old gate restored, showing exactly the 7.99% loss.

### The two silent warnings — now proven fixed END TO END

The classifier fix is verified through the REAL handler, not just the tag:
`test_no_silent_errors.py` now builds a `MainWindow`, feeds a stub worker the
literal engine strings, captures `QMessageBox.warning`, and asserts the text
the analyst would read contains "parse aborted mid-file" and "were not parsed",
and does NOT contain the throttle notice. 16/16; **12/16 with the whitelist
restored**, with both END-TO-END checks failing — so they catch the original
bug directly rather than only the tag.

## 64+ files, every one over the split threshold (2026-08-23)

The shard-collision bug came from naming sub-files `_hw_split_{i}_{pid}` —
identical for every source file in a run. Asked to stress the per-file tag that
fixed it, at 64+ files.

**Naming math first.** `_hw_split_{tag}_{i}_{pid}` over 80 tags x 16 shards
generates 1,280 names, **0 collisions**. The concatenation worry
(`tag=1,i=12` vs `tag=11,i=2`) does not arise: underscore-separated integers
parse unambiguously, so `_hw_split_1_12_*` != `_hw_split_11_2_*`.

**Then the real thing.** `tests/test_many_large_files_split.py` builds **66
files, 6.9 GB, 80–160 MB each — every one over the 64 MB threshold**, so all of
them split, ~800 shards live in one temp directory at once (all splitting
happens up front, before any worker starts). Four channels are cycled and the
record counts varied so that contamination is actually detectable — identical
content would hide it.

**10,546,780 records. 66/66 exact per-file counts. Zero cross-contamination.
Counters balance for every file. No shard left behind. 9/9.**

### Operational fact worth knowing

**Splitting doubles the disk requirement.** Peak usage for that run was **14 GB
for 6.9 GB of logs** — the shards are a full second copy of the data. An
analyst loading 60+ large DC exports needs roughly 2x free space on TMPDIR, and
TMPDIR is where the shards go, not the output directory. The test therefore
sets TMPDIR to a chosen volume and skips loudly (rather than failing on ENOSPC)
when the volume cannot hold ~0.22 GB per file.

### A test-hygiene fix

The first run printed a `FileNotFoundError` traceback *after* reporting 9/9:
the test deleted its work dir in `finally:`, but multiprocessing's own
`pymp-*` temp dir lived inside it and its atexit finalizer then could not find
it. Alarming and untrue on a passing run. Fixed by removing the work dir from
an `atexit` hook registered BEFORE the first process is created — atexit is
LIFO, so multiprocessing cleans up first and this runs last.

## Ordinary bug audit (2026-08-23)

Static analysis (`ruff --select F,B,E9`) plus targeted inspection. 147 raw
findings, triaged:

| rule | n | verdict |
|---|---|---|
| F401 unused-import | 63 | cosmetic |
| **B023** function-uses-loop-variable | 30 | **all false positives** — every one is a local helper (`_mark_start`, `_a`, `_any_match`) INVOKED in the same iteration, so late binding never applies |
| F541 f-string w/o placeholder | 17 | cosmetic |
| F841 unused-variable | 12 | dead leftovers (e.g. `ioc_result`/`corr_result` predate the switch to futures) |
| **F821** undefined-name | 7 | **all false positives** — quoted annotations `"pa.Table"`, never evaluated |
| B904 raise-without-from | 5 | cosmetic (traceback chaining) |
| B033 duplicate-value | 1 | `"hair"` twice in a TLD **set** — dedupes, no detection gap |

Also verified guarded, not bugs: every division candidate
(`total_hint`, `len(letters)`, `total_rules`) has a zero check; no mutable
default arguments; no bare `except:`; the two non-context-manager `open()`
calls are deliberate long-lived crash-log handles.

### Real defects found and fixed

**1. `EventRef(None)` — a regression I introduced earlier this session.**
`heavyweight_model.data(UserRole)` returned `EventRef(self.get_event(row))`,
but `get_event()` returns `None` for an out-of-range row. `EventRef(None)` is
**truthy** (verified), so `if index.data(UserRole):` would flip from "no event"
to "an event that is None" and fail one dereference later. Now returns a falsy
`None`, preserving the original contract. Latent (no consumer today) but a
contract break in the very wrapper added for safety.

**2. Column/WiFi worker leak — measured, not theoretical.** These QThreads are
built with `parent=self`, so **C++ owns them and dropping the Python reference
does not free them**. `_track_col_worker` pruned its list but nothing ever
deleted the objects: after 12 column popups, **12 finished QThreads were still
parented to the MainWindow**, each pinning its input (the visible-events list
in normal mode, the Arrow table in JM) so the previous dataset could not be
freed either. That matters in a tool whose parse path is already RAM-gated.

Fixed with `finished.connect(worker.deleteLater)` for the column workers and
the WiFi fetch worker. **12 retained -> 0.** Because a Python reference can now
outlive the C++ object, every `isRunning()` on those references goes through a
new `_thread_running()` helper that treats a reaped worker as not running —
otherwise the fix would trade a leak for a `RuntimeError`. Also routed a
copy-pasted inline tracking block through `_track_col_worker` so it gets the
same treatment.

`_ps_worker` already did this correctly (`wait()` + `deleteLater()`) and was
the model. **Still unfixed, same class:** `_RemoteAssistJMFetchWorker`,
`_JMSessionFetchWorker`, `_ComputerNormJMWorker` are parented and never
deleted — one leaked thread per opening of those dialogs. Lower frequency than
the column popups, same one-line fix, deliberately left for a scoped change
rather than bundled in late.

**3. `zip()` without `strict=` at four sites** — Parquet table assembly and the
JSON/CSV export row builder. Lengths match by construction today, so this is
hardening rather than a live bug, but the failure mode is silent column drop in
a written artifact, which is the exact shape this project treats as cardinal.
Now `strict=True`, so a mismatch raises instead of quietly shortening a record.

## Worker reaping — two wrong fixes before the right one (2026-08-23)

Asked why the three remaining leaked dialog workers were left unfixed. The
answer given ("keeping the thread-lifetime change small") did not hold up — the
same change had already been made and verified twice. Fixed. Doing so exposed
that **the first two fixes were themselves wrong**, so the earlier "12 -> 0"
claim was only true on the success path.

**Correction to the earlier note:** `_JMSessionFetchWorker` does **not** leak.
It is constructed WITHOUT `parent=self`, so Python owns it and it is collected
normally — measured, 0 retained. Listing it was an error.

Two genuinely leaked, and were measured before fixing: 10
`_RemoteAssistJMFetchWorker` + 10 `_ComputerNormJMWorker` still parented after
10 dialog openings.

### Why `finished.connect(worker.deleteLater)` was the wrong fix

Every one of these classes **declares its own `finished` signal** carrying
results — `Signal(object, bool)`, `Signal(dict)` — which SHADOWS
`QThread.finished`. The metaobject carries both (`finished()` and
`finished(PyObject,bool)`), and Python attribute lookup resolves to the custom
one. That signal is only emitted on the SUCCESS path; an error emits
`fetch_error`/`failed` and returns. **Measured: 0 of 10 deletions fired on the
error path** — the worker leaks precisely when something has already gone
wrong. The column and WiFi fixes had the same hole.

**Right fix:** `_reap_finished_workers()` deletes by LIVENESS during the
existing prune — independent of which signal exists and of success or failure.
Cost: at most one finished worker per list outstanding until the next call.
Applied to all four lists plus `_cleanup_juggernaut`, which previously just
dropped the Python list and left the QThreads parented.

### A measurement trap worth remembering

`QApplication.processEvents()` does **not** deliver `DeferredDelete` events, so
a test that pumps processEvents and counts children reports the leak as
unfixed even when it is fixed. That is what made the correct fix look broken.
A real `QEventLoop` must be entered — which is what the running application
does. With one: **20 failed dialog workers -> 1 + 1 retained**, 10 succeeded
column workers -> 1.

`tests/test_worker_reaping.py` (7) pins both traps, including an assertion that
the shadowing is real. Non-vacuous: 7/7 -> 4/7 with deletion removed.

## Timezone: filter and display disagreed by an hour across DST (2026-08-23)

Fresh audit of timestamp handling — the highest-stakes area in the tool, since
a wrong timestamp is a wrong timeline.

Three places converted between display time and stored UTC by reading the
**current** local offset (`datetime.now().astimezone().utcoffset()`) and
stamping it onto a log timestamp. An offset is only true for the instant it was
read. The display path (`apply_tz`) instead used the real local zone, which
resolves DST per instant. So the two disagreed:

```
analyst working in July (EDT, -4), filtering January logs (EST, -5)
  filter boundary 2025-01-15 00:00 local -> 04:00Z   (today's offset)
  table displays  2025-01-15 05:00Z      -> 00:00    (that date's rule)
```

**One hour apart, silently.** "Show me 15 January" returned 23:00 on the 14th
through 22:59 on the 15th — evidence attributed to the wrong day, with nothing
on screen to say so. India (IST, no DST) never triggers it, which is likely why
it survived.

| site | before | after |
|---|---|---|
| `filter_sql.py` JM date range | fixed offset from "now" | naive `.astimezone()` — resolved for the boundary's own date |
| `models.py` normal-mode range | fixed offset from "now" | same |
| `jm_col_worker.py` date grouping | `INTERVAL 'N seconds'` | `AT TIME ZONE '<IANA name>'`, per-event DST |

`specific` and `custom` modes were already correct (ZoneInfo resolves DST; a
custom offset is fixed by definition) — only `local` was wrong. The date-grouping
expression documented its own limitation ("DST-period drift ... is a known
limitation"); it is now closed by resolving the system IANA zone name
(`TZ`, then `/etc/localtime`, then `/etc/timezone`) and reusing the same
`AT TIME ZONE` path `specific` already used. Falls back to the old offset form
if the name cannot be determined.

`tests/test_timezone_dst.py` (8) checks display, filter and grouping agree in
BOTH seasons. Non-vacuous: 8/8 -> 5/7 with the fixed-offset logic restored.

## Export audit: the deliverable itself was corruptible (2026-08-23)

Fresh area — exports are what an examiner hands to someone else, and every
string in an event is attacker-influenced (hostnames, command lines, registry
values). Three defects, all found by feeding hostile values through the real
exporters and PARSING the output rather than grepping it.

### 1. HTML: apostrophe broke out of every attribute

`_esc()` escaped `& < > "` but **not the apostrophe**, while every attribute in
the report is written with SINGLE quotes (`data-computer='...'`,
`value='...'`). A hostname of

    PC' onmouseover='alert(1)

closed the attribute and injected a working handler. Confirmed with an HTML
parser, not a substring search: **2 live `onmouseover` attributes**, e.g.
`<option onmouseover='alert(1)'>`.

**It corrupted ordinary data too**, which is the part that matters even with no
attacker: the parser read `data-computer` back as just **`PC`** — the value was
silently cut at the apostrophe. A host called `O'Brien-PC` loses everything
after the quote in the report.

Fixed by using `html.escape(s, quote=True)` (covers `& < > " '`) in both the
HTML and XML helpers. After: 0 injected handlers, full value preserved.

### 2. XML: control bytes broke the export two different ways

XML 1.0 forbids most control characters; Windows event data contains them
freely. Neither back end coped:

| back end | behaviour |
|---|---|
| lxml | raised `ValueError` — and `export_xml` only catches `ImportError`, so the export **died** |
| stdlib | wrote the bytes through, producing a file that **is not well-formed XML** — a corrupt deliverable with nothing reporting it |

Fixed with `_xml_text()`, which renders an illegal codepoint as a **visible,
reversible `\xNN` escape** rather than dropping it or substituting U+FFFD — the
examiner can still see exactly which byte was in the log. Both back ends now
emit well-formed XML, injected markup (`</Computer><evil>`) stays inert text,
and no `<evil>` element is created.

### 3. Verified sound, not changed

JSON round-trips the 2**64-1 sentinel and unicode exactly; CSV round-trips
embedded quotes and newlines through a real parser.

**CSV formula injection is a deliberate NON-fix and needs the author's call.**
A cell whose value begins with `=` (e.g. `=cmd|'/c calc'!A1`, which can appear
in a logged command line) is written verbatim, and Excel/LibreOffice will
evaluate it on open. The standard mitigation is to prefix such cells with an
apostrophe — but that **alters the exported evidence**, which this project
treats as the cardinal sin. Left as-is and flagged rather than silently
changing exported values; the trade-off is the author's to make.

### Test-hygiene note

The first version of the HTML assertion banned *all* `on*` attributes and so
failed on correct output — the report legitimately ships 12 `onclick` and 6
`onchange` handlers for its own sorting and filtering. Tightened to "no handler
outside the report's own set, and none carrying event-derived content". A
substring search for `onmouseover=` is likewise useless: after the fix the
escaped text still contains that substring, inertly. Both traps are written
into the suite docstring.

`tests/test_export_safety.py` (16). Non-vacuous: 16/16 -> 4/10 with the old
`_esc` restored and `_xml_text` disabled.

## Analysis audit: correlation chains claimed effects before causes (2026-08-23)

Fresh area — the analysis subsystem is where the tool draws CONCLUSIONS an
examiner acts on, so a defect here is worse than a display glitch.

### THE FINDING: two rules invented causal links

`_ts_delta()` returns `abs((tb - ta).total_seconds())`. A time window built on
it is **direction-blind**: "B within 60 s of A" also matches a B that happened
60 s BEFORE A. Most directional rules therefore pair the window with
`_ts_ge(...)`. Two did not:

| rule | window | effect |
|---|---|---|
| `_rule_ps_exec_chain` | 60 s | chained a PowerShell script block that ran up to 60 s **before** the spawn, as "Suspicious Process Spawn -> PowerShell Execution" |
| `_rule_privilege_escalation` | 30 s | chained a privilege assignment up to 30 s **before** the logon it was attributed to |

Proven by calling the rule directly: with the script block at 00:00:00 and the
spawn at 00:00:30, it emitted a chain containing both, record ids `[2, 1]` —
the "consequence" preceding its cause by 30 seconds.

`_rule_ps_exec_chain` even carried the fingerprint: `if 0 <= _ts_delta(...) <=
60`. That `0 <=` is dead code — `abs()` is never negative — which is what a
signed comparison looks like after it has been lost.

**This is the same defect class as the RDP pairing that fabricated multi-hour
sessions:** two real, correctly-parsed events joined into a relationship the log
does not support. A fabricated attack chain is worse than a missed one, because
it is evidence of an intrusion that did not happen in that order.

Fixed by adding the `_ts_ge` guard both rules were missing. The genuine forward
case still chains — the fix must not silence a real detection, and that is
asserted.

### Checked and found sound

- **Correlator scoping** — rules group by `(computer, user)` and look up events
  per host; the one cross-host rule (`multi_host_lateral_movement`) is
  deliberate. Verified a cross-host pair does NOT chain.
- **IOC scorer** — private/link-local IPs score 0 with an explicit
  "Private/internal address" reason; public 30; TOR exit 85; punycode/homograph
  85; typosquatting 40. Well built.
- **IOC extraction** — domains use a TLD allowlist, so `kernel32.dll` and
  `setup.exe` are not matched. One mild false positive remains: `command.com`
  is extracted as a domain (`.com` is also a Windows executable extension). It
  scores 0, the same as a legitimate domain, so it is list noise rather than a
  false alarm; left alone.

### Test-hygiene note (the same trap twice in one session)

The suite's blanket assertion "every bounded `_ts_delta` window sits next to an
ordering test" failed on CORRECT code: three sites compare `x[i]` against
`x[j]` from the same sorted list with `j = i + 1`, clustering N similar events,
where ordering is already guaranteed and an absolute delta is right. Narrowed to
directional windows only. This is the second time this session a blanket
assertion flagged correct code (the HTML `on*` check was the first) — worth
remembering that "no X anywhere" is usually too strong.

`tests/test_correlation_causality.py` (6). Non-vacuous: 6/6 -> 5/6 with the
guards removed.

## Session log

- **2026-07-21 → 2026-07-27** — Built outbound RDP as its own type; replaced proximity
  bucketing with the RDPClient state machine; added Evidence + Source Log provenance
  columns. Commits `bd17cc8`, `4b04646`.
- **2026-07-27** — Audit rounds 1 and 2 (`6cee66f`, `4df09bb`): dedup, sort-key mismatch,
  long-span flag, flag tooltips, 1105 semantics, precision parity, undated events.
- **2026-07-28** — Audit round 3 (`07d3325`): cross-file dedup (the 70-rows finding),
  UserData payloads, proof-bounded durations, `LOCAL_CONSOLE`; first end-to-end Juggernaut
  verification. Scratchpad wiped later the same day; confirmed committed state compiles and
  both grep-checkable invariants hold; wrote this journal. **Paused with the inbound
  fabricated-duration defect open and 6 commits unpushed on `beta`.**
- **2026-08-11** — Released the backlog: user asked to merge `beta` into `main`. Verified
  `main` held nothing `beta` lacked (merge base *was* `main`'s tip), so this was a clean
  fast-forward of 21 commits, not a merge. Redacted three local filesystem paths from this
  journal first, because `main` is the default branch of a **public** repo and the notes
  cited an OCR'd copy of SANS courseware by path. Pushed `beta`, fast-forwarded `main` to
  `3b6f4fa`, pushed `main`. No test suite gated this — the harnesses that covered the
  changed RDP code are the ones lost on 2026-07-28; verification was `compileall` clean
  plus the empty `beta..main` range. **The inbound fabricated-duration defect is unchanged
  and now sits on `main`** — it predates `beta` and was never a regression from it, but it
  is no longer confined to a side branch.
- **2026-08-23** — Root-caused the `OverflowError` storm to `Signal(list)` coercing
  unsigned 64-bit BITS sentinels to `-1` (see the section above). Converted five signals
  to `Signal(object)`; verified no `@Slot` still declares the old type. Found and fixed a
  separate teardown gap where `_cleanup_juggernaut` left the materialize/export workers
  running, which could attribute IOC/Correlation findings to the wrong dataset. Added two
  regression suites, both proven non-vacuous against pre-fix code. **Paused with the
  inbound fabricated-duration defect still open and 29 commits unpushed on `beta`.**
- **2026-08-23 (cont.)** — Audited whether the crash fixes suppress rather than fix:
  three suppressions exist, all in teardown, none in the data path; proved by keeping
  every suppression and reverting only the signals (10/10 -> 5/10). Re-verified the
  >64 MB multi-file split on built fixtures (four 80-96 MB files, 504,395 records,
  10/10; both original bugs re-injected and caught). Closed a latent JM/normal EventID
  parity gap. Flagged a pre-existing fail-silent `ed = {}` path (0 occurrences on the
  corpus). **Still paused with the inbound fabricated-duration defect open and 29
  commits unpushed on `beta`.**
- **2026-08-23 (cont. 2)** — "No data skipped, no silent error" audit. Found that normal
  mode's substring whitelist hid `parse aborted mid-file` and `were not parsed` — the two
  worst evidence-loss warnings; replaced with source-tagged classification that fails
  loud. Fixed the self-truncating problem list, the invisibly-failing integrity watchdog,
  and basename ambiguity in the integrity dialog. Verified record accounting balances on
  40 real files (241,578 rows exact) and that truncated / garbage / empty / header-only
  inputs are all reported rather than silently empty. 22 suites, 379/379.
- **2026-08-23 (cont. 3)** — Enabled chunk salvage for SPLIT shards: one corrupt chunk in
  a 100 MB file went from 15,452 records lost (8.0%) to 93 (0.05%) — 15,359 recovered
  that were previously discarded. Confirmed truncated files were already fully recovered
  (engine == pyevtx on three cut fixtures) and always flagged. Proved the two previously
  silent warnings now reach the real dialog END TO END through `_on_parse_finished`.
  23 suites, 391/391.
- **2026-08-23 (cont. 4)** — Stressed the shard-name tag at scale: 66 files, 6.9 GB, every
  one over the 64 MB threshold, ~800 shards in one run — 10,546,780 records, 66/66 exact
  per-file counts, zero cross-contamination, no shard left behind. Recorded the
  operational fact that splitting DOUBLES disk (14 GB peak for 6.9 GB of logs, on TMPDIR)
  and added a skip-with-guidance guard. Fixed a misleading post-PASS traceback caused by
  test cleanup racing multiprocessing's atexit finalizer. 24 suites, 400/400.
- **2026-08-23 (cont. 5)** — Ordinary bug audit (ruff F/B/E9 + inspection). Triaged 147
  findings: the 30 B023 and 7 F821 are all false positives (helpers invoked in-iteration;
  quoted annotations). Three real items fixed: `EventRef(None)` truthiness — a contract
  break I had introduced earlier; a measured QThread leak (12 finished column workers
  still parented, each pinning its input dataset) fixed with deleteLater plus a
  reap-tolerant `_thread_running()`; and `strict=True` on four `zip()` sites where a
  mismatch would silently drop columns from a written artifact. Left documented and
  unfixed: the same leak in three lower-frequency dialog workers. 24 suites, 400/400.
- **2026-08-23 (cont. 6)** — Fixed the three remaining leaked dialog workers after being
  challenged on why they were left; doing so revealed the first two fixes were wrong
  (`finished` is shadowed, so deleteLater never fired on error paths — 0 of 10) and that
  `processEvents()` does not deliver DeferredDelete, which had made the correct fix look
  broken. Replaced with liveness-based reaping. Corrected the record:
  `_JMSessionFetchWorker` never leaked (unparented). Then a fresh audit of timestamp
  handling found filter/display disagreeing by an hour across DST in `local` mode —
  evidence on the wrong day — fixed in all three sites and the date-grouping SQL now uses
  AT TIME ZONE. 26 suites, 415/415.
- **2026-08-23 (cont. 7)** — Export audit (fresh area: the artifact handed to third
  parties). HTML `_esc` did not escape the apostrophe while every attribute uses single
  quotes — a hostname injected 2 live handlers AND `O'Brien-PC` was silently truncated to
  `PC`. XML broke two ways on control bytes: lxml raised uncaught, stdlib wrote a file
  that will not parse. Both fixed; illegal codepoints now render as a visible reversible
  `\xNN` escape rather than being dropped. JSON/CSV verified sound. CSV formula injection
  flagged as the author's call, not silently changed. 27 suites, 431/431.
- **2026-08-23 (cont. 8)** — Analysis-subsystem audit. `_ts_delta()` is absolute, and two
  correlation rules used it without an ordering test, so they chained a PowerShell block
  and a privilege assignment that occurred BEFORE the events they were attributed to —
  fabricated causal links, the same class as the RDP pairing defect. Both fixed with
  `_ts_ge`, with the forward case asserted so the fix cannot silence a real detection.
  Correlator host scoping, the IOC scorer and TLD-allowlist extraction all verified sound.
  28 suites, 437/437.
- **2026-08-23 (cont. 9)** — Pre-merge: removed 17 hardcoded `/mnt/NewVolume/...` corpus
  paths from `tests/`, replaced with `EVTX_TEST_LOGS` / `EVTX_TEST_WORKDIR` env vars that
  fall back to `sample_logs/` and skip cleanly. Two reasons: `main` is a PUBLIC default
  branch (the same redaction was done before the 2026-08-11 push), and the suites could
  not be run by anyone who cloned the repo. No local paths remain in any tracked file.

