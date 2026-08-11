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

Eight harnesses totalling **159 checks green** lived in the session scratchpad under
`/tmp/claude-1000/.../scratchpad/` and were **wiped by the environment**. All code work was
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
  fabricated-duration defect open and 5 commits unpushed on `beta`.**
