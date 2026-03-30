# Performance & Scale

## What This Covers

Architectural characteristics, memory behaviour, and known scale limits for all EventHawk components. Figures marked **[architectural]** are derived from the design — not from a formal benchmark run. Run `py -3 evtx_tool.py benchmark C:\Logs` on your own hardware for measured throughput.

---

## Normal Mode — How Performance Scales

Normal Mode uses a `ProcessPoolExecutor` with `CPU count − 1` workers by default. Each worker handles one `.evtx` file at a time using the Rust-backed `pyevtx-rs` parser.

**What drives speed:**
- Worker count — more cores = more files parsed in parallel
- Disk read speed — at high worker counts, I/O becomes the bottleneck ahead of CPU
- Profile filter — a tight event ID filter reduces the data returned per worker

**Built-in throttle:** A resource monitor daemon watches CPU and RAM. If CPU exceeds 85% it throttles the worker queue via a semaphore to prevent the system from becoming unresponsive. You will see this as a brief slowdown when parsing very large files on heavily loaded machines.

**Memory:** Grows roughly linearly with matched event count. If your dataset pushes past what comfortably fits in RAM, switch to Juggernaut Mode.

---

## Juggernaut Mode — Memory Architecture

JM is designed around one principle: **never load `event_data_json` into RAM**.

Raw event XML blobs average ~500 bytes per event. At 6 million events that is ~3 GB just for the XML. JM excludes this column from the Arrow table entirely — it stays in Parquet shards on disk and is fetched with a per-row DuckDB query only when you click a row (<20 ms on SSD, cached in LRU for repeat clicks).

What IS loaded into the Arrow table:

| Column group | Encoding | Why |
|---|---|---|
| `event_id`, `level`, `task`, `opcode`, etc. | int32 / int8 | Tiny, numeric |
| `level_name`, `channel`, `provider`, `computer`, `user_id`, `source_file` | Dictionary-encoded string | Low cardinality — 9× compression vs plain string |
| `timestamp_utc` | Plain string (19 chars) | ISO-8601 truncated to second precision |
| Extracted fields (`ed_subject_user`, `ed_ip_address`, etc.) | Plain string | Pre-extracted from XML at parse time |

**Result:** the Arrow table is compact relative to full event data. All scrolling is zero-I/O — the visible window is served from a 500-row slice of the in-memory table.

---

## Juggernaut Mode — Filter Behaviour

Filters run on a single background DuckDB thread registered against the full Arrow table. The thread processes only the latest queued request — rapid filter changes (e.g. fast typing in the search box) discard stale intermediate requests automatically.

**Text search** that includes `event_data_json` runs in two phases:
1. Arrow table filter (in-memory, fast) narrows the candidate row set.
2. Parquet scan applies full-text search only over that reduced set.

This avoids scanning all Parquet shards for every keypress.

---

## Juggernaut Mode — Scroll

Scrolling reads from the Arrow table via `.slice(start, count).to_pydict()` — a zero-copy O(1) operation with no I/O at any position in the dataset. The 500-row visible cache amortises the Python/C++ boundary call overhead per cell.

---

## Disk Usage (Parquet Shards)

Parquet shards use snappy compression. Typical ratio vs raw EVTX:

| Raw EVTX size | Approx. Parquet shard size |
|---|---|
| 1 GB | ~400 MB |
| 5 GB | ~2 GB |
| 10 GB | ~4 GB |

Shards are written to `%TEMP%\eventhawk_jm_<session_id>\` and cleaned up at the start of the next parse. If EventHawk crashes mid-parse, stale shards may remain — delete the `eventhawk_jm_*` folder from your temp directory manually.

---

## Juggernaut Mode — Event Detail Click

| Scenario | Expected latency |
|---|---|
| First click on a row (SSD) | < 20 ms [architectural] |
| First click on a row (HDD) | 100–300 ms [architectural] |
| Repeat click (LRU cache hit) | Instant — no disk access |

The LRU cache holds the last 100 clicked rows in memory.

---

## Scale Limits

| Limit | Value | Notes |
|---|---|---|
| Normal Mode max events | RAM-dependent | ~650 MB at 1M events on test hardware |
| Juggernaut Mode max events | No hard limit — shard-based | Confirmed working at 10M+ events |
| EVTX files per parse | No limit | Confirmed working with 200+ files |
| Parquet shard size | 50K rows fixed | More events = more shards, not larger shards |
| Column filter popup distinct values | 1,000 max | Truncated above this |
| Sentinel baseline corpus | No hard limit | Single-threaded; scales linearly with event count |

---

## Sentinel — Architecture Notes

Sentinel analysis is intentionally single-threaded. Events must be processed in chronological order for the lineage tracker to correctly resolve parent PIDs across reboots and recycled PIDs. Parallelising this would require per-host queues and coordination overhead that outweighs the benefit for typical investigation corpus sizes.

The baseline build phases (parse → stability → sigma → normalize → freq → trie → fuse → persist) are also single-threaded except the initial parse step, which uses the same multi-process engine as EventHawk.

---

## Tips for Best Performance

**Normal Mode:**
- Match `--workers` to your physical core count (not logical/hyperthreaded).
- Put EVTX files on the fastest drive available — at high worker counts, file read speed is the bottleneck.
- Use a profile to filter at parse time — fewer matched events = less RAM and faster analysis.

**Juggernaut Mode:**
- Ensure the temp drive has free space of at least 50% of your total EVTX size.
- The first DuckDB filter after load has a short warm-up (~200 ms). Subsequent filters are at steady-state speed.
- For very large corpora (10M+), allow 3–5 minutes total for parse + load before the table appears.

**Sentinel:**
- The richer the baseline corpus (more days, more process diversity), the lower the false-positive rate.
- Using `--sigma` adds pre-tagging time at startup but improves justification quality in the report.

---

## Related Docs

- [Normal Mode](03-normal-mode.md)
- [Juggernaut Mode](04-juggernaut-mode.md)
- [Sentinel — Overview](15-sentinel-overview.md)
- [CLI Mode — benchmark command](12-cli.md)
