"""
HeavyweightEngine — parse EVTX files into Parquet shards, then load into
an in-memory Arrow table for instant O(1) scroll access (Architecture 1).

Architecture:

Parse Phase — streaming EVTX → Parquet shards
  • ThreadPoolExecutor: GIL-free Rust parsing via pyevtx-rs
  • Large files split at 65 536-byte EVTX chunk boundaries
  • Streaming producer→consumer queue: parse overlaps Parquet write
  • Per-worker Parquet files (zstd, zone maps, dictionary encoding)
  • parquet_manifest.json lists shard paths for load_arrow_table()

Load Phase — load_arrow_table()
  • Reads all shards into a single in-memory pa.Table (~114 MB for 6M rows)
  • Excludes event_data_json (lazy-loaded on row selection from Parquet)
  • Dictionary-encodes 6 low-cardinality string columns (9× memory reduction)
  • Adds 0-based row_id column for display row numbers

Query Phase — ArrowTableModel + _FilterThread
  • data() reads directly from Arrow buffers: O(1), zero I/O
  • Single background QThread runs DuckDB SQL on the Arrow table for filters
  • No concurrent workers, no file locks, no OOM from simultaneous allocations
"""

from __future__ import annotations

import atexit
import binascii
import io
import itertools
import logging
import os
import queue
import shutil
import struct
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

import orjson

logger = logging.getLogger(__name__)

# ── Column order (22 non-PK columns, matches Arrow schema) ───────────────────
_COL_NAMES = (
    "record_id", "event_id", "level", "level_name", "timestamp_utc",
    "channel", "provider", "computer", "user_id", "keywords",
    "correlation_id", "source_file", "task", "opcode",
    "process_id", "thread_id",
    "ed_subject_user", "ed_target_user", "ed_ip_address",
    "ed_logon_type", "ed_new_process", "event_data_json",
)

# ── Arrow schema (imported lazily to avoid hard dep at import time) ───────────
def _make_schema():
    import pyarrow as pa
    return pa.schema([
        ("record_id",       pa.int64()),
        ("event_id",        pa.int32()),
        ("level",           pa.int8()),
        ("level_name",      pa.string()),
        ("timestamp_utc",   pa.string()),   # stored as ISO-8601 text; DuckDB casts on query
        ("channel",         pa.string()),
        ("provider",        pa.string()),
        ("computer",        pa.string()),
        ("user_id",         pa.string()),
        ("keywords",        pa.string()),
        ("correlation_id",  pa.string()),
        ("source_file",     pa.string()),
        ("task",            pa.int32()),
        ("opcode",          pa.int32()),
        ("process_id",      pa.int32()),
        ("thread_id",       pa.int32()),
        ("ed_subject_user", pa.string()),
        ("ed_target_user",  pa.string()),
        ("ed_ip_address",   pa.string()),
        ("ed_logon_type",   pa.string()),
        ("ed_new_process",  pa.string()),
        ("event_data_json", pa.string()),
    ])


# Search text SQL expression — shared between the VIEW and the persistent TABLE.
# Keeping one definition prevents the two from drifting apart.
_SEARCH_TEXT_EXPR = (
    "lower("
    "CAST(event_id AS VARCHAR) || ' ' || "
    "COALESCE(level_name, '') || ' ' || "
    "COALESCE(channel, '') || ' ' || "
    "COALESCE(provider, '') || ' ' || "
    "COALESCE(computer, '') || ' ' || "
    "COALESCE(user_id, '') || ' ' || "
    "COALESCE(source_file, '') || ' ' || "
    "COALESCE(event_data_json, '')"
    ")"
)

BATCH_SIZE         = 50_000   # rows accumulated in consumer before one Parquet write (controls shard size)
_WORKER_PUSH_SIZE  =  5_000   # rows per queue message from each worker (controls in-flight RAM)

_LEVEL_MAP = {0: "LogAlways", 1: "Critical", 2: "Error", 3: "Warning",
              4: "Information", 5: "Verbose"}

# ── Tier 5: EVTX file-header constants ───────────────────────────────────────
_EVTX_FILE_HDR   = 128
_EVTX_CHUNK_SZ   = 65_536
_EVTX_MIN_SPLIT  = 8

_HDR_OLDEST_CHUNK  = 0x08
_HDR_CURRENT_CHUNK = 0x10
_HDR_CHUNK_COUNT   = 0x2A
_HDR_CHECKSUM      = 0x7C


# ── Helpers ───────────────────────────────────────────────────────────────────

def _safe_int(val, default: int = 0) -> int:
    """Convert val to int; handle dict (EventID quirk) and None."""
    if val is None:
        return default
    if isinstance(val, dict):
        return int(val.get("#text", default) or default)
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


# ── Tier 5: GPU detection ─────────────────────────────────────────────────────

def _gpu_log() -> None:
    """Log GPU acceleration status at startup (informational only)."""
    try:
        import cudf  # RAPIDS cuDF  # noqa: F401
        logger.info(
            "GPU: RAPIDS cuDF %s available — JSON/DataFrame ops GPU-accelerated",
            cudf.__version__,
        )
        return
    except ImportError:
        pass

    try:
        import subprocess
        r = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=3,
        )
        if r.returncode == 0 and r.stdout.strip():
            gpu_name = r.stdout.strip().split("\n")[0].strip()
            if os.name == "nt":
                logger.info(
                    "GPU detected: %s — RAPIDS cuDF is Linux-only; "
                    "running CPU-only mode on Windows (Tier 5 threading active)",
                    gpu_name,
                )
            else:
                logger.info(
                    "GPU detected: %s — install RAPIDS cuDF for GPU acceleration: "
                    "pip install cudf-cu12 --extra-index-url=https://pypi.nvidia.com",
                    gpu_name,
                )
            return
    except Exception:
        pass

    logger.info("GPU: not detected — running CPU-only mode")


# ── Tier 5: EVTX chunk splitter ──────────────────────────────────────────────

def _split_evtx(filepath: str, n_parts: int, tmp_dir: str) -> list[str]:
    """
    Split a large EVTX file into *n_parts* sub-files at chunk boundaries.

    Returns a list of sub-file paths, or [filepath] when splitting is not
    worthwhile (too few chunks, or n_parts <= 1, or on any I/O error).
    """
    try:
        size = os.path.getsize(filepath)
        n_chunks = (size - _EVTX_FILE_HDR) // _EVTX_CHUNK_SZ
        if n_chunks < _EVTX_MIN_SPLIT or n_parts <= 1:
            return [filepath]

        per = max(1, n_chunks // n_parts)
        sub_files: list[str] = []

        with open(filepath, "rb") as src:
            orig_hdr = bytearray(src.read(_EVTX_FILE_HDR))

            for i in range(n_parts):
                start  = i * per
                end    = (i + 1) * per if i < n_parts - 1 else n_chunks
                n_this = end - start
                if n_this <= 0:
                    break

                hdr = bytearray(orig_hdr)
                struct.pack_into("<Q", hdr, _HDR_OLDEST_CHUNK,  start)
                struct.pack_into("<Q", hdr, _HDR_CURRENT_CHUNK, start + n_this - 1)
                struct.pack_into("<H", hdr, _HDR_CHUNK_COUNT,   n_this)
                crc = binascii.crc32(bytes(hdr[:120])) & 0xFFFFFFFF
                struct.pack_into("<I", hdr, _HDR_CHECKSUM, crc)

                tmp_path = os.path.join(tmp_dir, f"_hw_split_{i}_{os.getpid()}.evtx")
                with open(tmp_path, "wb") as dst:
                    dst.write(hdr)
                    src.seek(_EVTX_FILE_HDR + start * _EVTX_CHUNK_SZ)
                    dst.write(src.read(n_this * _EVTX_CHUNK_SZ))

                sub_files.append(tmp_path)

        logger.info(
            "Split %s (%d chunks) → %d sub-files for parallel parsing",
            os.path.basename(filepath), n_chunks, len(sub_files),
        )
        return sub_files or [filepath]

    except Exception as exc:
        logger.warning(
            "_split_evtx failed for %s (%s) — using original file",
            filepath, exc,
        )
        return [filepath]


# ── Tier 4: Fused extract-filter-convert ─────────────────────────────────────

def _extract_and_filter(parsed: dict, source_file: str, _passes) -> tuple | None:
    """
    Single-pass extract → filter → row-tuple conversion.

    Returns None if filtered out or on parse error.
    """
    try:
        event  = parsed.get("Event", parsed)
        system = event.get("System") or {}
        ed_raw = event.get("EventData") or event.get("UserData") or {}

        # ── Flatten EventData ONCE ────────────────────────────────────────────
        ed_was_flat = True
        flat_ed: dict = {}
        if isinstance(ed_raw, dict):
            for k, v in ed_raw.items():
                if isinstance(v, dict):
                    flat_ed.update(v)
                    ed_was_flat = False
                else:
                    flat_ed[k] = v

        # ── Extract shared fields ONCE ────────────────────────────────────────
        eid      = _safe_int(system.get("EventID", 0))
        level    = _safe_int(system.get("Level"), 4)
        channel  = str(system.get("Channel", "") or "")
        computer = str(system.get("Computer", "") or "")
        task_val = _safe_int(system.get("Task"))

        tc = system.get("TimeCreated") or {}
        if isinstance(tc, dict):
            ts_str = (tc.get("#attributes") or {}).get("SystemTime", "") or tc.get("SystemTime", "")
        else:
            ts_str = str(tc)

        prov = system.get("Provider") or {}
        if isinstance(prov, dict):
            provider_name = (prov.get("#attributes") or {}).get("Name", "") or prov.get("Name", "")
        else:
            provider_name = str(prov)

        # ── Pre-filter (reuse already-extracted values) ───────────────────────
        if _passes is not None:
            filter_dict = {
                "event_id":   eid,
                "level":      level,
                "channel":    channel,
                "provider":   provider_name,
                "computer":   computer,
                "user_id":    "",
                "task":       task_val,
                "timestamp":  ts_str,
                "event_data": flat_ed,
            }
            if not _passes(filter_dict):
                return None

        # ── Full row tuple (only for accepted events) ─────────────────────────
        ts_db      = ts_str.replace("T", " ").replace("Z", "")[:19] if ts_str else "1970-01-01 00:00:00"
        level_name = _LEVEL_MAP.get(level, "Information")
        record_id  = _safe_int(system.get("EventRecordID"))
        keywords   = str(system.get("Keywords", "") or "")
        opcode_val = _safe_int(system.get("Opcode"))

        sec     = system.get("Security") or {}
        user_id = ""
        if isinstance(sec, dict):
            user_id = (sec.get("#attributes") or {}).get("UserID", "") or sec.get("UserID", "")

        exe = system.get("Execution") or {}
        if isinstance(exe, dict):
            attrs = exe.get("#attributes") or exe
            pid   = _safe_int(attrs.get("ProcessID"))
            tid   = _safe_int(attrs.get("ThreadID"))
        else:
            pid, tid = 0, 0

        corr    = system.get("Correlation") or {}
        corr_id = ""
        if isinstance(corr, dict):
            corr_id = (corr.get("#attributes") or {}).get("ActivityID", "") or corr.get("ActivityID", "")

        if flat_ed:
            ed_json = orjson.dumps(ed_raw if ed_was_flat else flat_ed).decode()
        else:
            ed_json = None

        return (
            record_id, eid, level, level_name, ts_db,
            channel, provider_name, computer, user_id, keywords,
            corr_id, source_file, task_val, opcode_val,
            pid, tid,
            str(flat_ed.get("SubjectUserName", "") or ""),
            str(flat_ed.get("TargetUserName",  "") or ""),
            str(flat_ed.get("IpAddress",       "") or ""),
            str(flat_ed.get("LogonType",       "") or ""),
            str(flat_ed.get("NewProcessName",  "") or ""),
            ed_json,
        )
    except Exception as exc:
        logger.debug("_extract_and_filter error: %s", exc)
        return None


# ── Parquet writer helper ─────────────────────────────────────────────────────

def _write_parquet_batch(rows: list[tuple], out_path: str, schema) -> None:
    """Write a list of row tuples to a Parquet file using PyArrow.

    Rows are sorted by *timestamp_utc* (index 5 in _COL_NAMES) before writing.
    Pre-sorted shards let DuckDB perform a cheap O(shards) k-way merge for
    ORDER BY timestamp_utc queries instead of a full O(N log N) sort across
    all rows — eliminating the largest sort spike on the most common column.
    Other ORDER BY columns (event_id, level, computer …) still sort correctly;
    DuckDB re-sorts those, but starts from zone-map-pruned row groups.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    _TS_IDX = 5   # index of timestamp_utc in _COL_NAMES

    # Sort rows by timestamp_utc (None rows go last)
    try:
        rows = sorted(rows, key=lambda r: (r[_TS_IDX] is None, r[_TS_IDX]))
    except Exception:
        pass  # if sort fails (type mismatch) write unsorted — still correct

    # Transpose rows (list of tuples) → column arrays
    n = len(_COL_NAMES)
    cols = [[] for _ in range(n)]
    for row in rows:
        for i, val in enumerate(row):
            cols[i].append(val)

    arrays = []
    for i, field in enumerate(schema):
        try:
            arrays.append(pa.array(cols[i], type=field.type))
        except Exception:
            # Fallback: cast to string for any type that fails
            arrays.append(pa.array([str(v) if v is not None else None for v in cols[i]], type=pa.string()))

    table = pa.table(dict(zip([f.name for f in schema], arrays)), schema=schema)

    pq.write_table(
        table, out_path,
        compression="zstd",
        compression_level=3,
        row_group_size=65_536,  # 64K rows/group — finer zone-map granularity for sorted data
        write_statistics=True,  # enables zone maps (min/max per row-group)
        use_dictionary=True,    # dictionary-encode low-cardinality string cols
    )



# ── Arrow in-memory loader ────────────────────────────────────────────────────

_MANIFEST_FILENAME = "parquet_manifest.json"

# String columns with low cardinality — dictionary-encode for 9× memory savings.
# e.g. "Microsoft-Windows-Security-Auditing" (36 bytes) → 1-byte integer index.
_DICT_COLS = frozenset({
    "level_name", "channel", "provider", "computer", "user_id", "source_file",
})

# Columns loaded into the Arrow table.  event_data_json is intentionally
# excluded — it averages ~500 bytes/row and is lazy-loaded from Parquet on
# row selection (<20 ms on SSD).  The extracted ed_* columns cover all
# commonly-searched event_data fields.
_ARROW_COLS = [
    "record_id", "event_id", "level", "level_name", "timestamp_utc",
    "channel", "provider", "computer", "user_id", "keywords",
    "correlation_id", "source_file", "task", "opcode",
    "process_id", "thread_id",
    "ed_subject_user", "ed_target_user", "ed_ip_address",
    "ed_logon_type", "ed_new_process",
]


def load_arrow_table(parquet_dir: str) -> "pa.Table":
    """
    Read all Parquet shards into a single in-memory Apache Arrow table.

    Memory profile (dictionary-encoded, event_data_json excluded):
      1M rows  ~  19 MB
      6M rows  ~ 114 MB
      9M rows  ~ 171 MB

    The returned table is registered with an in-memory DuckDB connection in
    ArrowTableModel._FilterThread for zero-copy SQL filtering.  Parquet shards
    are kept on disk for lazy event_data_json lookup on row selection.
    """
    import json as _json
    import pyarrow as pa
    import pyarrow.parquet as pq

    manifest_file = os.path.join(parquet_dir, _MANIFEST_FILENAME)
    if not os.path.isfile(manifest_file):
        raise FileNotFoundError(
            f"parquet_manifest.json not found in {parquet_dir!r}. "
            f"Has the engine run yet?"
        )
    with open(manifest_file, "r", encoding="utf-8") as fh:
        parquet_files: list[str] = _json.load(fh)

    if not parquet_files:
        raise ValueError(f"parquet_manifest.json in {parquet_dir!r} lists zero shards.")

    missing = [p for p in parquet_files if not os.path.isfile(p)]
    if missing:
        raise FileNotFoundError(
            f"{len(missing)} shard(s) missing from manifest: {missing[:3]}"
        )

    # Read metadata columns only — event_data_json excluded intentionally.
    # Use pyarrow.dataset to stream shards one-at-a-time instead of loading
    # all N shards into a list then calling concat_tables (which peaks at 2×
    # the unencoded table size, ~3.3 GB for 6M rows).  The dataset scanner
    # reads each file in batches and assembles the result incrementally.
    import pyarrow.dataset as _ds
    dataset = _ds.dataset(parquet_files, format="parquet")
    combined = dataset.to_table(columns=_ARROW_COLS)

    # Apply dictionary encoding to low-cardinality string columns.
    # This reduces the Arrow table from ~1.7 GB (unencoded) to ~830 MB.
    for name in _DICT_COLS:
        if name not in combined.schema.names:
            continue
        idx = combined.schema.get_field_index(name)
        arr = combined.column(idx)
        if pa.types.is_string(arr.type) or pa.types.is_large_string(arr.type):
            combined = combined.set_column(idx, name, arr.dictionary_encode())

    # Add 0-based row_id column used for display row numbers.
    # uint32 is sufficient (max ~4.3B rows) and halves memory vs int64.
    row_id_col = pa.array(range(len(combined)), type=pa.uint32())
    combined = combined.append_column("row_id", row_id_col)

    logger.info(
        "Arrow table loaded: %d rows, %d columns, %.1f MB",
        len(combined),
        combined.num_columns,
        combined.nbytes / 1024 / 1024,
    )
    return combined



# ── Tier 5: Streaming worker ──────────────────────────────────────────────────

def _hw_worker_stream(
    task: dict,
    out_queue: "queue.Queue[tuple]",
    stop_event: threading.Event,
) -> None:
    """
    Parse one EVTX (sub-)file and push tuple batches to *out_queue*.

    Queue message protocol:
      ("TUPLES", src_basename, list_of_row_tuples)  — parsed rows
      ("DONE",   src_basename, None)                — sentinel: worker done
    """
    from evtx import PyEvtxParser          # type: ignore[import]
    from evtx_tool.core.filters import compile_filter

    fpath = task["filepath"]
    src   = os.path.basename(fpath)

    _passes = None
    if task.get("filter_config"):
        try:
            _passes = compile_filter(task["filter_config"])
        except Exception as exc:
            logger.warning("compile_filter failed for %s: %s — proceeding unfiltered", src, exc)

    try:
        parser = PyEvtxParser(fpath)
    except Exception as exc:
        logger.warning("Cannot open EVTX %s: %s", fpath, exc)
        out_queue.put(("DONE", src, None))
        return

    # ── Diagnostic counters ───────────────────────────────────────────────
    n_iterated       = 0
    n_json_errors    = 0
    n_extract_nones  = 0
    n_rows           = 0
    first_json_err   = None
    first_extract_err = None

    rows: list[tuple] = []
    try:
        for record in parser.records_json():
            if stop_event.is_set():
                break
            n_iterated += 1

            try:
                parsed = orjson.loads(record["data"])
            except Exception as exc:
                n_json_errors += 1
                if first_json_err is None:
                    first_json_err = str(exc)
                    logger.warning(
                        "[%s] First JSON parse error (record #%d): %s — data[:200]=%s",
                        src, n_iterated, exc, str(record.get("data", ""))[:200],
                    )
                continue

            row = _extract_and_filter(parsed, src, _passes)
            if row is None:
                n_extract_nones += 1
                if first_extract_err is None:
                    top_keys = list(parsed.keys())[:5] if isinstance(parsed, dict) else type(parsed).__name__
                    first_extract_err = f"top_keys={top_keys}"
                    logger.warning(
                        "[%s] First _extract_and_filter returned None (record #%d): %s",
                        src, n_iterated, first_extract_err,
                    )
                continue

            rows.append(row)
            n_rows += 1

            if len(rows) >= _WORKER_PUSH_SIZE:
                out_queue.put(("TUPLES", src, rows))
                rows = []

        # Flush remaining rows
        if rows:
            out_queue.put(("TUPLES", src, rows))

    except Exception as exc:
        logger.warning("Parse error in %s (partial results): %s", src, exc)
    finally:
        del parser   # release Rust file handle immediately; do not rely on GC timing
        log_fn = logger.warning if n_rows == 0 and n_iterated > 0 else logger.info
        log_fn(
            "[%s] Worker summary: iterated=%d, json_errors=%d, "
            "extract_nones=%d, rows_produced=%d",
            src, n_iterated, n_json_errors, n_extract_nones, n_rows,
        )
        out_queue.put(("DONE", src, None))


# ── Engine ────────────────────────────────────────────────────────────────────

ProgressCallback = Callable[[int, int, int, float], None]


class HeavyweightEngine:
    """
    Parse EVTX files into DuckDB over Parquet using streaming threads.

    Blueprint v2 architecture:
      • ThreadPoolExecutor — no spawn overhead, no pickle, GIL-free Rust parsing
      • EVTX files >64 MB split at chunk boundaries for N-way single-file parallelism
      • Streaming queue.Queue producer→consumer: parse overlaps Parquet write
      • Per-worker Parquet files (zstd compressed, zone maps, dictionary encoding)
      • DuckDB registers all Parquet files as a view — no index build needed
      • Returns parquet_dir string — caller opens DuckDB from that directory
    """

    def __init__(
        self,
        parquet_dir: str | None = None,
        on_progress: ProgressCallback | None = None,
    ):
        self._parquet_dir = parquet_dir  # None → auto temp dir
        self._on_progress = on_progress
        self._stop        = threading.Event()
        self._tmp_dir: str | None = None   # temp dir for EVTX chunk splits
        atexit.register(self._atexit_cleanup)

    def stop(self) -> None:
        """Signal all streaming workers to stop at next record boundary."""
        self._stop.set()

    def _atexit_cleanup(self) -> None:
        """Best-effort cleanup of temp chunk dir on unexpected exit."""
        if self._tmp_dir and os.path.isdir(self._tmp_dir):
            try:
                shutil.rmtree(self._tmp_dir, ignore_errors=True)
            except Exception:
                pass

    # ── main entry point ──────────────────────────────────────────────────────

    def run(
        self,
        files: list[str],
        filter_config: dict | None = None,
    ) -> str:
        """
        Parse *files* into Parquet and register with DuckDB.
        Returns the *parquet_dir* path — caller opens DuckDB from it.

        The parquet_dir contains:
          • N .parquet shard files (one per stream worker)
          • evtx_session.duckdb  — DuckDB database file (small; holds the VIEW)
        """
        # Reset stop flag so run() is re-entrant if the engine is reused
        self._stop.clear()

        # Dependency guard
        try:
            from evtx import PyEvtxParser  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "Juggernaut Mode requires pyevtx-rs (pip install evtx).\n"
                "If installed but failing, check for an Evtx/ vs evtx/ case conflict:\n"
                "  pip uninstall evtx python-evtx -y && pip install evtx"
            )

        try:
            import pyarrow  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "Juggernaut Mode requires pyarrow (pip install pyarrow).\n"
                "Install with: pip install pyarrow duckdb"
            )

        try:
            import duckdb  # noqa: F401
        except ImportError:
            raise RuntimeError(
                "Juggernaut Mode requires duckdb (pip install duckdb).\n"
                "Install with: pip install duckdb pyarrow"
            )

        _gpu_log()

        # ── Set up output Parquet directory ───────────────────────────────────
        if self._parquet_dir:
            pq_dir = self._parquet_dir
            os.makedirs(pq_dir, exist_ok=True)
            # Remove stale Parquet shards and manifest from previous runs so
            # os.listdir() at the end only picks up freshly written files.
            for _f in os.listdir(pq_dir):
                if _f.endswith(".parquet") or _f == _MANIFEST_FILENAME:
                    try:
                        os.remove(os.path.join(pq_dir, _f))
                    except OSError:
                        pass
        else:
            pq_dir = tempfile.mkdtemp(prefix="evtx_jm_")

        schema = _make_schema()

        # ── Build task list ───────────────────────────────────────────────────
        cpu       = os.cpu_count() or 4
        n_workers = max(1, min(cpu - 1, 16))
        tmp_dir   = tempfile.mkdtemp(prefix="evtx_hw_")
        self._tmp_dir = tmp_dir

        tmp_sub_files: list[str] = []
        all_tasks:     list[dict] = []

        for fp in files:
            try:
                size_mb = os.path.getsize(fp) / (1024 * 1024)
            except OSError:
                size_mb = 0.0

            if size_mb > 64 and n_workers > 1:
                subs = _split_evtx(fp, n_workers, tmp_dir)
                for s in subs:
                    all_tasks.append({"filepath": s, "filter_config": filter_config})
                    if s != fp:
                        tmp_sub_files.append(s)
            else:
                all_tasks.append({"filepath": fp, "filter_config": filter_config})

        total_tasks    = len(all_tasks)
        actual_workers = max(1, min(n_workers, total_tasks)) if total_tasks > 0 else 1

        logger.info(
            "Juggernaut v2 (DuckDB/Parquet): %d source file(s) → %d task(s) / %d worker thread(s)",
            len(files), total_tasks, actual_workers,
        )

        if total_tasks == 0:
            logger.warning("No EVTX tasks to process — returning empty parquet dir")
            self._tmp_dir = None
            return pq_dir

        # ── Streaming thread pool ─────────────────────────────────────────────
        # maxsize = actual_workers * 2:
        #   each worker can have at most 2 batches of _WORKER_PUSH_SIZE rows buffered.
        #   peak in-flight RAM = actual_workers * 2 * _WORKER_PUSH_SIZE * ~750 B/row
        #   e.g. 8 workers → 80K rows in-flight ≈ ~60 MB (was 3.2M rows / ~2.4 GB with *8/50K)
        out_queue = queue.Queue(maxsize=actual_workers * 2)
        stop_evt  = self._stop

        executor  = ThreadPoolExecutor(max_workers=actual_workers)
        task_iter = iter(all_tasks)

        for task in itertools.islice(task_iter, actual_workers):
            executor.submit(_hw_worker_stream, task, out_queue, stop_evt)

        # ── Consumer loop: drain queue → accumulate → write Parquet ──────────
        # Each worker streams TUPLES into a shared accumulator.  When the
        # accumulator reaches BATCH_SIZE rows we flush to a new Parquet shard.
        # This amortises Parquet write overhead (schema init, compression) across
        # large chunks while keeping memory bounded to ~BATCH_SIZE rows.

        shard_idx    = 0
        accum_rows: list[tuple] = []
        total_events = 0
        done_tasks   = 0
        t0           = time.monotonic()

        def _flush_shard():
            nonlocal shard_idx
            if not accum_rows:
                return
            shard_path = os.path.join(pq_dir, f"shard_{shard_idx:05d}.parquet")
            try:
                _write_parquet_batch(accum_rows, shard_path, schema)
            except Exception as exc:
                logger.warning("Parquet shard write failed (shard %d): %s", shard_idx, exc)
                # Delete the partially-written file so parquet_scan never sees a corrupt shard.
                try:
                    os.remove(shard_path)
                except OSError:
                    pass
            shard_idx += 1
            accum_rows.clear()

        try:
            while done_tasks < total_tasks:
                if stop_evt.is_set():
                    break
                try:
                    kind, src, data = out_queue.get(timeout=1.0)
                except queue.Empty:
                    continue

                if kind == "DONE":
                    done_tasks += 1

                    next_task = next(task_iter, None)
                    if next_task is not None:
                        executor.submit(_hw_worker_stream, next_task, out_queue, stop_evt)

                    elapsed = time.monotonic() - t0
                    eps     = total_events / elapsed if elapsed > 0 else 0.0
                    if self._on_progress:
                        approx_done = max(0, int(done_tasks / total_tasks * len(files)))
                        self._on_progress(approx_done, len(files), total_events, eps)

                elif kind == "TUPLES":
                    accum_rows.extend(data)
                    total_events += len(data)

                    # Flush when accumulator is large enough for a good Parquet shard
                    if len(accum_rows) >= BATCH_SIZE:
                        _flush_shard()

                        elapsed = time.monotonic() - t0
                        eps     = total_events / elapsed if elapsed > 0 else 0.0
                        if self._on_progress:
                            approx_done = max(0, int(done_tasks / total_tasks * len(files)))
                            self._on_progress(approx_done, len(files), total_events, eps)

        finally:
            executor.shutdown(wait=True, cancel_futures=True)

            # ── Cleanup temp sub-files ─────────────────────────────────────────
            for f in tmp_sub_files:
                try:
                    os.unlink(f)
                except Exception:
                    pass
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except Exception:
                pass
            self._tmp_dir = None

        # Flush any remaining rows
        if accum_rows:
            _flush_shard()

        # ── Collect Parquet shard paths ───────────────────────────────────────
        parquet_files = sorted(
            os.path.join(pq_dir, f)
            for f in os.listdir(pq_dir)
            if f.endswith(".parquet")
        )

        elapsed = time.monotonic() - t0
        logger.info(
            "Juggernaut parse complete: %d events / %d files / %.1fs / %.0f ev·s⁻¹ / %d shards",
            total_events, len(files), elapsed,
            total_events / max(elapsed, 0.001),
            len(parquet_files),
        )

        if not parquet_files:
            logger.warning("No Parquet shards written — parquet_dir is empty: %s", pq_dir)
            return pq_dir

        # ── Write parquet manifest (list of shard paths) ─────────────────────
        # load_arrow_table() reads this manifest to find all shards.
        # Shards are kept on disk — they serve as the persistence layer and
        # are used for lazy event_data_json lookup on row selection.
        try:
            import json as _json
            manifest_file = os.path.join(pq_dir, _MANIFEST_FILENAME)
            # Atomic write: write to a temp file then rename so a crash mid-write
            # never leaves a corrupted manifest that load_arrow_table() can't parse.
            tmp_fd, tmp_path = tempfile.mkstemp(dir=pq_dir, suffix=".tmp")
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    _json.dump(parquet_files, f)
                os.replace(tmp_path, manifest_file)
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
            logger.info(
                "Parquet manifest written: %d events across %d shards → %s",
                total_events, len(parquet_files), manifest_file,
            )
        except Exception as exc:
            logger.error("Manifest write failed: %s", exc)

        return pq_dir
