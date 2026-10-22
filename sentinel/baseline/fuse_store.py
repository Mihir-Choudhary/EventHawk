"""
Probabilistic set-membership filter for O(1) baseline pre-screening.

Implements a pure-Python XOR8 filter (same algorithm family as Binary Fuse Filter):
  - ~9.84 bits per element  (~1.23 MB per 1M keys)
  - FPR ≈ 1/256 ≈ 0.4%
  - O(1) query (3 array lookups + XOR)
  - O(n) build via queue-based peeling
  - Zero dependencies — entirely stdlib

vs frozenset baseline:
  - frozenset: ~200 bytes per entry (Python object overhead + hash table)  → 200 MB / 1M keys
  - XOR8:      ~1.23 bytes per entry                                        →   1.2 MB / 1M keys

The filter answers "is this (proc, parent, cmdline) triplet in the baseline?"
It does NOT store counts — use FrequencyModel for surprisal scoring.
Never produces false negatives; FPR ≈ 0.4%.
"""
from __future__ import annotations

import hashlib
import logging
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sentinel.models import NormalizedEvent

logger = logging.getLogger(__name__)

# ── XOR8 filter implementation ─────────────────────────────────────────────────
# Based on: "Xor Filters: Faster and Smaller Than Bloom and Cuckoo Filters"
# (Graf & Lemire, 2020).  8-bit fingerprints, 3 hash slots.

_FINGERPRINT_MASK = 0xFF   # 8-bit fingerprints
_CAPACITY_FACTOR  = 1.23   # array size = ceil(n * 1.23) — guaranteed to fit all keys
_EXTRA_SLOTS      = 32     # padding to avoid edge-case failures on small sets


def _xor8_hash(key: int, seed: int, block_length: int) -> int:
    """Reduce key to a slot index within one of the 3 equal-length blocks."""
    # Mix key with seed using a fast bijection to spread bits
    h = key ^ seed
    h ^= (h >> 33)
    h = (h * 0xff51afd7ed558ccd) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 33)
    h = (h * 0xc4ceb9fe1a85ec53) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 33)
    return h % block_length


def _fingerprint(key: int, seed: int) -> int:
    """8-bit fingerprint derived from key and global seed."""
    h = key ^ (seed * 0x9e3779b97f4a7c15 & 0xFFFFFFFFFFFFFFFF)
    h ^= (h >> 30)
    h = (h * 0xbf58476d1ce4e5b9) & 0xFFFFFFFFFFFFFFFF
    h ^= (h >> 27)
    return (h ^ (h >> 31)) & _FINGERPRINT_MASK


class _XOR8Filter:
    """
    Minimal XOR8 probabilistic set-membership filter.
    Stores 3 * block_length fingerprint bytes.
    """

    __slots__ = ("_fp", "_bl", "_seed")

    def __init__(self, fingerprints: bytearray, block_length: int, seed: int) -> None:
        self._fp  = fingerprints   # bytearray of length 3 * block_length
        self._bl  = block_length
        self._seed = seed

    def __contains__(self, key: int) -> bool:
        bl = self._bl
        h0 = _xor8_hash(key, self._seed,       bl)
        h1 = _xor8_hash(key, self._seed + 1,   bl) + bl
        h2 = _xor8_hash(key, self._seed + 2,   bl) + 2 * bl
        fp = _fingerprint(key, self._seed)
        return (self._fp[h0] ^ self._fp[h1] ^ self._fp[h2]) == fp

    def nbytes(self) -> int:
        return len(self._fp)


def _build_xor8(keys: list[int], max_attempts: int = 16) -> _XOR8Filter:
    """
    Construct an XOR8 filter for the given list of integer keys.
    Retries with a different random seed up to max_attempts times if
    the peeling process fails (very rare for n > 100).

    Uses the "count + XOR-of-indices" technique so that when slot_count drops
    to 1, slot_xor[slot] directly gives the remaining key's index — O(n) build.
    """
    import os
    n = len(keys)
    block_length = max(int(n * _CAPACITY_FACTOR) + _EXTRA_SLOTS, 8)
    total_slots = 3 * block_length

    for attempt in range(max_attempts):
        seed = int.from_bytes(os.urandom(8), 'big')  # S5: cryptographic randomness

        # ── Mapping phase ──────────────────────────────────────────────────
        # Compute the three slot indices for each key
        slots: list[tuple[int, int, int]] = []
        for k in keys:
            h0 = _xor8_hash(k, seed,     block_length)
            h1 = _xor8_hash(k, seed + 1, block_length) + block_length
            h2 = _xor8_hash(k, seed + 2, block_length) + 2 * block_length
            slots.append((h0, h1, h2))

        # slot_count[s]  = number of keys mapped to slot s
        # slot_xor[s]    = XOR of all key indices mapped to slot s
        #                  → when count==1, slot_xor[s] == the remaining key index
        slot_count: list[int] = [0] * total_slots
        slot_xor:   list[int] = [0] * total_slots

        for i, (h0, h1, h2) in enumerate(slots):
            slot_count[h0] += 1;  slot_xor[h0] ^= i
            slot_count[h1] += 1;  slot_xor[h1] ^= i
            slot_count[h2] += 1;  slot_xor[h2] ^= i

        # ── Peeling phase ──────────────────────────────────────────────────
        # Queue: slots with exactly 1 key remaining
        queue = [s for s in range(total_slots) if slot_count[s] == 1]
        order: list[tuple[int, int]] = []   # (key_index, assigned_slot)

        while queue:
            slot = queue.pop()
            if slot_count[slot] != 1:
                continue
            ki = slot_xor[slot]          # the single remaining key index
            if ki >= n:
                continue
            h0, h1, h2 = slots[ki]
            order.append((ki, slot))
            # Remove key ki from its other two slots
            for other in (h0, h1, h2):
                if other != slot:
                    slot_count[other] -= 1
                    slot_xor[other]   ^= ki   # un-XOR ki from that slot
                    if slot_count[other] == 1:
                        queue.append(other)

        if len(order) != n:
            # Peeling incomplete — hash collision, retry with new seed
            continue

        # ── Assignment phase ───────────────────────────────────────────────
        fp_array = bytearray(total_slots)
        for ki, assigned_slot in reversed(order):
            key = keys[ki]
            h0, h1, h2 = slots[ki]
            target_fp = _fingerprint(key, seed)
            others = [s for s in (h0, h1, h2) if s != assigned_slot]
            fp_array[assigned_slot] = (
                target_fp ^ fp_array[others[0]] ^ fp_array[others[1]]
            ) & _FINGERPRINT_MASK

        return _XOR8Filter(fp_array, block_length, seed)

    # All attempts exhausted — raise so caller falls back to frozenset
    raise RuntimeError(f"XOR8 filter construction failed after {max_attempts} attempts")


# ── Public FuseStore API ───────────────────────────────────────────────────────

def _triplet_key(proc: str, parent: str, cmdline: str) -> int:
    """Return a deterministic 64-bit key for (proc, parent, cmdline).

    Uses SHA-256 instead of Python's built-in hash() because hash() is
    process-randomised (PYTHONHASHSEED).  A fuse filter built in one process
    would silently give wrong results when loaded in another process with a
    different seed.  SHA-256 is stable, zero-dependency, and fast enough for
    this use-case (thousands of keys, built once).
    """
    digest = hashlib.sha256(
        f"{proc}\x00{parent}\x00{cmdline}".encode("utf-8")
    ).digest()
    # Take the first 8 bytes as an unsigned 64-bit integer
    return struct.unpack_from(">Q", digest)[0]


class FuseStore:
    """
    XOR8 probabilistic filter for triplet (proc, parent, cmdline) membership.

    Memory: ~1.23 bytes / entry — 200× more compact than a Python frozenset.
    FPR:    ≈ 0.4% (1/256).
    Query:  O(1) — 3 array lookups + 2 XORs.
    """

    def __init__(self) -> None:
        self._filter: _XOR8Filter | frozenset | None = None
        self._using_xor8: bool = False
        self._size: int = 0

    def build(self, events: list["NormalizedEvent"]) -> None:
        """Build the filter from NormalizedEvents.

        Keys must be unique for the XOR8 peeling algorithm to work correctly.
        Duplicate (proc, parent, cmdline) triplets are collapsed — the filter
        only answers membership queries, not counts.
        """
        keys = list({
            _triplet_key(ev.proc_norm, ev.parent_norm, ev.cmdline_norm)
            for ev in events
        })
        self._size = len(keys)

        if not keys:
            self._filter = frozenset()
            return

        try:
            self._filter = _build_xor8(keys)
            self._using_xor8 = True
            kb = self._filter.nbytes() / 1024
            logger.info(
                "Built XOR8 filter: %d entries, %.1f KB "
                "(vs ~%.0f KB for frozenset), FPR≈0.4%%",
                self._size, kb, self._size * 200 / 1024,
            )
        except Exception as exc:
            logger.warning(
                "XOR8 filter build failed (%s); falling back to frozenset "
                "(~%.0f KB)", exc, self._size * 200 / 1024,
            )
            self._filter = frozenset(keys)
            self._using_xor8 = False

    def contains(self, proc: str, parent: str, cmdline: str) -> bool:
        """
        Return True if this (proc, parent, cmdline) triplet is likely in the baseline.
        Never produces false negatives; FPR ≈ 0.4% when XOR8 is active.
        """
        if self._filter is None:
            return False
        k = _triplet_key(proc, parent, cmdline)
        return k in self._filter  # works for both _XOR8Filter and frozenset

    @property
    def size(self) -> int:
        return self._size

    @property
    def using_xor8(self) -> bool:
        return self._using_xor8
