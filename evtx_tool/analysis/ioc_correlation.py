"""
IOC Co-occurrence Correlation.

Builds approximate co-occurrence relationships between IOC entries by finding
which entries share the same user/computer context.  Since individual event
row-indices are not stored in IOCEntry (too memory-heavy), correlation is
based on the sets of (user, computer) pairs that appear alongside each IOC.

Public API
----------
correlate_iocs(iocs: dict) -> dict
    Returns {"pairs": [...top-100 pairs...]}
    Each pair: {type_a, value_a, type_b, value_b, shared_context, confidence}
"""

from __future__ import annotations

from itertools import combinations

# IOC types to include in correlation analysis (skip meta keys)
_SKIP_KEYS = frozenset({"summary", "correlation"})

# Cap to avoid O(N²) explosion on very large IOC sets per type
_MAX_PER_TYPE = 500


def correlate_iocs(iocs: dict) -> dict:
    """
    Build co-occurrence pairs from shared user/computer context across IOC entries.

    Parameters
    ----------
    iocs : dict
        The IOC dict from ioc_extractor (list[IOCEntry] per type key).

    Returns
    -------
    dict with key "pairs": list of correlation pair dicts, sorted by
    shared_context descending, capped at 100 entries.
    """
    # Step 1: Build a flat list of (type, value, context_frozenset)
    # context = frozenset of (user, computer) tuples that co-occurred with this IOC
    flat: list[tuple[str, str, frozenset]] = []

    for ioc_type, entries in iocs.items():
        if ioc_type in _SKIP_KEYS or not isinstance(entries, list):
            continue
        for entry in entries[:_MAX_PER_TYPE]:
            if not isinstance(entry, dict):
                continue
            value = entry.get("value", "")
            if not value:
                continue
            users = entry.get("users")
            if not isinstance(users, list):
                users = []
            computers = entry.get("computers")
            if not isinstance(computers, list):
                computers = []

            # Build context set: pairs of (user, computer)
            # If one list is empty, use a placeholder
            ctx_pairs: set[tuple[str, str]] = set()
            if users and computers:
                for u in users:
                    for c in computers:
                        ctx_pairs.add((u, c))
            elif users:
                for u in users:
                    ctx_pairs.add((u, ""))
            elif computers:
                for c in computers:
                    ctx_pairs.add(("", c))

            if ctx_pairs:
                flat.append((ioc_type, value, frozenset(ctx_pairs)))

    if len(flat) < 2:
        return {"pairs": []}

    # Step 2: Find all pairs with non-empty intersection
    # Guard against extreme combinatorial explosion
    MAX_FLAT = 2000
    if len(flat) > MAX_FLAT:
        flat = flat[:MAX_FLAT]

    pairs: list[dict] = []

    for (type_a, val_a, ctx_a), (type_b, val_b, ctx_b) in combinations(flat, 2):
        # Skip same type + same value
        if type_a == type_b and val_a == val_b:
            continue

        shared = ctx_a & ctx_b
        if not shared:
            continue

        n = len(shared)
        if n > 10:
            confidence = "high"
        elif n >= 5:
            confidence = "medium"
        else:
            confidence = "low"

        pairs.append({
            "type_a":         type_a,
            "value_a":        val_a,
            "type_b":         type_b,
            "value_b":        val_b,
            "shared_context": n,
            "confidence":     confidence,
        })

    # Step 3: Sort by shared_context descending, keep top 100
    pairs.sort(key=lambda p: p["shared_context"], reverse=True)
    pairs = pairs[:100]

    return {"pairs": pairs}
