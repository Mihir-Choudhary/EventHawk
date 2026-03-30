"""
Offline Tree Edit Distance (TED) forensic analysis — Zhang-Shasha algorithm.

NOT used in the real-time scoring pipeline.  Used as an optional appendix in
post-incident reports: given two full session process trees (baseline day vs
incident day), compute the structural edit distance and produce a human-readable
diff.

Complexity: O(n² × m) where n, m are tree sizes.
Only suitable for whole-session offline comparison.

Implementation note: uses the proper Zhang-Shasha leftmost-leaf-descendant
algorithm with parent pointers derived from the post-order traversal, rather
than the simplified identity approximation that was previously in place.

B4: _postorder is now iterative (explicit stack) to handle deep trees (>1000
    nodes) without hitting Python's default recursion limit.
B6: build_process_tree keys nodes by (pid, timestamp) to handle PID recycling.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProcessTree:
    """A rooted ordered process tree node."""
    name: str
    pid: int = 0
    children: list["ProcessTree"] = field(default_factory=list)


@dataclass
class TEDResult:
    edit_distance: int
    operations: list[tuple[str, str]]   # (op_type, node_name)
    baseline_size: int
    target_size: int


def session_ted(baseline_tree: ProcessTree, target_tree: ProcessTree) -> TEDResult:
    """
    Compute the Zhang-Shasha Tree Edit Distance between two process trees.

    Returns a TEDResult with the edit distance and list of edit operations.
    Used in the forensic report appendix for Tier 3-4 hosts.
    """
    b_nodes = _flatten(baseline_tree)
    t_nodes = _flatten(target_tree)

    n = len(b_nodes)
    m = len(t_nodes)

    # Build leftmost leaf descendant tables using proper parent-pointer walk
    b_lld = _leftmost_leaf(b_nodes)
    t_lld = _leftmost_leaf(t_nodes)

    b_kr = _keyroots(b_nodes, b_lld)
    t_kr = _keyroots(t_nodes, t_lld)

    # TD[i][j] = edit distance between subtree rooted at b_nodes[i] and t_nodes[j]
    td: list[list[int]] = [[0] * (m + 1) for _ in range(n + 1)]

    ops: list[tuple[str, str]] = []

    for i in b_kr:
        for j in t_kr:
            fd: list[list[int]] = [
                [0] * (j - t_lld[j] + 2) for _ in range(i - b_lld[i] + 2)
            ]
            for i2 in range(b_lld[i], i + 1):
                fd[i2 - b_lld[i] + 1][0] = fd[i2 - b_lld[i]][0] + 1  # delete
            for j2 in range(t_lld[j], j + 1):
                fd[0][j2 - t_lld[j] + 1] = fd[0][j2 - t_lld[j]] + 1  # insert

            for i2 in range(b_lld[i], i + 1):
                for j2 in range(t_lld[j], j + 1):
                    if b_lld[i2] == b_lld[i] and t_lld[j2] == t_lld[j]:
                        rename_cost = 0 if b_nodes[i2].name == t_nodes[j2].name else 1
                        fd[i2 - b_lld[i] + 1][j2 - t_lld[j] + 1] = min(
                            fd[i2 - b_lld[i]][j2 - t_lld[j] + 1] + 1,   # delete
                            fd[i2 - b_lld[i] + 1][j2 - t_lld[j]] + 1,   # insert
                            fd[i2 - b_lld[i]][j2 - t_lld[j]] + rename_cost,
                        )
                        td[i2][j2] = fd[i2 - b_lld[i] + 1][j2 - t_lld[j] + 1]
                    else:
                        fd[i2 - b_lld[i] + 1][j2 - t_lld[j] + 1] = min(
                            fd[i2 - b_lld[i]][j2 - t_lld[j] + 1] + 1,
                            fd[i2 - b_lld[i] + 1][j2 - t_lld[j]] + 1,
                            td[i2][j2] + fd[i2 - b_lld[i] + 1 - (i2 - b_lld[i2] + 1)]
                                           [j2 - t_lld[j] + 1 - (j2 - t_lld[j2] + 1)],
                        )

    edit_distance = td[n - 1][m - 1] if n > 0 and m > 0 else max(n, m)

    # Build a simple diff of node names for the report
    b_names = {nd.name for nd in b_nodes}
    t_names = {nd.name for nd in t_nodes}
    for name in b_names - t_names:
        ops.append(("delete", name))
    for name in t_names - b_names:
        ops.append(("insert", name))

    return TEDResult(
        edit_distance=edit_distance,
        operations=ops,
        baseline_size=n,
        target_size=m,
    )


def build_process_tree(events: list) -> ProcessTree:
    """
    Build a ProcessTree from a list of RawEvent (process_create only).
    Uses pid/ppid for structure.

    B6: PID recycling — Windows reuses PIDs.  We key each node by
    (pid, timestamp) so that two processes with the same PID are treated
    as distinct nodes.  The parent lookup still uses plain pid; if ppid
    has been recycled we fall back to the synthetic root.
    """
    # Map (pid, ts_iso) → ProcessTree node; plain pid → most recent node
    nodes_by_key: dict[tuple[int, str], ProcessTree] = {}
    latest_by_pid: dict[int, ProcessTree] = {}  # pid → most recently created
    root = ProcessTree(name="[root]", pid=0)
    latest_by_pid[0] = root

    for ev in sorted(events, key=lambda e: e.timestamp):
        if ev.event_id not in (4688, 1):
            continue
        ts_key = ev.timestamp.isoformat() if ev.timestamp else ""
        node = ProcessTree(name=ev.process_name, pid=ev.pid)
        nodes_by_key[(ev.pid, ts_key)] = node
        # Parent: use the most recent node with ppid (handles recycling)
        parent = latest_by_pid.get(ev.ppid, root)
        parent.children.append(node)
        # Update latest_by_pid so future children link to this node
        latest_by_pid[ev.pid] = node

    return root


# ── Internal helpers ───────────────────────────────────────────────────────────

def _flatten(tree: ProcessTree) -> list[ProcessTree]:
    """Post-order flattening — iterative (B4: avoids RecursionError on deep trees).

    B22: Standard two-stack post-order: push children in NATURAL (left→right)
    order so the rightmost is on top of stack → popped first into visit_stack →
    reversed at the end → correct left-to-right post-order.
    """
    result: list[ProcessTree] = []
    # Iterative post-order using two-stack approach
    stack: list[ProcessTree] = [tree]
    visit_stack: list[ProcessTree] = []
    while stack:
        node = stack.pop()
        visit_stack.append(node)
        stack.extend(node.children)  # B22: natural order, NOT reversed
    while visit_stack:
        result.append(visit_stack.pop())
    return result


def _build_parent_map(nodes: list[ProcessTree]) -> list[int]:
    """Build a parent index array from a post-order node list.

    For each node at index i, parent_map[i] is the index of its parent in the
    post-order list, or -1 if it is the root.

    In post-order traversal: a node's parent appears after all of its
    descendants.  We reconstruct the parent relationship by tracking which
    post-order index corresponds to each ProcessTree object.
    """
    obj_to_idx: dict[int, int] = {id(nd): i for i, nd in enumerate(nodes)}
    parent_map: list[int] = [-1] * len(nodes)
    for i, node in enumerate(nodes):
        for child in node.children:
            child_idx = obj_to_idx.get(id(child), -1)
            if child_idx >= 0:
                parent_map[child_idx] = i
    return parent_map


def _leftmost_leaf(nodes: list[ProcessTree]) -> list[int]:
    """Compute the leftmost leaf descendant index for each node (post-order list).

    Uses parent pointers derived from the actual tree structure — this is the
    correct Zhang-Shasha implementation rather than the simplified identity
    approximation.
    """
    n = len(nodes)
    if n == 0:
        return []

    parent_map = _build_parent_map(nodes)

    # For leaves, leftmost leaf = self.  For internal nodes, it is the
    # leftmost leaf of the leftmost child.
    # In post-order: process nodes left-to-right and propagate upward.
    lld = list(range(n))  # start: each node is its own leftmost leaf

    for i in range(n):
        p = parent_map[i]
        if p >= 0:
            # If lld[p] hasn't been set to a child yet (still pointing to p itself),
            # inherit from the first (leftmost) child processed.
            if lld[p] == p:
                lld[p] = lld[i]

    return lld


def _keyroots(nodes: list[ProcessTree], lld: list[int]) -> list[int]:
    """Keyroots: nodes that have a unique leftmost leaf descendant."""
    seen: set[int] = set()
    kr: list[int] = []
    for i in reversed(range(len(nodes))):
        if lld[i] not in seen:
            seen.add(lld[i])
            kr.append(i)
    return sorted(kr)
