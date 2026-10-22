"""
Ancestry Trie for O(depth) process lineage lookup.

Stores all parent-child ancestry chains observed in the baseline.
Query returns (match_depth, count_at_deepest_match):
  - match_depth == len(chain) → full baseline match
  - match_depth == 0          → process name itself is unseen
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TrieNode:
    children: dict[str, "TrieNode"] = field(default_factory=dict)
    count: int = 0


class AncestryTrie:
    """
    Process ancestry trie.  Chains are stored most-specific-first:
        chain = [proc_name, parent_name, grandparent_name, ...]
    """

    def __init__(self) -> None:
        self.root = TrieNode()
        self._total_insertions: int = 0

    def insert(self, chain: list[str]) -> None:
        """Insert an ancestry chain into the trie."""
        node = self.root
        for name in chain:
            node = node.children.setdefault(name, TrieNode())
            node.count += 1
        self._total_insertions += 1

    def query(self, chain: list[str]) -> tuple[int, int]:
        """
        Walk the chain until a miss.

        Returns:
            (match_depth, count_at_deepest_match)
            match_depth == len(chain) → full match
            match_depth == 0          → root-level miss (proc unknown)
        """
        node = self.root
        depth = 0
        last_count = 0
        for name in chain:
            if name not in node.children:
                break
            node = node.children[name]
            last_count = node.count
            depth += 1
        return depth, last_count

    def most_common_parent(self, proc_norm: str) -> str:
        """
        Return the most common baseline parent of proc_norm (by insertion count).
        Used for justification strings: "expected parent X, observed Y".
        Returns "" if proc_norm is not in the trie at all.
        """
        proc_node = self.root.children.get(proc_norm)
        if proc_node is None or not proc_node.children:
            return ""
        # Pick the parent child with the highest count
        return max(proc_node.children, key=lambda name: proc_node.children[name].count)

    @property
    def total_insertions(self) -> int:
        return self._total_insertions
