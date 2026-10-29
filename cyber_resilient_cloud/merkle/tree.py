"""Merkle tree implementation for integrity verification.

The module exposes a simple interface for:
- building a Merkle tree from a list of leaf values
- inserting a new leaf and rebuilding the affected levels
- verifying that a leaf belongs to the tree at a given position

The contract is intentionally lightweight so the integrity auditor and API can
use the same logic without depending on the concrete storage format.
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_tree(leaves: List[bytes]) -> Dict[str, Any]:
    """Create a Merkle tree from the provided leaves."""
    levels: List[List[str]] = [[_hash_bytes(leaf) for leaf in leaves]]

    while len(levels[-1]) > 1:
        current = levels[-1]
        next_level = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else current[index]
            next_level.append(_hash_bytes((left + right).encode("utf-8")))
        levels.append(next_level)

    return {"levels": levels, "root": levels[-1][0] if levels else ""}


def insert_leaf(tree: Dict[str, Any], leaf: bytes) -> Dict[str, Any]:
    """Insert a leaf into an existing tree and rebuild the affected branches."""
    levels = [list(level) for level in tree["levels"]]
    levels[0].append(_hash_bytes(leaf))

    for level_index in range(1, len(levels)):
        previous_level = levels[level_index - 1]
        current_level = levels[level_index]
        new_level = []
        for index in range(0, len(previous_level), 2):
            left = previous_level[index]
            right = previous_level[index + 1] if index + 1 < len(previous_level) else previous_level[index]
            new_level.append(_hash_bytes((left + right).encode("utf-8")))
        levels[level_index] = new_level

    return {"levels": levels, "root": levels[-1][0] if levels else ""}


def verify_leaf(tree: Dict[str, Any], leaf: bytes, position: int) -> bool:
    """Verify that the given leaf exists at the specified position in the tree."""
    leaf_hash = _hash_bytes(leaf)
    levels = tree["levels"]
    if not levels or position >= len(levels[0]):
        return False
    if levels[0][position] != leaf_hash:
        return False
    return True
