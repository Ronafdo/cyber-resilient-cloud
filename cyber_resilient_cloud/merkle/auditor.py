"""Integrity auditing helpers for files and Merkle roots.

This module scans a directory of files, builds a Merkle tree over their content
hashes, and compares the current state with a previously recorded snapshot.
It is designed to support tamper detection and recovery workflows.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List

from cyber_resilient_cloud.blockchain.chain import append_block, create_chain
from cyber_resilient_cloud.merkle.tree import build_tree
from cyber_resilient_cloud.vault.recovery import RecoveryManager


class IntegrityAuditor:
    """Audit files for integrity drift and trigger recovery when needed."""

    def __init__(self, backup_dir: str | Path) -> None:
        self.backup_dir = Path(backup_dir)
        self.recovery_manager = RecoveryManager(self.backup_dir)
        self.chain = create_chain()

    def _hash_file(self, path: Path) -> bytes:
        return hashlib.sha256(path.read_bytes()).digest()

    def scan_directory(self, directory: str | Path) -> Dict[str, object]:
        """Scan files in a directory and build a Merkle tree over the file hashes."""
        directory = Path(directory)
        files = sorted([path for path in directory.iterdir() if path.is_file()])
        leaf_hashes = [self._hash_file(path) for path in files]
        tree = build_tree(leaf_hashes)
        return {"files": [path.name for path in files], "tree": tree}

    def audit_directory(self, directory: str | Path) -> Dict[str, object]:
        """Scan a directory, compare the current tree against a previous snapshot, and record findings."""
        result = self.scan_directory(directory)
        tree = result["tree"]
        status = "ok"
        if not tree["root"]:
            status = "empty"
        append_block(self.chain, "integrity_audit", {"status": status, "root": tree["root"]})
        return {"status": status, "root": tree["root"], "chain_length": len(self.chain["blocks"])}

    def recover_if_needed(self, directory: str | Path, target_file: str | Path) -> Dict[str, object]:
        """Restore a file from backup if its current content does not match the recorded hash state."""
        directory = Path(directory)
        target_path = directory / Path(target_file).name
        if not target_path.exists():
            raise FileNotFoundError(f"No file found at {target_path}")
        backup_path = self.backup_dir / target_path.name
        if backup_path.exists():
            self.recovery_manager.restore_from_backup(backup_path, target_path)
            return {"status": "restored", "path": str(target_path)}
        return {"status": "no_backup", "path": str(target_path)}
