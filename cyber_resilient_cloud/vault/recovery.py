"""Recovery helpers for restoring files from backup after integrity mismatches."""

from __future__ import annotations

from pathlib import Path
from shutil import copy2
from typing import Dict


class RecoveryManager:
    """A lightweight recovery manager that restores a file from backup storage."""

    def __init__(self, backup_dir: str | Path) -> None:
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def restore_from_backup(self, source_path: str | Path, destination_path: str | Path) -> Dict[str, object]:
        """Copy the backup file into place and return a status payload."""
        source = Path(source_path)
        destination = Path(destination_path)
        backup_target = self.backup_dir / source.name

        if not backup_target.exists():
            raise FileNotFoundError(f"No backup found for {source.name}")

        destination.parent.mkdir(parents=True, exist_ok=True)
        copy2(backup_target, destination)
        return {"status": "restored", "source": str(source), "destination": str(destination)}

    def store_backup(self, source_path: str | Path) -> Dict[str, object]:
        """Store a copy of the source file in backup storage."""
        source = Path(source_path)
        backup_target = self.backup_dir / source.name
        if source.exists():
            copy2(source, backup_target)
        return {"status": "backed_up", "path": str(backup_target)}
