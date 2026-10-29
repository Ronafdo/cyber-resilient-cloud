from pathlib import Path

from cyber_resilient_cloud.vault.recovery import RecoveryManager


def test_backup_and_restore(tmp_path: Path):
    source = tmp_path / "file.txt"
    source.write_text("hello", encoding="utf-8")

    backup_dir = tmp_path / "backup"
    manager = RecoveryManager(backup_dir)
    manager.store_backup(source)

    restored_path = tmp_path / "restored.txt"
    result = manager.restore_from_backup(source, restored_path)

    assert result["status"] == "restored"
    assert restored_path.read_text(encoding="utf-8") == "hello"
