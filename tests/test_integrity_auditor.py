from pathlib import Path

from cyber_resilient_cloud.merkle.auditor import IntegrityAuditor


def test_audit_directory_and_recover(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    original = data_dir / "sample.txt"
    original.write_text("hello", encoding="utf-8")

    backup_dir = tmp_path / "backup"
    auditor = IntegrityAuditor(backup_dir)
    auditor.recovery_manager.store_backup(original)

    result = auditor.audit_directory(data_dir)
    assert result["status"] == "ok"

    original.write_text("tampered", encoding="utf-8")
    restored = auditor.recover_if_needed(data_dir, "sample.txt")
    assert restored["status"] == "restored"
    assert original.read_text(encoding="utf-8") == "hello"
