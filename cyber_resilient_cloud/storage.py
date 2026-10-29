"""Persistent encrypted-file metadata and tamper-evident audit storage."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any


class Storage:
    """Store encrypted blobs on disk and metadata/audit records in SQLite."""

    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir)
        self.blob_dir = self.data_dir / "encrypted_files"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.database_path = self.data_dir / "cloud.db"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    plaintext_size INTEGER NOT NULL,
                    plaintext_hash TEXT NOT NULL,
                    ciphertext_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    blob_name TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_blocks (
                    block_index INTEGER PRIMARY KEY,
                    event TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                );
                """
            )
            if connection.execute("SELECT COUNT(*) FROM audit_blocks").fetchone()[0] == 0:
                self._append_audit(connection, "genesis", {})

    def _append_audit(self, connection: sqlite3.Connection, event: str, payload: dict[str, Any]) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT block_index, hash FROM audit_blocks ORDER BY block_index DESC LIMIT 1"
        ).fetchone()
        index = 0 if previous is None else previous["block_index"] + 1
        previous_hash = "0" if previous is None else previous["hash"]
        block = {"index": index, "event": event, "payload": payload, "previous_hash": previous_hash}
        block_hash = hashlib.sha256(
            json.dumps(block, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        connection.execute(
            "INSERT INTO audit_blocks VALUES (?, ?, ?, ?, ?)",
            (index, event, json.dumps(payload, sort_keys=True), previous_hash, block_hash),
        )
        return {**block, "hash": block_hash}

    def save_file(self, metadata: dict[str, Any], ciphertext: bytes) -> dict[str, Any]:
        file_id = uuid.uuid4().hex
        blob_name = f"{file_id}.bin"
        (self.blob_dir / blob_name).write_bytes(ciphertext)
        record = {**metadata, "id": file_id, "blob_name": blob_name, "created_at": time.time()}
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(record[key] for key in (
                    "id", "filename", "mime_type", "plaintext_size", "plaintext_hash",
                    "ciphertext_hash", "salt", "nonce", "blob_name", "created_at",
                )),
            )
            self._append_audit(connection, "file_uploaded", {
                "file_id": file_id,
                "filename": record["filename"],
                "plaintext_hash": record["plaintext_hash"],
                "ciphertext_hash": record["ciphertext_hash"],
            })
        return record

    def list_files(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT id, filename, mime_type, plaintext_size, plaintext_hash, ciphertext_hash, created_at "
                "FROM files ORDER BY created_at DESC"
            ).fetchall()]

    def get_file(self, file_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM files WHERE id = ?", (file_id,)).fetchone()
        return None if row is None else dict(row)

    def read_blob(self, record: dict[str, Any]) -> bytes:
        return (self.blob_dir / record["blob_name"]).read_bytes()

    def verify_file(self, file_id: str) -> dict[str, Any]:
        record = self.get_file(file_id)
        if record is None:
            raise FileNotFoundError(file_id)
        blob = self.read_blob(record)
        actual_hash = hashlib.sha256(blob).hexdigest()
        valid = actual_hash == record["ciphertext_hash"]
        with self._connect() as connection:
            self._append_audit(connection, "file_verified", {
                "file_id": file_id, "valid": valid, "ciphertext_hash": actual_hash,
            })
        return {"id": file_id, "valid": valid, "stored_hash": record["ciphertext_hash"], "actual_hash": actual_hash}

    def audit_blocks(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM audit_blocks ORDER BY block_index").fetchall()
        return [{
            "index": row["block_index"], "event": row["event"], "payload": json.loads(row["payload"]),
            "previous_hash": row["previous_hash"], "hash": row["hash"],
        } for row in rows]
