"""Client-side encryption helpers for the vault module.

This module exposes a small, self-contained interface for:
- deriving a symmetric key from a password using PBKDF2-HMAC-SHA256
- encrypting bytes with AES-256 GCM
- decrypting bytes with AES-256 GCM

The API is intentionally simple so the shield, Merkle, blockchain, and API
packages can depend on it without needing to know the underlying cryptography
implementation details.
"""

from __future__ import annotations

import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SALT_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16


def derive_key(password: str, salt: bytes | None = None) -> bytes:
    """Derive a 32-byte AES key from a password using PBKDF2-HMAC-SHA256."""
    if salt is None:
        salt = b"cyber-resilient-cloud"[:SALT_SIZE]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=200_000,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(plaintext: bytes, password: str) -> Tuple[bytes, bytes, bytes]:
    """Encrypt plaintext bytes and return ciphertext, nonce, and authentication tag."""
    key = derive_key(password)
    nonce = os.urandom(NONCE_SIZE)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    return ciphertext[:-TAG_SIZE], nonce, ciphertext[-TAG_SIZE:]


def decrypt_bytes(ciphertext: bytes, password: str, nonce: bytes, tag: bytes) -> bytes:
    """Decrypt ciphertext bytes and verify integrity using AES-GCM."""
    key = derive_key(password)
    cipher = AESGCM(key)
    try:
        return cipher.decrypt(nonce, ciphertext + tag, None)
    except Exception as exc:  # pragma: no cover - cryptography raises a specific error
        raise ValueError("Unable to decrypt payload; the password or payload may be invalid") from exc
