import pytest

from cyber_resilient_cloud.vault.crypto import (
    derive_key,
    encrypt_bytes,
    decrypt_bytes,
)


def test_encrypt_decrypt_roundtrip():
    password = "capstone-secret"
    plaintext = b"sensitive payload"

    ciphertext, nonce, tag = encrypt_bytes(plaintext, password)

    assert ciphertext != plaintext
    assert len(nonce) == 12
    assert len(tag) == 16

    recovered = decrypt_bytes(ciphertext, password, nonce, tag)
    assert recovered == plaintext


def test_derive_key_is_stable_for_same_password():
    password = "capstone-secret"
    key_a = derive_key(password)
    key_b = derive_key(password)

    assert key_a == key_b


def test_decrypt_with_wrong_password_fails():
    password = "capstone-secret"
    other_password = "wrong-secret"
    plaintext = b"sensitive payload"

    ciphertext, nonce, tag = encrypt_bytes(plaintext, password)

    with pytest.raises(ValueError):
        decrypt_bytes(ciphertext, other_password, nonce, tag)
