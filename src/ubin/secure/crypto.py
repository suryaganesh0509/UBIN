from __future__ import annotations

import os
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import UbinAuthenticationError, UbinKeyError

KEY_SIZE = 32  # AES-256


def generate_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def validate_key(key: bytes) -> bytes:
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise UbinKeyError("UBIN Secure key must be bytes-like")
    key = bytes(key)
    if len(key) != KEY_SIZE:
        raise UbinKeyError("UBIN Secure AES-256 key must be exactly 32 bytes")
    return key


def encrypt_aead(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    return AESGCM(validate_key(key)).encrypt(nonce, plaintext, aad)


def decrypt_aead(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    try:
        return AESGCM(validate_key(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise UbinAuthenticationError(
            "UBIN Secure authentication failed: wrong key or modified data"
        ) from exc
