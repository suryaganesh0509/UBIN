from pathlib import Path
import hashlib
import os

import pytest

import ubin
from ubin.errors import (
    UbinAuthenticationError,
    UbinCorruptionError,
    UbinOutputExists,
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"x",
        b"Hello UBIN Secure",
        bytes(range(256)) * 100,
        os.urandom(2 * 1024 * 1024 + 123),
    ],
)
def test_encrypt_decrypt_exact_round_trip(tmp_path: Path, payload: bytes):
    source = tmp_path / "anything.unknownEXT"
    secure_path = tmp_path / "anything.ubs"
    restored = tmp_path / "restored.noMatter"
    source.write_bytes(payload)

    receipt = ubin.secure(source).save(secure_path)
    restore = ubin.decrypt(secure_path, restored, key=receipt.key)

    assert restored.read_bytes() == payload
    assert receipt.sha256 == _sha256(payload)
    assert restore.sha256 == _sha256(payload)
    assert restore.session_id == receipt.session_id


def test_wrong_key_is_rejected_and_no_output_is_published(tmp_path: Path):
    source = tmp_path / "data.bin"
    secure_path = tmp_path / "data.ubs"
    restored = tmp_path / "restored.bin"
    source.write_bytes(os.urandom(5000))

    ubin.secure(source).save(secure_path)
    wrong_key = ubin.secure(source).key

    with pytest.raises(UbinAuthenticationError):
        ubin.decrypt(secure_path, restored, key=wrong_key)

    assert not restored.exists()


def test_ciphertext_tamper_is_rejected(tmp_path: Path):
    source = tmp_path / "data.bin"
    secure_path = tmp_path / "data.ubs"
    restored = tmp_path / "restored.bin"
    source.write_bytes(os.urandom(10000))

    receipt = ubin.secure(source).save(secure_path)

    raw = bytearray(secure_path.read_bytes())
    # Flip a byte well after the fixed header, inside first frame ciphertext.
    raw[80] ^= 0x01
    secure_path.write_bytes(raw)

    with pytest.raises((UbinAuthenticationError, UbinCorruptionError)):
        ubin.decrypt(secure_path, restored, key=receipt.key)

    assert not restored.exists()


def test_header_tamper_is_rejected(tmp_path: Path):
    source = tmp_path / "data.bin"
    secure_path = tmp_path / "data.ubs"
    restored = tmp_path / "restored.bin"
    source.write_bytes(os.urandom(8000))

    receipt = ubin.secure(source).save(secure_path)

    raw = bytearray(secure_path.read_bytes())
    # Mutate version minor byte: parser must reject before decrypting.
    raw[5] ^= 0x01
    secure_path.write_bytes(raw)

    with pytest.raises(Exception):
        ubin.decrypt(secure_path, restored, key=receipt.key)

    assert not restored.exists()


def test_truncation_is_rejected(tmp_path: Path):
    source = tmp_path / "data.bin"
    secure_path = tmp_path / "data.ubs"
    restored = tmp_path / "restored.bin"
    source.write_bytes(os.urandom(12000))

    receipt = ubin.secure(source).save(secure_path)
    raw = secure_path.read_bytes()
    secure_path.write_bytes(raw[:-11])

    with pytest.raises(UbinCorruptionError):
        ubin.decrypt(secure_path, restored, key=receipt.key)

    assert not restored.exists()


def test_existing_output_is_not_overwritten_by_default(tmp_path: Path):
    source = tmp_path / "data.bin"
    secure_path = tmp_path / "data.ubs"
    restored = tmp_path / "restored.bin"

    source.write_bytes(b"original")
    restored.write_bytes(b"keep-me")

    receipt = ubin.secure(source).save(secure_path)

    with pytest.raises(UbinOutputExists):
        ubin.decrypt(secure_path, restored, key=receipt.key)

    assert restored.read_bytes() == b"keep-me"


def test_small_frame_size_exercises_multiple_frames(tmp_path: Path):
    payload = os.urandom(5000)
    source = tmp_path / "manyframes.bin"
    secure_path = tmp_path / "manyframes.ubs"
    restored = tmp_path / "restored.bin"
    source.write_bytes(payload)

    receipt = ubin.secure(source).save(secure_path, frame_size=257)
    assert receipt.frame_count > 10

    ubin.decrypt(secure_path, restored, key=receipt.key)
    assert restored.read_bytes() == payload


def test_trailing_data_is_rejected(tmp_path: Path):
    source = tmp_path / "data.bin"
    secure_path = tmp_path / "data.ubs"
    restored = tmp_path / "restored.bin"
    source.write_bytes(b"payload" * 100)

    receipt = ubin.secure(source).save(secure_path)
    with secure_path.open("ab") as f:
        f.write(b"ATTACKER-TRAILING-DATA")

    with pytest.raises(UbinCorruptionError):
        ubin.decrypt(secure_path, restored, key=receipt.key)

    assert not restored.exists()


def test_frame_nonce_derivation_is_unique_for_same_base():
    from ubin.secure.format import frame_nonce
    base = bytes.fromhex("00112233445566778899aabb")
    nonces = {frame_nonce(base, i) for i in range(10000)}
    assert len(nonces) == 10000
    assert all(len(nonce) == 12 for nonce in nonces)


def test_two_secure_containers_use_different_nonce_bases(tmp_path: Path):
    from ubin.secure.format import HEADER_SIZE, SecureHeader

    source = tmp_path / "data.bin"
    first = tmp_path / "first.ubs"
    second = tmp_path / "second.ubs"
    source.write_bytes(b"same-source" * 1000)

    secured = ubin.secure(source)
    key = secured.key
    ubin.secure(source, key=key).save(first)
    ubin.secure(source, key=key).save(second)

    with first.open("rb") as f:
        h1 = SecureHeader.unpack(f.read(HEADER_SIZE))
    with second.open("rb") as f:
        h2 = SecureHeader.unpack(f.read(HEADER_SIZE))

    assert h1.nonce_base != h2.nonce_base
