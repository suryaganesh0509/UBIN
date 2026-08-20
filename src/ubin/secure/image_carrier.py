from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import struct
import tempfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ..errors import (
    UbinAuthenticationError,
    UbinCarrierError,
    UbinOutputExists,
)
from .container import DEFAULT_SECURE_FRAME_SIZE, SecureSource, decrypt_file
from .krp import DEFAULT_KRP_BLOCK_SIZE, permute_file, restore_file
from .png_codec import DEFAULT_WIDTH, decode_png_to_file, encode_file_to_png

CARRIER_MAGIC = b"UBIPNG10"
CARRIER_VERSION = 1
CARRIER_FLAGS_KRP = 0x01
CARRIER_HEADER_FIXED = struct.Struct(">8sBBHQQH16s16s32s")
CARRIER_MAX_FILENAME_BYTES = 1024
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1


@dataclass(frozen=True, slots=True)
class ImageCarrierReceipt:
    output: Path
    original_name: str
    original_size: int
    carrier_size: int
    secure_payload_size: int
    sha256: str
    width: int
    height: int
    layout: str = "krp+png"


@dataclass(frozen=True, slots=True)
class ImageRestoreReceipt:
    output: Path
    original_name: str
    restored_size: int
    sha256: str
    width: int
    height: int
    layout: str = "krp+png"


def _passphrase_bytes(passphrase) -> bytes:
    if isinstance(passphrase, str):
        raw = passphrase.encode("utf-8")
    elif isinstance(passphrase, (bytes, bytearray)):
        raw = bytes(passphrase)
    else:
        raise TypeError("passphrase must be str or bytes")
    if len(raw) < 8:
        raise ValueError("UBIN image passphrase must be at least 8 bytes/characters")
    return raw


def _derive_keys(passphrase, salt: bytes, context_id: bytes) -> tuple[bytes, bytes]:
    master = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    ).derive(_passphrase_bytes(passphrase))
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=context_id,
        info=b"UBIN-v1.0/image-carrier-keys",
    ).derive(master)
    return material[:32], material[32:]


def _carrier_context(salt: bytes, context_id: bytes) -> bytes:
    return b"UBIN-v1.0/image-carrier-krp\x00" + salt + context_id


def _hash_file(path: Path, block_size: int = 1024 * 1024) -> bytes:
    h = hashlib.sha256()
    with path.open("rb", buffering=0) as f:
        while True:
            block = f.read(block_size)
            if not block:
                break
            h.update(block)
    return h.digest()


def _pack_header(
    *,
    original_name: str,
    original_size: int,
    secure_payload_size: int,
    salt: bytes,
    context_id: bytes,
    payload_sha256: bytes,
) -> bytes:
    name = original_name.encode("utf-8")
    if not name or len(name) > CARRIER_MAX_FILENAME_BYTES:
        raise UbinCarrierError("invalid or overly long original filename")
    if "/" in original_name or "\\" in original_name or "\x00" in original_name:
        raise UbinCarrierError("carrier original filename must be a basename")
    header_len = CARRIER_HEADER_FIXED.size + len(name)
    return CARRIER_HEADER_FIXED.pack(
        CARRIER_MAGIC,
        CARRIER_VERSION,
        CARRIER_FLAGS_KRP,
        header_len,
        original_size,
        secure_payload_size,
        len(name),
        salt,
        context_id,
        payload_sha256,
    ) + name


def _read_header(pixel_path: Path):
    with pixel_path.open("rb", buffering=0) as f:
        fixed = f.read(CARRIER_HEADER_FIXED.size)
        if len(fixed) != CARRIER_HEADER_FIXED.size:
            raise UbinCarrierError("PNG does not contain a complete UBIN carrier header")
        (
            magic,
            version,
            flags,
            header_len,
            original_size,
            secure_payload_size,
            name_len,
            salt,
            context_id,
            payload_sha256,
        ) = CARRIER_HEADER_FIXED.unpack(fixed)
        if magic != CARRIER_MAGIC or version != CARRIER_VERSION:
            raise UbinCarrierError("PNG is not a UBIN v1 image carrier")
        if flags != CARRIER_FLAGS_KRP:
            raise UbinCarrierError("unsupported UBIN image carrier flags")
        if not (1 <= name_len <= CARRIER_MAX_FILENAME_BYTES):
            raise UbinCarrierError("invalid carrier filename length")
        if header_len != CARRIER_HEADER_FIXED.size + name_len:
            raise UbinCarrierError("invalid UBIN carrier header length")
        name_raw = f.read(name_len)
        if len(name_raw) != name_len:
            raise UbinCarrierError("truncated UBIN carrier filename")
        try:
            original_name = name_raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UbinCarrierError("carrier filename is not valid UTF-8") from exc
        if not original_name or "/" in original_name or "\\" in original_name or "\x00" in original_name:
            raise UbinCarrierError("unsafe carrier filename")
        total = pixel_path.stat().st_size
        if secure_payload_size < 1 or header_len + secure_payload_size > total:
            raise UbinCarrierError("carrier payload length exceeds PNG pixel capacity")
        return {
            "header_len": header_len,
            "original_size": original_size,
            "secure_payload_size": secure_payload_size,
            "original_name": original_name,
            "salt": salt,
            "context_id": context_id,
            "payload_sha256": payload_sha256,
        }


def create_image_carrier(
    source,
    destination,
    *,
    passphrase,
    frame_size: int = DEFAULT_SECURE_FRAME_SIZE,
    krp_block_size: int = DEFAULT_KRP_BLOCK_SIZE,
    width: int = DEFAULT_WIDTH,
    overwrite: bool = False,
) -> ImageCarrierReceipt:
    source_path = Path(source).expanduser()
    destination = Path(destination).expanduser()
    if destination.exists() and not overwrite:
        raise UbinOutputExists(f"destination already exists: {destination}")
    if source_path.resolve() == destination.resolve():
        raise ValueError("image carrier destination must differ from source")

    destination.parent.mkdir(parents=True, exist_ok=True)
    salt = secrets.token_bytes(16)
    context_id = secrets.token_bytes(16)
    encryption_key, permutation_key = _derive_keys(passphrase, salt, context_id)

    with tempfile.TemporaryDirectory(prefix="ubin-image-") as tmp:
        tmp = Path(tmp)
        secure_path = tmp / "payload.ubs"
        permuted_path = tmp / "payload.krp"
        carrier_payload_path = tmp / "carrier.raw"

        secure_receipt = SecureSource(source_path, key=encryption_key).save(
            secure_path,
            frame_size=frame_size,
            overwrite=True,
        )
        permute_file(
            secure_path,
            permuted_path,
            permutation_key,
            context=_carrier_context(salt, context_id),
            block_size=krp_block_size,
        )
        secure_payload_size = secure_path.stat().st_size
        payload_digest = _hash_file(permuted_path)
        header = _pack_header(
            original_name=source_path.name,
            original_size=secure_receipt.original_size,
            secure_payload_size=permuted_path.stat().st_size,
            salt=salt,
            context_id=context_id,
            payload_sha256=payload_digest,
        )

        with carrier_payload_path.open("wb", buffering=0) as out, permuted_path.open("rb", buffering=0) as inp:
            out.write(header)
            while True:
                block = inp.read(1024 * 1024)
                if not block:
                    break
                out.write(block)
            out.flush()
            os.fsync(out.fileno())

        png_info = encode_file_to_png(carrier_payload_path, destination, width=width)

    return ImageCarrierReceipt(
        output=destination,
        original_name=source_path.name,
        original_size=secure_receipt.original_size,
        carrier_size=destination.stat().st_size,
        secure_payload_size=secure_payload_size,
        sha256=secure_receipt.sha256,
        width=png_info.width,
        height=png_info.height,
    )


def restore_image_carrier(
    carrier,
    destination=None,
    *,
    passphrase,
    krp_block_size: int = DEFAULT_KRP_BLOCK_SIZE,
    overwrite: bool = False,
) -> ImageRestoreReceipt:
    carrier_path = Path(carrier).expanduser()

    with tempfile.TemporaryDirectory(prefix="ubin-image-restore-") as tmp:
        tmp = Path(tmp)
        pixels_path = tmp / "pixels.raw"
        permuted_path = tmp / "payload.krp"
        secure_path = tmp / "payload.ubs"

        png_info = decode_png_to_file(carrier_path, pixels_path)
        meta = _read_header(pixels_path)
        if destination is None:
            destination = carrier_path.with_name(meta["original_name"])
        destination = Path(destination).expanduser()
        if destination.exists() and not overwrite:
            raise UbinOutputExists(f"destination already exists: {destination}")

        with pixels_path.open("rb", buffering=0) as src, permuted_path.open("wb", buffering=0) as out:
            src.seek(meta["header_len"])
            remaining = meta["secure_payload_size"]
            digest = hashlib.sha256()
            while remaining:
                block = src.read(min(1024 * 1024, remaining))
                if not block:
                    raise UbinCarrierError("truncated UBIN image payload")
                out.write(block)
                digest.update(block)
                remaining -= len(block)
            out.flush()
            os.fsync(out.fileno())
        if not secrets.compare_digest(digest.digest(), meta["payload_sha256"]):
            raise UbinCarrierError("UBIN image payload hash mismatch")

        encryption_key, permutation_key = _derive_keys(
            passphrase, meta["salt"], meta["context_id"]
        )
        restore_file(
            permuted_path,
            secure_path,
            permutation_key,
            context=_carrier_context(meta["salt"], meta["context_id"]),
            block_size=krp_block_size,
        )
        try:
            restored = decrypt_file(
                secure_path,
                destination,
                key=encryption_key,
                overwrite=overwrite,
            )
        except Exception as exc:
            if isinstance(exc, UbinOutputExists):
                raise
            raise UbinAuthenticationError(
                "UBIN image authentication failed (wrong passphrase or modified carrier)"
            ) from exc

    return ImageRestoreReceipt(
        output=restored.output,
        original_name=meta["original_name"],
        restored_size=restored.restored_size,
        sha256=restored.sha256,
        width=png_info.width,
        height=png_info.height,
    )
