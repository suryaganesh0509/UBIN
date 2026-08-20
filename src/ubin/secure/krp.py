from __future__ import annotations

import hashlib
import hmac
from math import ceil

from ..errors import UbinSecureError

DEFAULT_KRP_BLOCK_SIZE = 4096
KRP_ROUNDS = 6


class UbinPermutationError(UbinSecureError):
    """Invalid keyed reversible permutation input or configuration."""


def _validate(key: bytes, data_len: int, block_size: int, context: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) < 16:
        raise UbinPermutationError("KRP key must contain at least 16 bytes")
    if data_len < 0:
        raise UbinPermutationError("KRP data length cannot be negative")
    if block_size <= 0:
        raise UbinPermutationError("KRP block_size must be positive")
    if not isinstance(context, (bytes, bytearray)):
        raise UbinPermutationError("KRP context must be bytes")


def _round_value(key: bytes, context: bytes, round_no: int, right: int, half_bytes: int) -> int:
    payload = (
        b"UBIN-KRP-v0.5\x00"
        + len(context).to_bytes(2, "big")
        + bytes(context)
        + round_no.to_bytes(1, "big")
        + right.to_bytes(half_bytes, "big")
    )
    digest = hmac.new(bytes(key), payload, hashlib.sha256).digest()
    return int.from_bytes(digest[:half_bytes], "big")


def _feistel_once(index: int, key: bytes, context: bytes, width_bits: int) -> int:
    half_bits = width_bits // 2
    half_mask = (1 << half_bits) - 1
    half_bytes = ceil(half_bits / 8)
    left = index >> half_bits
    right = index & half_mask

    for round_no in range(KRP_ROUNDS):
        f = _round_value(key, context, round_no, right, half_bytes) & half_mask
        left, right = right, left ^ f

    return (left << half_bits) | right


def _permuted_index(index: int, count: int, key: bytes, context: bytes) -> int:
    """
    Map one block index to another without storing a permutation table.

    A balanced Feistel permutation is built over the smallest even-bit power-
    of-two domain containing `count`; cycle walking maps it back into [0,count).
    """
    if not (0 <= index < count):
        raise UbinPermutationError("KRP block index is out of range")
    if count <= 1:
        return index

    width_bits = max(2, (count - 1).bit_length())
    if width_bits % 2:
        width_bits += 1

    value = index
    # The containing Feistel domain is at most <4x the requested range because
    # width_bits is rounded to the next even value, so cycle walking terminates
    # quickly on average. The guard turns pathological behavior into a controlled
    # error rather than an unbounded loop.
    for _ in range(128):
        value = _feistel_once(value, key, context, width_bits)
        if value < count:
            return value
    raise UbinPermutationError("KRP cycle-walk safety limit exceeded")


def permute_blocks(
    data: bytes,
    key: bytes,
    *,
    context: bytes,
    block_size: int = DEFAULT_KRP_BLOCK_SIZE,
) -> bytes:
    """
    Reorder only complete fixed-size blocks; a short tail remains in place.

    This makes the transform exactly reversible without serializing/storing a
    sequence table. Security still comes from AES-GCM/TLS; KRP is a reversible
    ciphertext-layout layer for later carrier formats.
    """
    raw = bytes(data)
    _validate(key, len(raw), block_size, context)

    block_count = len(raw) // block_size
    if block_count <= 1:
        return raw

    full_len = block_count * block_size
    out = bytearray(len(raw))
    for source_index in range(block_count):
        target_index = _permuted_index(source_index, block_count, key, context)
        src = source_index * block_size
        dst = target_index * block_size
        out[dst : dst + block_size] = raw[src : src + block_size]

    out[full_len:] = raw[full_len:]
    return bytes(out)


def restore_blocks(
    data: bytes,
    key: bytes,
    *,
    context: bytes,
    block_size: int = DEFAULT_KRP_BLOCK_SIZE,
) -> bytes:
    """Reverse :func:`permute_blocks` exactly."""
    raw = bytes(data)
    _validate(key, len(raw), block_size, context)

    block_count = len(raw) // block_size
    if block_count <= 1:
        return raw

    full_len = block_count * block_size
    out = bytearray(len(raw))
    for original_index in range(block_count):
        permuted_index = _permuted_index(
            original_index,
            block_count,
            key,
            context,
        )
        src = permuted_index * block_size
        dst = original_index * block_size
        out[dst : dst + block_size] = raw[src : src + block_size]

    out[full_len:] = raw[full_len:]
    return bytes(out)


def frame_context(
    transfer_id: bytes,
    nonce_base: bytes,
    frame_number: int,
) -> bytes:
    if len(transfer_id) != 16:
        raise UbinPermutationError("transfer_id must be 16 bytes")
    if len(nonce_base) != 12:
        raise UbinPermutationError("nonce_base must be 12 bytes")
    if not (0 <= frame_number <= (1 << 64) - 1):
        raise UbinPermutationError("frame number out of range")
    return (
        b"UBIN-KRP-FRAME-v0.5\x00"
        + transfer_id
        + nonce_base
        + frame_number.to_bytes(8, "big")
    )


def permute_file(
    source_path,
    destination_path,
    key: bytes,
    *,
    context: bytes,
    block_size: int = DEFAULT_KRP_BLOCK_SIZE,
) -> int:
    """Permute a file with bounded memory and return bytes written."""
    from pathlib import Path
    import os

    source = Path(source_path)
    destination = Path(destination_path)
    size = source.stat().st_size
    _validate(key, size, block_size, context)
    destination.parent.mkdir(parents=True, exist_ok=True)

    block_count = size // block_size
    full_len = block_count * block_size

    with source.open("rb", buffering=0) as src, destination.open("wb", buffering=0) as out:
        out.truncate(size)
        src_fd = src.fileno()
        out_fd = out.fileno()

        for source_index in range(block_count):
            target_index = _permuted_index(source_index, block_count, key, context)
            src_offset = source_index * block_size
            dst_offset = target_index * block_size
            if hasattr(os, "pread"):
                block = os.pread(src_fd, block_size, src_offset)
            else:
                src.seek(src_offset)
                block = src.read(block_size)
            if len(block) != block_size:
                raise UbinPermutationError("source changed during KRP file permutation")
            if hasattr(os, "pwrite"):
                written = os.pwrite(out_fd, block, dst_offset)
                if written != len(block):
                    raise UbinPermutationError("short KRP file write")
            else:
                out.seek(dst_offset)
                out.write(block)

        if full_len < size:
            tail_len = size - full_len
            if hasattr(os, "pread"):
                tail = os.pread(src_fd, tail_len, full_len)
            else:
                src.seek(full_len)
                tail = src.read(tail_len)
            if len(tail) != tail_len:
                raise UbinPermutationError("source changed during KRP tail read")
            if hasattr(os, "pwrite"):
                written = os.pwrite(out_fd, tail, full_len)
                if written != len(tail):
                    raise UbinPermutationError("short KRP tail write")
            else:
                out.seek(full_len)
                out.write(tail)

        out.flush()
        os.fsync(out.fileno())

    return size


def restore_file(
    source_path,
    destination_path,
    key: bytes,
    *,
    context: bytes,
    block_size: int = DEFAULT_KRP_BLOCK_SIZE,
) -> int:
    """Reverse :func:`permute_file` with bounded memory."""
    from pathlib import Path
    import os

    source = Path(source_path)
    destination = Path(destination_path)
    size = source.stat().st_size
    _validate(key, size, block_size, context)
    destination.parent.mkdir(parents=True, exist_ok=True)

    block_count = size // block_size
    full_len = block_count * block_size

    with source.open("rb", buffering=0) as src, destination.open("wb", buffering=0) as out:
        out.truncate(size)
        src_fd = src.fileno()
        out_fd = out.fileno()

        for original_index in range(block_count):
            permuted_index = _permuted_index(original_index, block_count, key, context)
            src_offset = permuted_index * block_size
            dst_offset = original_index * block_size
            if hasattr(os, "pread"):
                block = os.pread(src_fd, block_size, src_offset)
            else:
                src.seek(src_offset)
                block = src.read(block_size)
            if len(block) != block_size:
                raise UbinPermutationError("source changed during KRP file restoration")
            if hasattr(os, "pwrite"):
                written = os.pwrite(out_fd, block, dst_offset)
                if written != len(block):
                    raise UbinPermutationError("short KRP restore write")
            else:
                out.seek(dst_offset)
                out.write(block)

        if full_len < size:
            tail_len = size - full_len
            if hasattr(os, "pread"):
                tail = os.pread(src_fd, tail_len, full_len)
            else:
                src.seek(full_len)
                tail = src.read(tail_len)
            if len(tail) != tail_len:
                raise UbinPermutationError("source changed during KRP restore tail read")
            if hasattr(os, "pwrite"):
                written = os.pwrite(out_fd, tail, full_len)
                if written != len(tail):
                    raise UbinPermutationError("short KRP restore tail write")
            else:
                out.seek(full_len)
                out.write(tail)

        out.flush()
        os.fsync(out.fileno())

    return size
