from __future__ import annotations

from dataclasses import dataclass
import struct

from ..errors import UbinInvalidHeader

MAGIC = b"UBS1"
VERSION_MAJOR = 0
VERSION_MINOR = 2
ALGORITHM_AES_256_GCM = 1
FLAGS_NONE = 0

# 4s magic
# B  major
# B  minor
# B  algorithm
# B  flags
# H  header length
# I  frame size
# Q  original plaintext size
# Q  frame count
# 16s session id
# 12s nonce base
_HEADER = struct.Struct(">4sBBBBHIQQ16s12s")
HEADER_SIZE = _HEADER.size

FRAME_META = struct.Struct(">QII")
FINAL_META = struct.Struct(">4sI")
FINAL_MAGIC = b"END1"

GCM_TAG_SIZE = 16
FINAL_PLAINTEXT_SIZE = 32  # SHA-256 digest bytes
FINAL_CIPHERTEXT_SIZE = FINAL_PLAINTEXT_SIZE + GCM_TAG_SIZE

MAX_FRAME_SIZE = 64 * 1024 * 1024  # hard parser safety ceiling: 64 MiB
MIN_FRAME_SIZE = 1
MAX_FRAME_COUNT = (1 << 64) - 2  # reserve one counter value for final frame


@dataclass(frozen=True, slots=True)
class SecureHeader:
    frame_size: int
    original_size: int
    frame_count: int
    session_id: bytes
    nonce_base: bytes
    algorithm: int = ALGORITHM_AES_256_GCM
    flags: int = FLAGS_NONE
    major: int = VERSION_MAJOR
    minor: int = VERSION_MINOR

    def pack(self) -> bytes:
        if not (MIN_FRAME_SIZE <= self.frame_size <= MAX_FRAME_SIZE):
            raise UbinInvalidHeader("frame size outside UBIN Secure limits")
        if self.original_size < 0:
            raise UbinInvalidHeader("negative original size")
        if not (0 <= self.frame_count <= MAX_FRAME_COUNT):
            raise UbinInvalidHeader("frame count outside UBIN Secure limits")
        if len(self.session_id) != 16:
            raise UbinInvalidHeader("session_id must be 16 bytes")
        if len(self.nonce_base) != 12:
            raise UbinInvalidHeader("nonce_base must be 12 bytes")

        return _HEADER.pack(
            MAGIC,
            self.major,
            self.minor,
            self.algorithm,
            self.flags,
            HEADER_SIZE,
            self.frame_size,
            self.original_size,
            self.frame_count,
            self.session_id,
            self.nonce_base,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> "SecureHeader":
        if len(raw) != HEADER_SIZE:
            raise UbinInvalidHeader("incorrect UBIN Secure header length")

        (
            magic,
            major,
            minor,
            algorithm,
            flags,
            header_len,
            frame_size,
            original_size,
            frame_count,
            session_id,
            nonce_base,
        ) = _HEADER.unpack(raw)

        if magic != MAGIC:
            raise UbinInvalidHeader("not a UBIN Secure container")
        if (major, minor) != (VERSION_MAJOR, VERSION_MINOR):
            raise UbinInvalidHeader(
                f"unsupported UBIN Secure version {major}.{minor}"
            )
        if algorithm != ALGORITHM_AES_256_GCM:
            raise UbinInvalidHeader(f"unsupported algorithm id {algorithm}")
        if header_len != HEADER_SIZE:
            raise UbinInvalidHeader("unsupported header size")
        if flags != FLAGS_NONE:
            raise UbinInvalidHeader("unsupported UBIN Secure flags")
        if not (MIN_FRAME_SIZE <= frame_size <= MAX_FRAME_SIZE):
            raise UbinInvalidHeader("declared frame size outside safety limits")
        if frame_count > MAX_FRAME_COUNT:
            raise UbinInvalidHeader("declared frame count outside safety limits")

        # Structural consistency before any large processing.
        expected = 0 if original_size == 0 else (original_size + frame_size - 1) // frame_size
        if frame_count != expected:
            raise UbinInvalidHeader(
                "frame count does not match original size/frame size"
            )

        return cls(
            frame_size=frame_size,
            original_size=original_size,
            frame_count=frame_count,
            session_id=session_id,
            nonce_base=nonce_base,
            algorithm=algorithm,
            flags=flags,
            major=major,
            minor=minor,
        )


def frame_nonce(base: bytes, frame_number: int) -> bytes:
    """
    Derive a 96-bit per-frame nonce from a random 96-bit per-container base.
    Distinct frame numbers yield distinct nonces within the same container.
    """
    if len(base) != 12:
        raise ValueError("nonce base must be 12 bytes")
    if not (0 <= frame_number <= (1 << 64) - 1):
        raise ValueError("frame number out of range")

    high = base[:4]
    low = int.from_bytes(base[4:], "big") ^ frame_number
    return high + low.to_bytes(8, "big")

def frame_aad(header_bytes: bytes, frame_number: int, plaintext_len: int) -> bytes:
    # ciphertext length is deterministic for AES-GCM: plaintext + 16-byte tag.
    ciphertext_len = plaintext_len + GCM_TAG_SIZE
    return header_bytes + FRAME_META.pack(
        frame_number,
        plaintext_len,
        ciphertext_len,
    )


def final_aad(header_bytes: bytes) -> bytes:
    return header_bytes + FINAL_META.pack(FINAL_MAGIC, FINAL_CIPHERTEXT_SIZE)
