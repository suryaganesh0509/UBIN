from __future__ import annotations

from dataclasses import dataclass
import struct

from ..errors import UbinProtocolError
from .format import GCM_TAG_SIZE, MAX_FRAME_COUNT, MAX_FRAME_SIZE
from .network_format import (
    FRAME_META,
    FINAL_MAGIC,
    FINAL_META,
    MAX_FILENAME_BYTES,
)

TRANSFER_MAGIC = b"UBT4"
TRANSFER_MAJOR = 0
TRANSFER_MINOR = 4
TRANSFER_FLAGS_NONE = 0

# magic, major, minor, flags, frame_size, original_size, frame_count,
# transfer_id, per-connection nonce base, source SHA-256, filename length
TRANSFER_FIXED = struct.Struct(">4sBBHIQQ16s12s32sH")

REQUEST_MAGIC = b"UBR4"
REQUEST_NEW = 0
REQUEST_RESUME = 1
REQUEST = struct.Struct(">4sB32s")

STATUS_MAGIC = b"UBS4"
STATUS_OK = 1
# magic, status, next_frame, bytes_received, resume_ticket
STATUS = struct.Struct(">4sBQQ32s")

ACK_MAGIC = b"UBA4"
ACK = struct.Struct(">4sBQ32s16s")

TICKET_SIZE = 32
ZERO_TICKET = b"\x00" * TICKET_SIZE

FINAL_PLAINTEXT_SIZE = 32
FINAL_CIPHERTEXT_SIZE = FINAL_PLAINTEXT_SIZE + GCM_TAG_SIZE


def _validate_filename(name: str) -> None:
    if not name or name in {".", ".."}:
        raise UbinProtocolError("invalid UBIN transfer filename")
    if "/" in name or "\\" in name or "\x00" in name:
        raise UbinProtocolError(
            "UBIN network filename must be a single basename"
        )


@dataclass(frozen=True, slots=True)
class ResumeTransferHeader:
    filename: str
    frame_size: int
    original_size: int
    frame_count: int
    transfer_id: bytes
    nonce_base: bytes
    source_sha256: bytes
    flags: int = TRANSFER_FLAGS_NONE

    def pack(self) -> bytes:
        _validate_filename(self.filename)
        filename_bytes = self.filename.encode("utf-8")
        if len(filename_bytes) > MAX_FILENAME_BYTES:
            raise UbinProtocolError("UBIN filename is too long")
        if not (1 <= self.frame_size <= MAX_FRAME_SIZE):
            raise UbinProtocolError("invalid UBIN network frame size")
        if self.original_size < 0:
            raise UbinProtocolError("negative UBIN source size")

        expected = (
            0
            if self.original_size == 0
            else (self.original_size + self.frame_size - 1) // self.frame_size
        )
        if self.frame_count != expected or self.frame_count > MAX_FRAME_COUNT:
            raise UbinProtocolError(
                "frame count does not match UBIN source size"
            )
        if len(self.transfer_id) != 16:
            raise UbinProtocolError("transfer_id must be 16 bytes")
        if len(self.nonce_base) != 12:
            raise UbinProtocolError("nonce_base must be 12 bytes")
        if len(self.source_sha256) != 32:
            raise UbinProtocolError("source_sha256 must be 32 bytes")

        fixed = TRANSFER_FIXED.pack(
            TRANSFER_MAGIC,
            TRANSFER_MAJOR,
            TRANSFER_MINOR,
            self.flags,
            self.frame_size,
            self.original_size,
            self.frame_count,
            self.transfer_id,
            self.nonce_base,
            self.source_sha256,
            len(filename_bytes),
        )
        return fixed + filename_bytes

    @classmethod
    def unpack(
        cls,
        fixed: bytes,
        filename_bytes: bytes,
    ) -> "ResumeTransferHeader":
        if len(fixed) != TRANSFER_FIXED.size:
            raise UbinProtocolError("invalid resumable transfer header length")

        (
            magic,
            major,
            minor,
            flags,
            frame_size,
            original_size,
            frame_count,
            transfer_id,
            nonce_base,
            source_sha256,
            filename_len,
        ) = TRANSFER_FIXED.unpack(fixed)

        if magic != TRANSFER_MAGIC:
            raise UbinProtocolError("invalid UBIN resumable transfer magic")
        if (major, minor) != (TRANSFER_MAJOR, TRANSFER_MINOR):
            raise UbinProtocolError(
                f"unsupported UBIN resumable transfer version {major}.{minor}"
            )
        if flags != TRANSFER_FLAGS_NONE:
            raise UbinProtocolError("unsupported UBIN resumable flags")
        if filename_len != len(filename_bytes):
            raise UbinProtocolError("filename length mismatch")
        if filename_len > MAX_FILENAME_BYTES:
            raise UbinProtocolError("UBIN filename exceeds safety limit")

        try:
            filename = filename_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UbinProtocolError("filename is not valid UTF-8") from exc

        header = cls(
            filename=filename,
            frame_size=frame_size,
            original_size=original_size,
            frame_count=frame_count,
            transfer_id=transfer_id,
            nonce_base=nonce_base,
            source_sha256=source_sha256,
            flags=flags,
        )
        header.pack()
        return header


def expected_bytes_for_next_frame(
    next_frame: int,
    frame_size: int,
    original_size: int,
    frame_count: int,
) -> int:
    if not (0 <= next_frame <= frame_count):
        raise UbinProtocolError("resume next_frame is out of range")
    if next_frame == frame_count:
        return original_size
    return next_frame * frame_size


def frame_aad(
    header_bytes: bytes,
    status_bytes: bytes,
    frame_number: int,
    plaintext_len: int,
) -> bytes:
    return (
        header_bytes
        + status_bytes
        + FRAME_META.pack(
            frame_number,
            plaintext_len,
            plaintext_len + GCM_TAG_SIZE,
        )
    )


def final_aad(header_bytes: bytes, status_bytes: bytes) -> bytes:
    return (
        header_bytes
        + status_bytes
        + FINAL_META.pack(FINAL_MAGIC, FINAL_CIPHERTEXT_SIZE)
    )
