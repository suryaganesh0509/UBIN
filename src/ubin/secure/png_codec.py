from __future__ import annotations

from dataclasses import dataclass
import binascii
import math
import os
from pathlib import Path
import struct
import tempfile
import zlib

from ..errors import UbinCarrierError, UbinCorruptionError

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
IHDR = struct.Struct(">IIBBBBB")
MAX_DIMENSION = (1 << 31) - 1
DEFAULT_WIDTH = 1024
MAX_CHUNK_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PngInfo:
    width: int
    height: int
    payload_capacity: int


def _chunk_bytes(chunk_type: bytes, data: bytes) -> bytes:
    crc = binascii.crc32(chunk_type)
    crc = binascii.crc32(data, crc) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)


def _write_chunk(out, chunk_type: bytes, data: bytes) -> None:
    out.write(_chunk_bytes(chunk_type, data))


def dimensions_for_payload(payload_size: int, *, width: int = DEFAULT_WIDTH) -> PngInfo:
    if payload_size < 0:
        raise ValueError("payload_size must be >= 0")
    if not (1 <= width <= MAX_DIMENSION):
        raise ValueError("PNG width is out of range")
    pixels = max(1, math.ceil(payload_size / 4))
    height = math.ceil(pixels / width)
    if height > MAX_DIMENSION:
        raise UbinCarrierError("payload exceeds PNG dimension limits")
    return PngInfo(width=width, height=height, payload_capacity=width * height * 4)


def encode_file_to_png(payload_path, png_path, *, width: int = DEFAULT_WIDTH) -> PngInfo:
    """Encode exact payload bytes into an RGBA PNG using filter type 0 only."""
    payload = Path(payload_path)
    destination = Path(png_path)
    info = dimensions_for_payload(payload.stat().st_size, width=width)
    destination.parent.mkdir(parents=True, exist_ok=True)

    row_bytes = info.width * 4
    compressor = zlib.compressobj(level=1)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".ubin-part", dir=str(destination.parent)
    )
    temp_path = Path(temp_name)

    try:
        with os.fdopen(fd, "wb", buffering=0) as out, payload.open("rb", buffering=0) as src:
            out.write(PNG_SIGNATURE)
            _write_chunk(out, b"IHDR", IHDR.pack(info.width, info.height, 8, 6, 0, 0, 0))

            pending = bytearray()
            remaining = payload.stat().st_size
            for _row in range(info.height):
                take = min(row_bytes, remaining)
                row = src.read(take)
                if len(row) != take:
                    raise UbinCorruptionError("payload changed during PNG encoding")
                remaining -= take
                if take < row_bytes:
                    row += os.urandom(row_bytes - take)

                compressed = compressor.compress(b"\x00" + row)
                if compressed:
                    pending.extend(compressed)
                if len(pending) >= 1024 * 1024:
                    _write_chunk(out, b"IDAT", bytes(pending))
                    pending.clear()

            tail = compressor.flush()
            if tail:
                pending.extend(tail)
            if pending:
                _write_chunk(out, b"IDAT", bytes(pending))
            _write_chunk(out, b"IEND", b"")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp_path, destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise

    return info


def _read_chunk(file_obj):
    length_raw = file_obj.read(4)
    if length_raw == b"":
        raise UbinCarrierError("PNG ended before IEND")
    if len(length_raw) != 4:
        raise UbinCarrierError("truncated PNG chunk length")
    length = struct.unpack(">I", length_raw)[0]
    if length > (1 << 31) - 1:
        raise UbinCarrierError("PNG chunk length exceeds specification limit")
    if length > MAX_CHUNK_BYTES:
        raise UbinCarrierError("PNG chunk exceeds UBIN carrier safety limit")
    chunk_type = file_obj.read(4)
    if len(chunk_type) != 4:
        raise UbinCarrierError("truncated PNG chunk type")
    data = file_obj.read(length)
    if len(data) != length:
        raise UbinCarrierError("truncated PNG chunk data")
    crc_raw = file_obj.read(4)
    if len(crc_raw) != 4:
        raise UbinCarrierError("truncated PNG chunk CRC")
    expected_crc = struct.unpack(">I", crc_raw)[0]
    actual_crc = binascii.crc32(chunk_type)
    actual_crc = binascii.crc32(data, actual_crc) & 0xFFFFFFFF
    if expected_crc != actual_crc:
        raise UbinCarrierError(f"PNG CRC mismatch in {chunk_type!r}")
    return chunk_type, data


def decode_png_to_file(png_path, payload_path) -> PngInfo:
    """Decode UBIN-compatible RGBA/filter-0 PNG pixels to exact raw pixel bytes."""
    source = Path(png_path)
    destination = Path(payload_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    filtered_fd, filtered_name = tempfile.mkstemp(
        prefix=".ubin-png-filtered-", suffix=".tmp", dir=str(destination.parent)
    )
    filtered_path = Path(filtered_name)
    out_fd = None
    temp_path = None

    try:
        with source.open("rb", buffering=0) as f:
            if f.read(len(PNG_SIGNATURE)) != PNG_SIGNATURE:
                raise UbinCarrierError("not a PNG file")

            chunk_type, ihdr_data = _read_chunk(f)
            if chunk_type != b"IHDR" or len(ihdr_data) != IHDR.size:
                raise UbinCarrierError("PNG must begin with a valid IHDR chunk")
            width, height, bit_depth, color_type, compression, filter_method, interlace = IHDR.unpack(ihdr_data)
            if width == 0 or height == 0:
                raise UbinCarrierError("PNG dimensions must be non-zero")
            if (bit_depth, color_type, compression, filter_method, interlace) != (8, 6, 0, 0, 0):
                raise UbinCarrierError(
                    "UBIN carrier requires non-interlaced 8-bit RGBA PNG with standard compression/filter methods"
                )

            row_bytes = width * 4
            expected_filtered = height * (row_bytes + 1)
            decompressor = zlib.decompressobj()
            produced = 0
            seen_idat = False
            seen_iend = False

            with os.fdopen(filtered_fd, "wb", buffering=0) as filtered:
                # os.fdopen() now owns the descriptor.
                # Clear our raw reference so cleanup never double-closes it.
                filtered_fd = None
                while not seen_iend:
                    chunk_type, data = _read_chunk(f)
                    if chunk_type == b"IDAT":
                        seen_idat = True
                        pending_input = data
                        while pending_input:
                            remaining_output = expected_filtered - produced
                            block = decompressor.decompress(
                                pending_input,
                                max(1, remaining_output + 1),
                            )
                            produced += len(block)
                            if produced > expected_filtered:
                                raise UbinCarrierError("PNG expands beyond declared image dimensions")
                            filtered.write(block)
                            pending_input = decompressor.unconsumed_tail
                            if not pending_input:
                                break
                        if decompressor.unused_data:
                            raise UbinCarrierError("unexpected extra compressed PNG stream")
                    elif chunk_type == b"IEND":
                        if data:
                            raise UbinCarrierError("IEND chunk must be empty")
                        seen_iend = True
                    elif chunk_type[0] & 0x20 == 0:
                        raise UbinCarrierError(f"unsupported critical PNG chunk {chunk_type!r}")

                if decompressor.unused_data or decompressor.unconsumed_tail:
                    raise UbinCarrierError("unexpected extra compressed PNG data")
                block = decompressor.flush()
                produced += len(block)
                if produced != expected_filtered:
                    raise UbinCarrierError("PNG pixel stream length does not match IHDR dimensions")
                if not decompressor.eof:
                    raise UbinCarrierError("truncated PNG compressed stream")
                filtered.write(block)
                filtered.flush()
                os.fsync(filtered.fileno())

            if not seen_idat:
                raise UbinCarrierError("PNG contains no IDAT data")
            if f.read(1) != b"":
                raise UbinCarrierError("trailing bytes after PNG IEND are not accepted")

        out_fd, temp_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=str(destination.parent)
        )
        temp_path = Path(temp_name)
        with filtered_path.open("rb", buffering=0) as filtered, os.fdopen(out_fd, "wb", buffering=0) as out:
            out_fd = None
            for _ in range(height):
                marker = filtered.read(1)
                if marker != b"\x00":
                    raise UbinCarrierError("UBIN carrier PNG was filtered or transformed")
                row = filtered.read(row_bytes)
                if len(row) != row_bytes:
                    raise UbinCarrierError("truncated PNG scanline")
                out.write(row)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp_path, destination)
        temp_path = None
        return PngInfo(width=width, height=height, payload_capacity=width * height * 4)
    except zlib.error as exc:
        raise UbinCarrierError("invalid PNG compressed stream") from exc
    finally:
        # A malformed PNG can fail before os.fdopen() takes ownership of
        # filtered_fd. Windows does not allow an open file to be unlinked,
        # so close every descriptor still owned here before cleanup.
        if filtered_fd is not None:
            try:
                os.close(filtered_fd)
            except OSError:
                pass

        if out_fd is not None:
            try:
                os.close(out_fd)
            except OSError:
                pass

        try:
            filtered_path.unlink(missing_ok=True)
        except OSError:
            pass

        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
