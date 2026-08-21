"""UBIN 2 stable language-neutral canonical value and envelope protocol.

The protocol is intentionally independent of Python object internals. Its wire
representation is specified in ``docs/PROTOCOL_V2.md`` and is shared by the C,
C++, Java and Python conformance implementations under ``interop/``.
"""

from __future__ import annotations

import math
import struct
from typing import Any

from .version import PROTOCOL_VERSION

MAGIC = b"UBN2"
PROTOCOL_STABILITY = "stable"
HEADER_SIZE = 12
MAX_DEPTH = 64
DEFAULT_MAX_PAYLOAD = 64 * 1024 * 1024
DEFAULT_MAX_ITEMS = 1_000_000
MESSAGE_TYPE_VALUE = 1
MESSAGE_TYPE_BYTES = 2
_HEADER = struct.Struct(">4sBBHI")


class ProtocolDecodeError(ValueError):
    """Raised when untrusted UBIN protocol bytes are invalid or non-canonical."""


def _u32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise OverflowError("value does not fit UBIN u32")
    return struct.pack(">I", value)


def encode_value(value: Any, *, _depth: int = 0) -> bytes:
    """Encode a supported logical value into the canonical UBIN 2 representation."""
    if _depth > MAX_DEPTH:
        raise ValueError("UBIN value nesting is too deep")
    if value is None:
        return b"\x00"
    if value is False:
        return b"\x01"
    if value is True:
        return b"\x02"
    if isinstance(value, int) and not isinstance(value, bool):
        if not -(2**63) <= value < 2**63:
            raise OverflowError("UBIN integer must fit signed int64")
        return b"\x10" + struct.pack(">q", value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("UBIN canonical float must be finite")
        return b"\x11" + struct.pack(">d", value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return b"\x20" + _u32(len(raw)) + raw
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return b"\x21" + _u32(len(raw)) + raw
    if isinstance(value, (list, tuple)):
        body = bytearray(b"\x30" + _u32(len(value)))
        for item in value:
            body.extend(encode_value(item, _depth=_depth + 1))
        return bytes(body)
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("UBIN canonical map keys must be strings")
        keys = sorted(value, key=lambda item: item.encode("utf-8"))
        body = bytearray(b"\x31" + _u32(len(keys)))
        for key in keys:
            body.extend(encode_value(key, _depth=_depth + 1))
            body.extend(encode_value(value[key], _depth=_depth + 1))
        return bytes(body)
    raise TypeError(f"unsupported UBIN canonical value type: {type(value).__name__}")


class _Reader:
    __slots__ = ("data", "offset", "max_items", "items")

    def __init__(self, data: bytes, *, max_items: int):
        self.data = data
        self.offset = 0
        self.max_items = max_items
        self.items = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise ProtocolDecodeError("truncated UBIN value")
        out = self.data[self.offset:self.offset + size]
        self.offset += size
        return out

    def value(self, depth: int = 0):
        if depth > MAX_DEPTH:
            raise ProtocolDecodeError("UBIN value nesting is too deep")
        self.items += 1
        if self.items > self.max_items:
            raise ProtocolDecodeError("UBIN value item limit exceeded")
        tag = self.take(1)[0]
        if tag == 0x00:
            return None
        if tag == 0x01:
            return False
        if tag == 0x02:
            return True
        if tag == 0x10:
            return struct.unpack(">q", self.take(8))[0]
        if tag == 0x11:
            value = struct.unpack(">d", self.take(8))[0]
            if not math.isfinite(value):
                raise ProtocolDecodeError("non-finite UBIN float")
            return value
        if tag in (0x20, 0x21):
            size = struct.unpack(">I", self.take(4))[0]
            raw = self.take(size)
            if tag == 0x20:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ProtocolDecodeError("invalid UBIN UTF-8 string") from exc
        if tag == 0x30:
            count = struct.unpack(">I", self.take(4))[0]
            if count > self.max_items - self.items:
                raise ProtocolDecodeError("UBIN value item limit exceeded")
            return [self.value(depth + 1) for _ in range(count)]
        if tag == 0x31:
            count = struct.unpack(">I", self.take(4))[0]
            if count > (self.max_items - self.items) // 2:
                raise ProtocolDecodeError("UBIN value item limit exceeded")
            result = {}
            previous: bytes | None = None
            for _ in range(count):
                key = self.value(depth + 1)
                if not isinstance(key, str):
                    raise ProtocolDecodeError("UBIN map key is not a string")
                encoded_key = key.encode("utf-8")
                if previous is not None and encoded_key <= previous:
                    raise ProtocolDecodeError("UBIN map keys are not in canonical order")
                previous = encoded_key
                result[key] = self.value(depth + 1)
            return result
        raise ProtocolDecodeError(f"unknown UBIN value tag: 0x{tag:02x}")


def decode_value(
    data: bytes | bytearray | memoryview,
    *,
    max_items: int = DEFAULT_MAX_ITEMS,
    max_bytes: int = DEFAULT_MAX_PAYLOAD,
):
    """Decode one canonical UBIN value with bounded resource limits."""
    if max_items < 1:
        raise ValueError("max_items must be at least 1")
    if max_bytes < 0:
        raise ValueError("max_bytes must be non-negative")
    raw = bytes(data)
    if len(raw) > max_bytes:
        raise ProtocolDecodeError("UBIN value exceeds byte limit")
    reader = _Reader(raw, max_items=max_items)
    value = reader.value()
    if reader.offset != len(reader.data):
        raise ProtocolDecodeError("trailing bytes after UBIN value")
    return value


def encode_envelope(payload: bytes | bytearray | memoryview, *, message_type: int = MESSAGE_TYPE_VALUE, flags: int = 0) -> bytes:
    """Frame payload bytes in the fixed 12-byte UBIN 2 envelope."""
    raw = bytes(payload)
    if len(raw) > 0xFFFFFFFF:
        raise OverflowError("UBIN envelope payload must fit uint32")
    if not 0 <= message_type <= 255:
        raise ValueError("message_type must fit uint8")
    if not 0 <= flags <= 0xFFFF:
        raise ValueError("flags must fit uint16")
    return _HEADER.pack(MAGIC, PROTOCOL_VERSION, message_type, flags, len(raw)) + raw


def decode_envelope(data: bytes | bytearray | memoryview, *, max_payload: int = DEFAULT_MAX_PAYLOAD):
    """Decode and structurally validate one complete UBIN 2 envelope."""
    if max_payload < 0:
        raise ValueError("max_payload must be non-negative")
    raw = bytes(data)
    if len(raw) < _HEADER.size:
        raise ProtocolDecodeError("truncated UBIN envelope")
    magic, version, message_type, flags, size = _HEADER.unpack(raw[:_HEADER.size])
    if magic != MAGIC:
        raise ProtocolDecodeError("invalid UBIN envelope magic")
    if version != PROTOCOL_VERSION:
        raise ProtocolDecodeError(f"unsupported UBIN protocol version: {version}")
    if size > max_payload:
        raise ProtocolDecodeError("UBIN envelope exceeds payload limit")
    if len(raw) != _HEADER.size + size:
        raise ProtocolDecodeError("UBIN envelope length mismatch")
    return {
        "version": version,
        "message_type": message_type,
        "flags": flags,
        "payload": raw[_HEADER.size:],
    }


def encode_message(value: Any, *, flags: int = 0) -> bytes:
    """Encode a canonical UBIN value and wrap it as a value message."""
    return encode_envelope(encode_value(value), message_type=MESSAGE_TYPE_VALUE, flags=flags)


def decode_message(
    data: bytes | bytearray | memoryview,
    *,
    max_payload: int = DEFAULT_MAX_PAYLOAD,
    max_items: int = DEFAULT_MAX_ITEMS,
):
    """Decode a UBIN canonical-value message, rejecting other message types."""
    envelope = decode_envelope(data, max_payload=max_payload)
    if envelope["message_type"] != MESSAGE_TYPE_VALUE:
        raise ProtocolDecodeError("UBIN envelope is not a canonical-value message")
    return decode_value(envelope["payload"], max_items=max_items, max_bytes=max_payload)


def conformance_vector() -> dict[str, str]:
    value = {"bytes": b"\x00\x01", "language": "UBIN", "ok": True, "version": 2}
    canonical = encode_value(value)
    envelope = encode_envelope(b"hello UBIN", message_type=MESSAGE_TYPE_VALUE, flags=0)
    message = encode_message(value)
    return {
        "canonical_value_hex": canonical.hex(),
        "envelope_hex": envelope.hex(),
        "canonical_message_hex": message.hex(),
    }


__all__ = [
    "MAGIC", "PROTOCOL_VERSION", "PROTOCOL_STABILITY", "HEADER_SIZE", "MAX_DEPTH",
    "DEFAULT_MAX_PAYLOAD", "DEFAULT_MAX_ITEMS", "MESSAGE_TYPE_VALUE", "MESSAGE_TYPE_BYTES",
    "ProtocolDecodeError", "encode_value", "decode_value", "encode_envelope", "decode_envelope",
    "encode_message", "decode_message", "conformance_vector",
]
