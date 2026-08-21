from __future__ import annotations

import math
import struct
from typing import Any

MAGIC = b"UBN2"
PROTOCOL_VERSION = 2
MAX_DEPTH = 64
DEFAULT_MAX_PAYLOAD = 64 * 1024 * 1024
_HEADER = struct.Struct(">4sBBHI")


class ProtocolDecodeError(ValueError):
    pass


def _u32(value: int) -> bytes:
    if value < 0 or value > 0xFFFFFFFF:
        raise OverflowError("value does not fit UBIN u32")
    return struct.pack(">I", value)


def encode_value(value: Any, *, _depth: int = 0) -> bytes:
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
        return b"\x30" + _u32(len(value)) + b"".join(
            encode_value(item, _depth=_depth + 1) for item in value
        )
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
            return [self.value(depth + 1) for _ in range(count)]
        if tag == 0x31:
            count = struct.unpack(">I", self.take(4))[0]
            result = {}
            previous = None
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


def decode_value(data: bytes | bytearray | memoryview, *, max_items: int = 1_000_000):
    reader = _Reader(bytes(data), max_items=max_items)
    value = reader.value()
    if reader.offset != len(reader.data):
        raise ProtocolDecodeError("trailing bytes after UBIN value")
    return value


def encode_envelope(payload: bytes | bytearray | memoryview, *, message_type: int = 1, flags: int = 0) -> bytes:
    raw = bytes(payload)
    if not 0 <= message_type <= 255:
        raise ValueError("message_type must fit uint8")
    if not 0 <= flags <= 0xFFFF:
        raise ValueError("flags must fit uint16")
    return _HEADER.pack(MAGIC, PROTOCOL_VERSION, message_type, flags, len(raw)) + raw


def decode_envelope(data: bytes | bytearray | memoryview, *, max_payload: int = DEFAULT_MAX_PAYLOAD):
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


def conformance_vector() -> dict[str, str]:
    value = {"bytes": b"\x00\x01", "language": "UBIN", "ok": True, "version": 2}
    canonical = encode_value(value)
    envelope = encode_envelope(b"hello UBIN", message_type=1, flags=0)
    return {
        "canonical_value_hex": canonical.hex(),
        "envelope_hex": envelope.hex(),
    }


__all__ = [
    "MAGIC", "PROTOCOL_VERSION", "ProtocolDecodeError", "encode_value", "decode_value",
    "encode_envelope", "decode_envelope", "conformance_vector",
]
