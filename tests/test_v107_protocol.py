from __future__ import annotations

import math
import struct

import pytest
import ubin


def test_protocol_vector_is_stable():
    vector = ubin.protocol.conformance_vector()
    assert vector["envelope_hex"] == "55424e32020100000000000a68656c6c6f205542494e"
    assert vector["canonical_value_hex"].startswith("3100000004")


@pytest.mark.parametrize(
    "value",
    [None, False, True, 0, -1, 2**63 - 1, -(2**63), 0.0, -3.25, b"", b"abc", "", "UBIN", "తెలుగు", [], [1, "x"], {}, {"b": 2, "a": 1}],
)
def test_canonical_round_trip(value):
    encoded = ubin.protocol.encode_value(value)
    assert ubin.protocol.decode_value(encoded) == value


def test_map_order_is_canonical():
    first = ubin.protocol.encode_value({"z": 1, "a": 2})
    second = ubin.protocol.encode_value({"a": 2, "z": 1})
    assert first == second


def test_non_string_map_key_rejected():
    with pytest.raises(TypeError):
        ubin.protocol.encode_value({1: "bad"})


def test_large_integer_rejected():
    with pytest.raises(OverflowError):
        ubin.protocol.encode_value(2**63)


@pytest.mark.parametrize("value", [math.inf, -math.inf, math.nan])
def test_nonfinite_float_rejected(value):
    with pytest.raises(ValueError):
        ubin.protocol.encode_value(value)


def test_unknown_value_tag_rejected():
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_value(b"\xff")


def test_truncated_value_rejected():
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_value(b"\x10\x00")


def test_trailing_value_bytes_rejected():
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_value(b"\x00\x00")


def test_noncanonical_map_order_rejected():
    # tag map, count 2, key z/value 1, key a/value 2
    raw = b"\x31" + struct.pack(">I", 2)
    raw += ubin.protocol.encode_value("z") + ubin.protocol.encode_value(1)
    raw += ubin.protocol.encode_value("a") + ubin.protocol.encode_value(2)
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_value(raw)


def test_envelope_round_trip():
    encoded = ubin.protocol.encode_envelope(b"hello UBIN", message_type=7, flags=3)
    decoded = ubin.protocol.decode_envelope(encoded)
    assert decoded == {"version": 2, "message_type": 7, "flags": 3, "payload": b"hello UBIN"}


def test_envelope_magic_rejected():
    raw = bytearray(ubin.protocol.encode_envelope(b"x"))
    raw[0] = 0
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_envelope(raw)


def test_envelope_version_rejected():
    raw = bytearray(ubin.protocol.encode_envelope(b"x"))
    raw[4] = 9
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_envelope(raw)


def test_envelope_truncation_rejected():
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_envelope(b"UBN2")


def test_envelope_size_limit():
    encoded = ubin.protocol.encode_envelope(b"1234")
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_envelope(encoded, max_payload=3)


def test_envelope_invalid_fields():
    with pytest.raises(ValueError):
        ubin.protocol.encode_envelope(b"x", message_type=256)
    with pytest.raises(ValueError):
        ubin.protocol.encode_envelope(b"x", flags=65536)
