from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest
import ubin


def test_release_and_protocol_versions_are_stable():
    assert ubin.__version__ == "2.0.0"
    assert ubin.protocol.PROTOCOL_VERSION == 2
    assert ubin.protocol.PROTOCOL_STABILITY == "stable"


def test_shared_conformance_vectors_match_python_reference():
    path = Path(__file__).resolve().parents[1] / "interop" / "conformance" / "vectors.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))
    assert ubin.protocol.conformance_vector() == vectors


def test_value_message_round_trip():
    value = {"a": [1, True, None], "b": b"bytes", "text": "తెలుగు"}
    encoded = ubin.protocol.encode_message(value)
    assert ubin.protocol.decode_message(encoded) == value


def test_value_message_rejects_wrong_message_type():
    encoded = ubin.protocol.encode_envelope(b"raw", message_type=2)
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_message(encoded)


def test_decode_value_limits_are_validated():
    with pytest.raises(ValueError):
        ubin.protocol.decode_value(b"\x00", max_items=0)
    with pytest.raises(ValueError):
        ubin.protocol.decode_value(b"\x00", max_bytes=-1)
    with pytest.raises(ubin.protocol.ProtocolDecodeError):
        ubin.protocol.decode_value(b"\x20\x00\x00\x00\x01x", max_bytes=5)


def test_declared_huge_list_is_rejected_before_iteration():
    raw = b"\x30" + struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(ubin.protocol.ProtocolDecodeError, match="item limit"):
        ubin.protocol.decode_value(raw, max_items=100)


def test_declared_huge_map_is_rejected_before_iteration():
    raw = b"\x31" + struct.pack(">I", 0xFFFFFFFF)
    with pytest.raises(ubin.protocol.ProtocolDecodeError, match="item limit"):
        ubin.protocol.decode_value(raw, max_items=100)


def test_envelope_limit_argument_is_validated():
    encoded = ubin.protocol.encode_envelope(b"")
    with pytest.raises(ValueError):
        ubin.protocol.decode_envelope(encoded, max_payload=-1)


def test_invalid_utf8_is_rejected():
    raw = b"\x21" + struct.pack(">I", 1) + b"\xff"
    with pytest.raises(ubin.protocol.ProtocolDecodeError, match="UTF-8"):
        ubin.protocol.decode_value(raw)


def test_duplicate_canonical_map_key_is_rejected():
    key = ubin.protocol.encode_value("a")
    raw = b"\x31" + struct.pack(">I", 2) + key + b"\x00" + key + b"\x00"
    with pytest.raises(ubin.protocol.ProtocolDecodeError, match="canonical order"):
        ubin.protocol.decode_value(raw)
