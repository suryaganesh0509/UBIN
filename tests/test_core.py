import hashlib
from pathlib import Path

import pytest

import ubin
from ubin.errors import UbinClosed, UbinInvalidRange, UbinNotFound


def test_unknown_extension_is_supported(tmp_path: Path):
    payload = b"\x00\x01\x02future-format\xff"
    path = tmp_path / "thing.futureXYZ"
    path.write_bytes(payload)

    with ubin.open(path) as obj:
        assert obj.size == len(payload)
        assert obj.type == "application/octet-stream"
        assert obj.bytes() == payload


def test_extensionless_file_is_supported(tmp_path: Path):
    payload = b"hello"
    path = tmp_path / "NO_EXTENSION"
    path.write_bytes(payload)

    with ubin.open(path) as obj:
        assert obj.read_at(0, 5) == payload


def test_signature_detection_ignores_filename_extension(tmp_path: Path):
    path = tmp_path / "not_a_png.xyz"
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"payload")

    with ubin.open(path) as obj:
        assert obj.type == "image/png"


def test_zero_byte_file(tmp_path: Path):
    path = tmp_path / "empty"
    path.write_bytes(b"")

    with ubin.open(path) as obj:
        assert obj.size == 0
        assert obj.read(10) == b""
        assert list(obj.stream()) == []


def test_read_at_does_not_move_sequential_cursor(tmp_path: Path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"abcdefghij")

    with ubin.open(path) as obj:
        assert obj.read(2) == b"ab"
        before = obj.tell()
        assert obj.read_at(5, 3) == b"fgh"
        assert obj.tell() == before
        assert obj.read(2) == b"cd"


def test_stream_exact_reconstruction(tmp_path: Path):
    payload = bytes(range(256)) * 1000
    path = tmp_path / "large-ish.bin"
    path.write_bytes(payload)

    with ubin.open(path) as obj:
        rebuilt = b"".join(obj.stream(block_size=997))
        assert rebuilt == payload


def test_sha256_and_verify(tmp_path: Path):
    payload = b"ubin" * 10000
    path = tmp_path / "data.bin"
    path.write_bytes(payload)
    expected = hashlib.sha256(payload).hexdigest()

    with ubin.open(path) as obj:
        assert obj.hash() == expected
        assert obj.verify(expected)
        assert not obj.verify("00" * 32)


def test_explicit_whole_file_guard(tmp_path: Path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"0123456789")

    with ubin.open(path) as obj:
        with pytest.raises(UbinInvalidRange):
            obj.bytes(max_bytes=5)


def test_closed_object_rejected(tmp_path: Path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abc")

    obj = ubin.open(path)
    obj.close()

    with pytest.raises(UbinClosed):
        obj.read(1)


def test_missing_source():
    with pytest.raises(UbinNotFound):
        ubin.open("/definitely/not/a/real/ubin/source")


def test_memory_bytes_source_is_supported():
    payload = b"memory-source-ubin"
    with ubin.open(payload, name="packet.future") as obj:
        assert obj.name == "packet.future"
        assert obj.size == len(payload)
        assert obj.read_at(0, 6) == b"memory"
        assert obj.bytes() == payload
        assert obj.info().path == "<memory:packet.future>"


def test_bytearray_and_memoryview_sources_are_supported():
    payload = bytearray(b"abcdef")
    with ubin.open(payload) as obj:
        assert obj.read(3) == b"abc"
        assert obj.read_at(3, 3) == b"def"
    with ubin.open(memoryview(b"xyz")) as obj:
        assert obj.bytes() == b"xyz"


def test_seekable_binary_stream_is_supported_without_being_closed():
    import io

    stream = io.BytesIO(b"stream-data")
    with ubin.open(stream, name="stream.custom") as obj:
        assert obj.size == 11
        assert obj.read(6) == b"stream"
        before = obj.tell()
        assert obj.read_at(7, 4) == b"data"
        assert obj.tell() == before
    assert not stream.closed


def test_text_stream_is_rejected():
    import io

    with pytest.raises(TypeError):
        ubin.open(io.StringIO("not binary"))
