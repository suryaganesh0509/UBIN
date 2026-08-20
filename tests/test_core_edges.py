import hashlib
import io
from pathlib import Path

import pytest

import ubin
from ubin.core import UbinMemoryObject, UbinStreamObject
from ubin.errors import UbinClosed, UbinInvalidRange, UbinNotAFile


def test_file_info_seek_zero_ranges_and_properties(tmp_path: Path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    obj = ubin.open(path)
    assert obj.closed is False
    assert obj.path == path
    assert obj.info().size == 6
    assert obj.seek(2) == 2
    assert obj.tell() == 2
    assert obj.read_at(6, 10) == b""
    assert obj.read_at(1, 0) == b""
    obj.close()
    assert obj.closed is True
    obj.close()


def test_file_invalid_ranges_and_hash_algorithm(tmp_path: Path):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdef")
    with ubin.open(path) as obj:
        for operation in (
            lambda: obj.read(-1),
            lambda: obj.seek(-1),
            lambda: obj.read_at(-1, 1),
            lambda: obj.read_at(0, -1),
            lambda: list(obj.stream(block_size=0)),
            lambda: list(obj.stream(start=-1)),
            lambda: obj.bytes(max_bytes=-1),
            lambda: obj.hash(block_size=0),
        ):
            with pytest.raises(UbinInvalidRange):
                operation()
        with pytest.raises(ValueError, match="unsupported hash algorithm"):
            obj.hash("not-a-real-hash")


def test_directory_is_not_a_file(tmp_path: Path):
    with pytest.raises(UbinNotAFile):
        ubin.open(tmp_path)


def test_top_level_rejects_non_binary_source_object():
    with pytest.raises(TypeError):
        ubin.open(object())


def test_memory_cursor_hash_verify_and_close():
    payload = b"0123456789"
    obj = UbinMemoryObject(payload, name="x.bin")
    assert obj.path is None
    assert obj.type == "application/octet-stream"
    assert obj.closed is False
    assert obj.seek(3) == 3
    assert obj.tell() == 3
    assert obj.read(2) == b"34"
    assert obj.read_at(99, 1) == b""
    assert b"".join(obj.stream(block_size=3, start=2)) == payload[2:]
    expected = hashlib.sha256(payload).hexdigest()
    assert obj.verify(expected)
    obj.close()
    assert obj.closed is True
    with pytest.raises(UbinClosed):
        obj.info()


def test_memory_invalid_ranges_and_hash_algorithm():
    obj = UbinMemoryObject(b"abcdef")
    for operation in (
        lambda: obj.read(-1),
        lambda: obj.seek(-1),
        lambda: obj.read_at(-1, 1),
        lambda: obj.read_at(0, -1),
        lambda: list(obj.stream(block_size=0)),
        lambda: list(obj.stream(start=-1)),
        lambda: obj.bytes(max_bytes=2),
        lambda: obj.hash(block_size=0),
    ):
        with pytest.raises(UbinInvalidRange):
            operation()
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        obj.hash("not-a-real-hash")
    obj.close()


def test_memory_object_rejects_non_buffer_directly():
    with pytest.raises(TypeError):
        UbinMemoryObject(object())


def test_stream_full_api_and_close_semantics():
    payload = b"stream-payload"
    stream = io.BytesIO(payload)
    obj = UbinStreamObject(stream, name="folder/name.custom")
    assert obj.name == "name.custom"
    assert obj.path is None
    assert obj.size == len(payload)
    assert obj.closed is False
    assert obj.info().path == "<stream:name.custom>"
    assert obj.seek(1) == 1
    assert obj.tell() == 1
    assert obj.read(3) == b"tre"
    assert obj.read_at(len(payload), 1) == b""
    assert obj.bytes() == payload
    expected = hashlib.sha256(payload).hexdigest()
    assert obj.hash() == expected
    assert obj.verify(expected.upper())
    obj.close()
    assert obj.closed is True
    assert stream.closed is False
    with pytest.raises(UbinClosed):
        obj.read(1)


def test_stream_invalid_ranges_limits_and_hash_algorithm():
    obj = UbinStreamObject(io.BytesIO(b"abcdef"))
    for operation in (
        lambda: obj.read(-1),
        lambda: obj.seek(-1),
        lambda: obj.read_at(-1, 1),
        lambda: obj.read_at(0, -1),
        lambda: list(obj.stream(block_size=0)),
        lambda: list(obj.stream(start=-1)),
        lambda: obj.bytes(max_bytes=2),
    ):
        with pytest.raises(UbinInvalidRange):
            operation()
    with pytest.raises(ValueError, match="unsupported hash algorithm"):
        obj.hash("not-a-real-hash")


def test_stream_object_directly_rejects_missing_methods():
    with pytest.raises(TypeError):
        UbinStreamObject(object())


def test_stream_read_must_return_bytes():
    class BadStream:
        def __init__(self):
            self.pos = 0

        def tell(self):
            return self.pos

        def seek(self, offset, whence=0):
            if whence == 2:
                self.pos = 1
            else:
                self.pos = offset
            return self.pos

        def read(self, length):
            return "x"

    with pytest.raises(TypeError, match="binary mode"):
        UbinStreamObject(BadStream())


def test_stream_read_at_restores_cursor_on_bytesio():
    stream = io.BytesIO(b"abcdefgh")
    obj = UbinStreamObject(stream)
    obj.seek(5)
    assert obj.read_at(1, 3) == b"bcd"
    assert obj.tell() == 5
