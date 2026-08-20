import binascii
import hashlib
import os
from pathlib import Path
import struct

import pytest

import ubin
from ubin.errors import UbinAuthenticationError, UbinCarrierError, UbinOutputExists
from ubin.secure.krp import permute_file, restore_file

PASS = "correct horse battery staple"


@pytest.mark.parametrize("size", [0, 1, 17, 4095, 4096, 4097, 100_000, 2 * 1024 * 1024 + 123])
def test_image_carrier_exact_round_trip(tmp_path: Path, size: int):
    payload = os.urandom(size)
    source = tmp_path / "anything.futureXYZ"
    image = tmp_path / "anything.ubin.png"
    restored = tmp_path / "restored.futureXYZ"
    source.write_bytes(payload)

    packed = ubin.to_image(source, image, passphrase=PASS, width=257)
    unpacked = ubin.from_image(image, restored, passphrase=PASS)

    assert image.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert restored.read_bytes() == payload
    assert packed.original_size == size
    assert unpacked.restored_size == size
    assert packed.sha256 == unpacked.sha256 == hashlib.sha256(payload).hexdigest()
    assert packed.layout == "krp+png"


def test_image_carrier_wrong_passphrase_never_publishes(tmp_path: Path):
    source = tmp_path / "secret.bin"
    source.write_bytes(os.urandom(30_000))
    image = tmp_path / "secret.png"
    output = tmp_path / "wrong.bin"
    ubin.to_image(source, image, passphrase=PASS)

    with pytest.raises(UbinAuthenticationError):
        ubin.from_image(image, output, passphrase="this is definitely wrong")
    assert not output.exists()


def test_image_carrier_tampered_png_crc_is_rejected(tmp_path: Path):
    source = tmp_path / "data.bin"
    source.write_bytes(os.urandom(50_000))
    image = tmp_path / "data.png"
    ubin.to_image(source, image, passphrase=PASS)

    raw = bytearray(image.read_bytes())
    marker = raw.find(b"IDAT")
    assert marker > 0
    data_start = marker + 4
    raw[data_start + 10] ^= 0x01
    image.write_bytes(raw)

    with pytest.raises(UbinCarrierError):
        ubin.from_image(image, tmp_path / "restored.bin", passphrase=PASS)


def test_image_carrier_truncated_png_is_rejected(tmp_path: Path):
    source = tmp_path / "data.bin"
    source.write_bytes(os.urandom(10_000))
    image = tmp_path / "data.png"
    ubin.to_image(source, image, passphrase=PASS)
    image.write_bytes(image.read_bytes()[:-20])

    with pytest.raises(UbinCarrierError):
        ubin.from_image(image, tmp_path / "restored.bin", passphrase=PASS)


def test_image_carrier_rejects_existing_output(tmp_path: Path):
    source = tmp_path / "data.bin"
    source.write_bytes(b"abc" * 1000)
    image = tmp_path / "data.png"
    out = tmp_path / "out.bin"
    out.write_bytes(b"do not overwrite")
    ubin.to_image(source, image, passphrase=PASS)

    with pytest.raises(UbinOutputExists):
        ubin.from_image(image, out, passphrase=PASS)
    assert out.read_bytes() == b"do not overwrite"


def test_image_carrier_randomizes_same_source(tmp_path: Path):
    source = tmp_path / "same.bin"
    source.write_bytes(b"same data" * 5000)
    a = tmp_path / "a.png"
    b = tmp_path / "b.png"
    ubin.to_image(source, a, passphrase=PASS)
    ubin.to_image(source, b, passphrase=PASS)
    assert a.read_bytes() != b.read_bytes()


def test_image_carrier_default_restore_name(tmp_path: Path):
    source_dir = tmp_path / "source"
    carrier_dir = tmp_path / "carrier"
    source_dir.mkdir()
    carrier_dir.mkdir()
    source = source_dir / "original.custom"
    source.write_bytes(b"default destination")
    image = carrier_dir / "artifact.png"
    ubin.to_image(source, image, passphrase=PASS)

    receipt = ubin.from_image(image, passphrase=PASS)
    assert receipt.output == carrier_dir / "original.custom"
    assert receipt.output.read_bytes() == source.read_bytes()


def test_image_passphrase_minimum_length(tmp_path: Path):
    source = tmp_path / "a"
    source.write_bytes(b"x")
    with pytest.raises(ValueError):
        ubin.to_image(source, tmp_path / "a.png", passphrase="short")


@pytest.mark.parametrize("size", [0, 1, 255, 256, 4095, 4096, 4097, 65_537])
def test_krp_file_round_trip_bounded(tmp_path: Path, size: int):
    source = tmp_path / "source.bin"
    permuted = tmp_path / "permuted.bin"
    restored = tmp_path / "restored.bin"
    data = os.urandom(size)
    source.write_bytes(data)
    key = os.urandom(32)
    context = b"v1-final-file-krp"

    assert permute_file(source, permuted, key, context=context, block_size=256) == size
    assert permuted.stat().st_size == size
    assert restore_file(permuted, restored, key, context=context, block_size=256) == size
    assert restored.read_bytes() == data


def test_image_carrier_detected_as_png_by_ubin_core(tmp_path: Path):
    source = tmp_path / "x.unknown"
    source.write_bytes(b"hello")
    image = tmp_path / "x.png"
    ubin.to_image(source, image, passphrase=PASS)
    with ubin.open(image) as obj:
        assert obj.type == "image/png"


def test_image_receipts_expose_no_raw_keys(tmp_path: Path):
    source = tmp_path / "data.bin"
    source.write_bytes(os.urandom(12_000))
    image = tmp_path / "data.png"
    packed = ubin.to_image(source, image, passphrase=PASS)
    restored = ubin.from_image(image, tmp_path / "restored.bin", passphrase=PASS)
    assert not hasattr(packed, "key")
    assert not hasattr(packed, "permutation_key")
    assert not hasattr(restored, "key")


def test_reencoded_png_with_nonzero_filter_is_rejected(tmp_path: Path):
    import zlib

    source = tmp_path / "data.bin"
    source.write_bytes(os.urandom(20_000))
    image = tmp_path / "data.png"
    ubin.to_image(source, image, passphrase=PASS)
    raw = image.read_bytes()

    sig = raw[:8]
    pos = 8
    ihdr_chunk = None
    idat_data = bytearray()
    chunks_after = []
    while pos < len(raw):
        length = struct.unpack(">I", raw[pos:pos+4])[0]
        ctype = raw[pos+4:pos+8]
        data = raw[pos+8:pos+8+length]
        full = raw[pos:pos+12+length]
        pos += 12 + length
        if ctype == b"IHDR":
            ihdr_chunk = full
        elif ctype == b"IDAT":
            idat_data.extend(data)
        elif ctype == b"IEND":
            chunks_after.append(full)
            break
        else:
            chunks_after.append(full)

    filtered = bytearray(zlib.decompress(bytes(idat_data)))
    assert filtered[0] == 0
    filtered[0] = 1
    compressed = zlib.compress(bytes(filtered), level=1)

    def chunk(t, d):
        crc = binascii.crc32(t)
        crc = binascii.crc32(d, crc) & 0xFFFFFFFF
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", crc)

    image.write_bytes(sig + ihdr_chunk + chunk(b"IDAT", compressed) + chunk(b"IEND", b""))

    with pytest.raises(UbinCarrierError, match="filtered|transformed"):
        ubin.from_image(image, tmp_path / "restored.bin", passphrase=PASS)
