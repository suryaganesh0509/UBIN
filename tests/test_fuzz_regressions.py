from pathlib import Path
import hashlib
import os

import pytest

from ubin.errors import UbinCarrierError
from ubin.secure.krp import permute_blocks, restore_blocks
from ubin.secure.png_codec import decode_png_to_file, encode_file_to_png


@pytest.mark.parametrize("size", [0, 1, 2, 31, 255, 4097])
def test_mutation_seed_krp_round_trip(size: int):
    seed = hashlib.sha256(f"ubin-seed-{size}".encode()).digest()
    data = (seed * ((size + len(seed) - 1) // len(seed)))[:size]
    key = hashlib.sha256(b"ubin-deterministic-fuzz-key" + seed).digest()
    context = hashlib.sha256(b"ubin-context" + seed).digest()
    block_size = 1 if size < 2 else min(64, max(1, size // 2))

    transformed = permute_blocks(data, key, context=context, block_size=block_size)
    assert len(transformed) == len(data)
    assert restore_blocks(transformed, key, context=context, block_size=block_size) == data


@pytest.mark.parametrize("cut", [1, 2, 7, 31])
def test_png_truncation_mutations_never_publish_output(tmp_path: Path, cut: int):
    source = tmp_path / "payload.bin"
    image = tmp_path / "carrier.png"
    source.write_bytes(os.urandom(16_384))
    encode_file_to_png(source, image, width=128)
    raw = image.read_bytes()
    image.write_bytes(raw[:-cut])
    output = tmp_path / "pixels.bin"

    with pytest.raises(UbinCarrierError):
        decode_png_to_file(image, output)
    assert not output.exists()
