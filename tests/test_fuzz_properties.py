from pathlib import Path
import tempfile

import pytest

from ubin.errors import UbinCarrierError
from ubin.secure.krp import permute_blocks, restore_blocks
from ubin.secure.png_codec import decode_png_to_file, encode_file_to_png

hypothesis = pytest.importorskip("hypothesis")
given = hypothesis.given
settings = hypothesis.settings
st = hypothesis.strategies


@given(
    data=st.binary(max_size=32_768),
    key=st.binary(min_size=16, max_size=64),
    context=st.binary(max_size=128),
    block_size=st.integers(min_value=1, max_value=2048),
)
@settings(max_examples=120, deadline=None)
def test_property_krp_round_trip_is_exact(data, key, context, block_size):
    transformed = permute_blocks(data, key, context=context, block_size=block_size)
    restored = restore_blocks(transformed, key, context=context, block_size=block_size)
    assert restored == data
    assert len(transformed) == len(data)


@given(
    data=st.binary(min_size=8, max_size=16_384),
    key=st.binary(min_size=16, max_size=64),
    context_a=st.binary(min_size=1, max_size=64),
    context_b=st.binary(min_size=1, max_size=64),
)
@settings(max_examples=80, deadline=None)
def test_property_krp_contexts_still_restore_exactly(data, key, context_a, context_b):
    block_size = max(1, min(256, len(data) // 4 or 1))
    a = permute_blocks(data, key, context=context_a, block_size=block_size)
    b = permute_blocks(data, key, context=context_b, block_size=block_size)
    assert restore_blocks(a, key, context=context_a, block_size=block_size) == data
    assert restore_blocks(b, key, context=context_b, block_size=block_size) == data


@given(payload=st.binary(max_size=64_000), width=st.integers(min_value=1, max_value=512))
@settings(max_examples=60, deadline=None)
def test_property_png_codec_round_trip(payload: bytes, width: int):
    # Hypothesis executes this test many times. A pytest function-scoped
    # tmp_path fixture would be shared across generated examples, so create
    # fresh filesystem state inside every individual Hypothesis example.
    with tempfile.TemporaryDirectory(prefix="ubin-hypothesis-png-") as tmp_name:
        tmp_path = Path(tmp_name)
        source = tmp_path / "payload.bin"
        image = tmp_path / "carrier.png"
        restored = tmp_path / "restored.bin"
        source.write_bytes(payload)

        info = encode_file_to_png(source, image, width=width)
        decoded = decode_png_to_file(image, restored)

        assert restored.read_bytes()[: len(payload)] == payload
        assert decoded.width == info.width
        assert decoded.height == info.height
        assert decoded.payload_capacity >= len(payload)


@given(data=st.binary(max_size=8192))
@settings(max_examples=150, deadline=None)
def test_property_arbitrary_png_bytes_fail_closed(data: bytes):
    # Keep every generated parser input isolated. This avoids state leaking
    # between examples and intentionally satisfies Hypothesis' fixture health
    # check instead of suppressing it.
    with tempfile.TemporaryDirectory(prefix="ubin-hypothesis-malformed-png-") as tmp_name:
        tmp_path = Path(tmp_name)
        candidate = tmp_path / "candidate.png"
        output = tmp_path / "pixels.bin"
        candidate.write_bytes(data)

        try:
            decode_png_to_file(candidate, output)
        except UbinCarrierError:
            assert not output.exists()
        else:
            assert output.is_file()
