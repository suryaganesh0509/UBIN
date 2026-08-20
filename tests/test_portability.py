from pathlib import Path
import os

import ubin
from ubin.secure.krp import permute_file, restore_file


def test_core_positioned_read_fallback_without_pread(tmp_path: Path, monkeypatch):
    path = tmp_path / "data.bin"
    path.write_bytes(b"abcdefghij")
    monkeypatch.delattr(os, "pread", raising=False)

    with ubin.open(path) as obj:
        obj.seek(4)
        assert obj.read_at(1, 3) == b"bcd"
        assert obj.tell() == 4


def test_krp_file_fallback_without_pread_or_pwrite(tmp_path: Path, monkeypatch):
    source = tmp_path / "source.bin"
    permuted = tmp_path / "permuted.bin"
    restored = tmp_path / "restored.bin"
    payload = bytes(range(251)) * 50
    source.write_bytes(payload)

    monkeypatch.delattr(os, "pread", raising=False)
    monkeypatch.delattr(os, "pwrite", raising=False)

    key = bytes(range(32))
    context = b"cross-platform-fallback"
    permute_file(source, permuted, key, context=context, block_size=257)
    restore_file(permuted, restored, key, context=context, block_size=257)

    assert restored.read_bytes() == payload
