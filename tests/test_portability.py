from pathlib import Path
import os

import pytest

import ubin
from ubin.errors import UbinCarrierError
from ubin.secure import png_codec
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



def test_png_error_cleanup_closes_fd_before_windows_style_unlink(
    tmp_path: Path,
    monkeypatch,
):
    """Malformed PNG cleanup must close temp FDs before unlinking."""
    candidate = tmp_path / "not-a-png.bin"
    output = tmp_path / "pixels.bin"
    candidate.write_bytes(b"definitely not a PNG")

    real_mkstemp = png_codec.tempfile.mkstemp
    real_unlink = Path.unlink
    tracked_fds: list[int] = []

    def tracking_mkstemp(*args, **kwargs):
        fd, name = real_mkstemp(*args, **kwargs)
        tracked_fds.append(fd)
        return fd, name

    def windows_style_unlink(path_obj, *args, **kwargs):
        for fd in tracked_fds:
            try:
                os.fstat(fd)
            except OSError:
                continue

            raise PermissionError(
                "simulated Windows: cannot unlink an open file"
            )

        return real_unlink(path_obj, *args, **kwargs)

    monkeypatch.setattr(
        png_codec.tempfile,
        "mkstemp",
        tracking_mkstemp,
    )
    monkeypatch.setattr(
        Path,
        "unlink",
        windows_style_unlink,
    )

    with pytest.raises(UbinCarrierError):
        png_codec.decode_png_to_file(candidate, output)

    assert not output.exists()

    for fd in tracked_fds:
        with pytest.raises(OSError):
            os.fstat(fd)


def test_resume_state_writers_work_without_fchmod(tmp_path, monkeypatch):
    """Platforms without os.fchmod must remain supported."""
    import json

    from ubin.secure import krp_transfer
    from ubin.secure import resume

    monkeypatch.delattr(os, "fchmod", raising=False)

    resume_path = tmp_path / "resume.json"
    krp_path = tmp_path / "krp.json"

    resume._atomic_write_json(resume_path, {"kind": "resume"})
    krp_transfer._atomic_write_json(krp_path, {"kind": "krp"})

    assert json.loads(resume_path.read_text()) == {"kind": "resume"}
    assert json.loads(krp_path.read_text()) == {"kind": "krp"}
