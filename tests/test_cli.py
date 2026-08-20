import json
import os
from pathlib import Path
import subprocess
import sys


def _run(project: Path, *args, env=None):
    merged = os.environ.copy()
    merged["PYTHONPATH"] = str(project / "src")
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, "-m", "ubin.cli", *args],
        cwd=project,
        env=merged,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_version():
    project = Path(__file__).resolve().parents[1]
    result = _run(project, "--version")
    assert result.returncode == 0
    assert "UBIN 1.0.1" in result.stdout


def test_cli_info_and_hash(tmp_path: Path):
    project = Path(__file__).resolve().parents[1]
    source = tmp_path / "sample.future"
    source.write_bytes(b"hello cli")

    info = _run(project, "info", str(source))
    assert info.returncode == 0
    parsed = json.loads(info.stdout)
    assert parsed["name"] == "sample.future"
    assert parsed["size"] == 9

    digest = _run(project, "hash", str(source))
    assert digest.returncode == 0
    assert len(digest.stdout.strip()) == 64


def test_cli_image_pack_restore_with_environment_passphrase(tmp_path: Path):
    project = Path(__file__).resolve().parents[1]
    source = tmp_path / "data.bin"
    image = tmp_path / "data.png"
    restored = tmp_path / "restored.bin"
    source.write_bytes(os.urandom(20_000))
    env = {"UBIN_TEST_PASS": "command line demo secret"}

    packed = _run(
        project,
        "image-pack", str(source), str(image),
        "--passphrase-env", "UBIN_TEST_PASS",
        env=env,
    )
    assert packed.returncode == 0, packed.stderr
    assert image.exists()

    unpacked = _run(
        project,
        "image-restore", str(image), str(restored),
        "--passphrase-env", "UBIN_TEST_PASS",
        env=env,
    )
    assert unpacked.returncode == 0, unpacked.stderr
    assert restored.read_bytes() == source.read_bytes()
