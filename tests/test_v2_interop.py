from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _need(command: str) -> str:
    path = shutil.which(command)
    required = os.environ.get("UBIN_REQUIRE_POLYGLOT") == "1"
    if path is None:
        if required:
            pytest.fail(f"required polyglot tool is missing: {command}")
        pytest.skip(f"{command} is not installed")
    try:
        probe = subprocess.run([path, "--version"], capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        if required:
            pytest.fail(f"required polyglot tool is unusable: {command}: {exc}")
        pytest.skip(f"{command} is not usable")
    if probe.returncode != 0:
        if required:
            pytest.fail(f"required polyglot tool failed its version probe: {command}")
        pytest.skip(f"{command} is not usable")
    return path


def test_c_conformance(tmp_path: Path):
    cc = _need("cc")
    output = tmp_path / "c-vector"
    subprocess.run(
        [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "interop/c/ubin_wire.c", "interop/c/test_vector.c", "-lm", "-o", str(output)],
        cwd=ROOT, check=True,
    )
    result = subprocess.run([str(output)], cwd=ROOT, check=True, text=True, capture_output=True)
    assert "v2 stable" in result.stdout


def test_cpp_conformance(tmp_path: Path):
    cxx = _need("c++")
    output = tmp_path / "cpp-vector"
    subprocess.run(
        [cxx, "-std=c++17", "-Wall", "-Wextra", "-Werror", "interop/cpp/test_vector.cpp", "-o", str(output)],
        cwd=ROOT, check=True,
    )
    result = subprocess.run([str(output)], cwd=ROOT, check=True, text=True, capture_output=True)
    assert "v2 stable" in result.stdout


def test_java_conformance(tmp_path: Path):
    javac = _need("javac")
    java = _need("java")
    subprocess.run(
        [javac, "-d", str(tmp_path), "interop/java/io/ubin/UbinWire.java", "interop/java/io/ubin/ProtocolSelfTest.java"],
        cwd=ROOT, check=True,
    )
    result = subprocess.run([java, "-cp", str(tmp_path), "io.ubin.ProtocolSelfTest"], cwd=ROOT, check=True, text=True, capture_output=True)
    assert "v2 stable" in result.stdout
