from __future__ import annotations

import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

import ubin

ROOT = Path(__file__).resolve().parents[1]


def test_project_metadata_matches_runtime_version():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == ubin.__version__ == "2.0.0"


def test_protocol_vector_file_is_exact_reference_output():
    vectors = json.loads((ROOT / "interop/conformance/vectors.json").read_text(encoding="utf-8"))
    assert vectors == ubin.protocol.conformance_vector()


def test_readme_identifies_recommended_stable_release():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "UBIN v2.0.0 — Recommended Stable Universal Runtime" in readme
    assert "python3 -m pip install ubin==2.0.0" in readme
