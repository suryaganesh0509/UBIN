from pathlib import Path

import ubin


def test_final_public_api_symbols():
    assert ubin.__version__ == "1.0.6"
    for name in ("open", "secure", "decrypt", "secure_server", "to_image", "from_image"):
        assert callable(getattr(ubin, name))


def test_no_numpy_required_for_core_import():
    # Keep this test Python 3.10-compatible: tomllib is only in the stdlib from 3.11.
    project = Path(__file__).resolve().parents[1]
    text = (project / "pyproject.toml").read_text(encoding="utf-8")
    project_section = text.split("[project]", 1)[1].split("\n[", 1)[0].lower()
    dependency_block = project_section.split("dependencies", 1)[1].split("]", 1)[0]
    assert "numpy" not in dependency_block
