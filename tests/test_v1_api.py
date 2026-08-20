from pathlib import Path

import ubin


def test_final_public_api_symbols():
    assert ubin.__version__ == "1.0.0"
    for name in ("open", "secure", "decrypt", "secure_server", "to_image", "from_image"):
        assert callable(getattr(ubin, name))


def test_no_numpy_required_for_core_import():
    # UBIN works directly on bytes/files and intentionally has no mandatory NumPy dependency.
    import tomllib
    project = Path(__file__).resolve().parents[1]
    data = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    reqs = data["project"].get("dependencies", [])
    assert not any(req.lower().startswith("numpy") for req in reqs)
