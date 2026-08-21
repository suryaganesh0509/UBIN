# UBIN v2.0.0 Local Release Validation

Run from a clean checkout of the intended v2.0.0 release commit. Stop at the first failure.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
python -m pip check
```

Core release gate:

```bash
python -m pytest -q
python -m pytest -q --cov=ubin --cov-report=term-missing --cov-fail-under=82
python -m compileall -q src/ubin
ruff check src tests fuzz
bandit -r src/ubin -ll -ii
pip-audit
```

Polyglot conformance:

```bash
python -m pytest -q tests/test_v2_protocol.py tests/test_v2_interop.py
```

Build/install gate:

```bash
rm -rf dist build
python -m build
python -m twine check dist/*
python3 -m venv /tmp/ubin-v2-wheel
/tmp/ubin-v2-wheel/bin/python -m pip install --upgrade pip
/tmp/ubin-v2-wheel/bin/python -m pip install dist/ubin-2.0.0-py3-none-any.whl
cd /tmp
/tmp/ubin-v2-wheel/bin/python -c "import ubin; assert ubin.__version__ == '2.0.0'; print(ubin.__file__)"
/tmp/ubin-v2-wheel/bin/ubin --version
```

The GitHub release must additionally pass the complete OS/Python matrix, Package, Security, polyglot conformance, Trusted PyPI publication, and a fresh `--no-cache-dir` public PyPI installation.
