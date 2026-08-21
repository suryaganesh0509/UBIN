# Testing UBIN v2.0.0

This guide reproduces the stable release gates.

## Fresh environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
python -m pip check
```

## Version integrity

```bash
python - <<'PY'
import importlib.metadata
import ubin

assert ubin.__version__ == "2.0.0"
assert importlib.metadata.version("ubin") == "2.0.0"
assert ubin.protocol.PROTOCOL_VERSION == 2
assert ubin.protocol.PROTOCOL_STABILITY == "stable"
print("PASS: version integrity")
PY
```

## Full Python regression

```bash
python -m pytest -q
```

All tests must pass. A release is blocked by any failure in an established v1 compatibility path or a new v2 path.

## Coverage

```bash
python -m pytest -q --cov=ubin --cov-report=term-missing --cov-report=xml:coverage.xml --cov-fail-under=82
```

The current minimum is 82%. Raising coverage is encouraged; lowering the gate for a release requires an explicit reviewed decision.

## Polyglot conformance

```bash
python -m pytest -q tests/test_v2_protocol.py tests/test_v2_interop.py
```

This compiles/runs the available C, C++, and Java reference implementations and compares behavior with the shared stable vectors. GitHub CI installs the required toolchains so these tests cannot be skipped in the release gate.

## Static/security checks

```bash
ruff check src tests fuzz
bandit -r src/ubin -ll -ii
pip-audit
```

GitHub additionally runs Semgrep and uploads machine-readable reports.

## Portable CI matrix

GitHub CI covers:

```text
Ubuntu / macOS / Windows
×
Python 3.10 / 3.11 / 3.12 / 3.13 / 3.14
```

The polyglot conformance job separately compiles C11, C++17, and Java 17 references.

## Build

```bash
rm -rf dist build
python -m build
python -m twine check dist/*
```

Expected release artifacts:

```text
ubin-2.0.0-py3-none-any.whl
ubin-2.0.0.tar.gz
```

## Clean wheel install outside repository

```bash
python3 -m venv /tmp/ubin-v2-wheel
/tmp/ubin-v2-wheel/bin/python -m pip install --upgrade pip
/tmp/ubin-v2-wheel/bin/python -m pip install dist/ubin-2.0.0-py3-none-any.whl
cd /tmp
/tmp/ubin-v2-wheel/bin/python -c "import ubin; assert ubin.__version__ == '2.0.0'; print(ubin.__file__)"
/tmp/ubin-v2-wheel/bin/ubin --version
```

The module path must point into the clean environment's `site-packages`, not the repository.

## Public-consumer and manual demonstrations

```bash
python examples/public_consumer_test.py
python manual_secure_demo.py
python manual_network_demo.py
python manual_resume_demo.py
python manual_krp_demo.py
python manual_image_demo.py
```

## Repository integrity

```bash
git diff --check
git status --short
```

Do not tag until CI, Package, Security, and polyglot conformance are green on the exact release commit. After publication, verify a fresh no-cache PyPI install before declaring 2.0.0 released and frozen.
