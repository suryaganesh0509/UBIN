# Testing UBIN v1.0.5

This guide is for repository developers and independent validators.

## 1. Fresh environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
```

## 2. Version integrity

```bash
python - <<'PY'
import importlib.metadata
import ubin

print("runtime :", ubin.__version__)
print("metadata:", importlib.metadata.version("ubin"))

assert ubin.__version__ == "1.0.5"
assert importlib.metadata.version("ubin") == "1.0.5"
PY
```

## 3. Test collection / portable node IDs

```bash
pytest --collect-only -q > collected-tests.txt

python - <<'PY'
from pathlib import Path

lines = Path("collected-tests.txt").read_text().splitlines()
tests = [line for line in lines if "::" in line]

assert tests
longest = max(tests, key=len)

print("Collected:", len(tests))
print("Longest test ID:", len(longest))
print("Longest:", longest)

assert len(longest) <= 2048
PY

rm collected-tests.txt
```

## 4. Full regression

```bash
pytest -q
```

v1.0.5 is documentation-focused, so the runtime regression behavior should remain consistent with the v1.0.4 baseline.

## 5. Coverage gate

```bash
pytest -q \
  --cov=ubin \
  --cov-report=term-missing \
  --cov-fail-under=82
```

The enforced threshold is 82%.

## 6. Static and dependency checks

```bash
ruff check src tests fuzz
bandit -r src/ubin -ll -ii
pip-audit
```

## 7. Consumer integration

```bash
python examples/public_consumer_test.py
```

The integration test covers major public flows including:

- package/version metadata
- unknown/custom extension
- reading, hashing and streaming
- bytes-like and stream sources
- local secure container
- wrong-key rejection
- PNG carrier
- wrong-passphrase rejection
- TLS 1.3
- resume
- KRP
- exact sender/receiver content
- CLI

## 8. Manual demonstrations

```bash
python manual_secure_demo.py
python manual_network_demo.py
python manual_resume_demo.py
python manual_krp_demo.py
python manual_image_demo.py
```

## 9. Documentation smoke checks

Run the main documented CLI commands:

```bash
ubin --version
ubin --help
```

Then create a small test file:

```bash
printf 'UBIN documentation smoke test\n' > doc-smoke.custom

ubin info doc-smoke.custom
ubin hash doc-smoke.custom
```

Run Python:

```bash
python - <<'PY'
import ubin

with ubin.open("doc-smoke.custom") as obj:
    assert obj.size > 0
    assert obj.read_at(0, 4) == b"UBIN"
    assert obj.verify(obj.hash())

print("PASS: documentation core examples")
PY
```

## 10. Build distributions

```bash
rm -rf dist build
python -m build
python -m twine check dist/*
```

Expected files:

```text
ubin-1.0.5-py3-none-any.whl
ubin-1.0.5.tar.gz
```

## 11. Clean wheel install

```bash
rm -rf /tmp/ubin-v105-wheel-test
python -m venv /tmp/ubin-v105-wheel-test
/tmp/ubin-v105-wheel-test/bin/python -m pip install --upgrade pip
/tmp/ubin-v105-wheel-test/bin/python -m pip install dist/ubin-1.0.5-py3-none-any.whl
/tmp/ubin-v105-wheel-test/bin/ubin --version
```

Expected:

```text
UBIN 1.0.5
```

## 12. Repository integrity

```bash
git diff --check
git status --short
```

Do not tag until the intended documentation/version changes have passed the full local gate and the candidate commit subsequently passes GitHub CI.
