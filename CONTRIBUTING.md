# Contributing to UBIN

Thanks for testing or improving UBIN.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
```

## Before opening a pull request

```bash
pytest -q
ruff check src tests fuzz
bandit -r src/ubin -ll -ii
python -m build
```

Security-sensitive behavior should include failure-path tests. Never commit real passphrases, private keys, production certificates, user data, `.ubs` outputs, or resume-state secrets.

## Compatibility

The supported Python floor is 3.10. Python 3.9 reached upstream end-of-life and is intentionally not part of the v1.0.1 CI support claim.
