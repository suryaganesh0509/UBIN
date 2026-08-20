# UBIN release process

UBIN v1.0.1 includes GitHub Actions workflows for testing, packaging, security scanning, fuzz-smoke runs, and PyPI Trusted Publishing.

## Release gate

Before creating a tag:

```bash
python -m pip install -e ".[dev,security]"
pytest -q
pytest -q --cov=ubin --cov-report=term-missing --cov-fail-under=82
ruff check src tests fuzz
bandit -r src/ubin -ll -ii
pip-audit
python -m build
python -m twine check dist/*
```

On Linux with the optional fuzzer installed:

```bash
python -m pip install -e ".[dev,fuzz]"
python fuzz/fuzz_krp.py -runs=10000 -max_len=8192
python fuzz/fuzz_png_parser.py -runs=5000 -max_len=8192
```

## PyPI Trusted Publishing

The repository workflow `.github/workflows/publish-pypi.yml` uses GitHub OIDC; no long-lived PyPI API token is stored in the repository.

Before the first publication, configure a PyPI Trusted Publisher (or Pending Publisher) for:

- owner: `suryaganesh0509`
- repository: `UBIN`
- workflow: `publish-pypi.yml`
- environment: `pypi`

Also create a GitHub environment named `pypi`; protection rules/reviewer approval are recommended.

Then create the version tag and publish a GitHub Release. The release event builds the wheel/sdist and publishes them through OIDC.

## Version integrity

Never move an already published version tag. Fixes after v1.0.1 become v1.0.2 or a later semantic version.
