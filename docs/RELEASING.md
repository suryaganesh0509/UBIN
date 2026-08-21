# UBIN release process

The UBIN v1 release process uses GitHub Actions for testing, packaging, security scanning, fuzz-smoke runs, artifact validation, and PyPI Trusted Publishing.

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

## Candidate-first release flow

Prepare and validate the release locally first.

Push the candidate commit to `main` without creating the version tag.

Require the current candidate commit to pass CI, Package, and Security
workflows before tagging.

Only after those current-commit workflows are green should the immutable
version tag be created and pushed.

A GitHub Release may then be created from that exact tag, which triggers the
PyPI Trusted Publishing workflow.

## Version integrity

Never move or overwrite an already published version tag.

If a problem is found after a public tag exists, preserve that tag and create
a new semantic patch version.

Historical failed workflow runs remain part of repository history; release
health is determined by the workflow results attached to the final release
commit and tag.
