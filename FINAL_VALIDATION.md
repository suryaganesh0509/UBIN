# UBIN v1.0.1 Release Validation

This file records the local validation completed while building the v1.0.1 release candidate. GitHub-hosted multi-OS jobs must also pass after the candidate is pushed.


## Hypothesis fixture isolation

The PNG property tests create a fresh `TemporaryDirectory()` inside every Hypothesis-generated example. They intentionally do not use pytest's function-scoped `tmp_path` fixture, preventing state reuse across generated inputs and satisfying Hypothesis' fixture health check without suppressing it.

## Reference environment

- Python: 3.13.5
- cryptography: 46.0.4
- Platform: Linux x86_64 validation container
- Declared Python support: 3.10-3.14
- Runtime dependency count: one external dependency (`cryptography>=42`)

Python 3.9 is intentionally not claimed by v1.0.1 because it is upstream end-of-life and the package floor is Python 3.10.

## Regression suite

The local environment could not download new packages from PyPI, so Hypothesis was unavailable here. All tests not requiring that newly added dev dependency passed:

```text
110 passed, 1 skipped
```

The skipped module contains 4 Hypothesis property tests. With `python -m pip install -e ".[dev]"`, the expected collected suite is 114 pytest cases and GitHub CI runs those tests.

## Coverage gate

Core-library coverage excludes only presentation/command wrappers (`src/ubin/demo.py` and `src/ubin/cli.py`), which are separately smoke/integration tested.

```text
TOTAL: 84.0% line coverage
Required threshold: 82%
Result: PASS
```

Notable measured modules in this run:

```text
core.py                 94.8%
secure/krp.py           90.4%
secure/image_carrier.py 88.4%
secure/container.py     86.2%
secure/png_codec.py     84.2%
secure/network.py       83.8%
```

## Randomized parser/KRP smoke campaign

A deterministic-seed randomized campaign was run in addition to pytest:

```text
KRP round trips:              500
PNG codec round trips:         80
Arbitrary PNG parser inputs:  250
Result: PASS
```

The repository also contains Atheris coverage-guided fuzz targets. They are executed by the Linux fuzz workflow when the optional `fuzz` dependencies are available.

## Manual feature demonstrations

All of the following completed successfully from the v1.0.1 source tree:

```text
manual_secure_demo.py   -> MATCH: True
manual_network_demo.py  -> TLSv1.3, NO MANUAL KEY: True, MATCH: True
manual_resume_demo.py   -> resumed from frame 3, MATCH: True, final published
manual_krp_demo.py      -> KRP, resume, NO KRP KEY EXPOSED: True, MATCH: True
manual_image_demo.py    -> valid PNG signature, krp+png, MATCH: True
```

## Public-consumer integration example

The single-file public-consumer example was run against the v1.0.1 package metadata/API and completed:

```text
46 passed, 0 failed
```

It exercises import/package metadata, universal binary access, local secure containers, PNG carriers, TLS 1.3, interruption/resume, KRP, key non-exposure checks, and the CLI.

## Browser demo

The local `ubin demo` HTTP server was started on loopback and the home page was fetched successfully:

```text
DEMO_HTTP_OK True
```

## Packaging validation

The wheel was built from `pyproject.toml` after resolving modern setuptools metadata validation. Result:

```text
ubin-1.0.1-py3-none-any.whl
```

The wheel was installed into a fresh virtual environment with the validation environment's cryptography available and passed:

```text
IMPORT_OK 1.0.1
PNG True
MATCH True True
UBIN 1.0.1
```

Wheel metadata confirms:

```text
Requires-Python: >=3.10
Requires-Dist: cryptography>=42
```

NumPy, Pillow, Flask, and other large frameworks are not UBIN runtime requirements.

## Workflow/configuration validation

All GitHub workflow YAML files and `codecov.yml` parsed successfully in the release environment:

```text
ci.yml               OK
security.yml         OK
fuzz.yml             OK
package.yml          OK
publish-pypi.yml     OK
codecov.yml          OK
```

The CI configuration covers Linux/macOS/Windows with Python 3.10, 3.11, 3.12, 3.13, and 3.14. The security workflow is configured for Ruff, Bandit, Semgrep CE, and pip-audit. These external scanners could not be installed in the offline release container, so their authoritative pass/fail result comes from GitHub Actions after push; the project does not claim they passed locally when they were not executed.

## Security/fuzzing scope

v1.0.1 adds an explicit threat model and trust boundaries, Hypothesis property tests, Atheris fuzz harnesses, static/security scanning workflows, dependency auditing, and fail-closed parser mutation tests. These improve evidence but are not an independent professional security audit or formal proof.

## Release rule

Do not create/move the `v1.0.1` tag until the user's local test run succeeds. After push, verify all GitHub Actions jobs are green before creating the GitHub Release / PyPI publication.
