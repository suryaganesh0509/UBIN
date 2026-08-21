# UBIN v2.0.0 — Local Validation Record

This record captures validation performed while preparing the supplied v2.0.0 source package. Hosted GitHub/PyPI gates still have to run on the exact commit that will be tagged.

## Passed locally

- release/runtime/protocol version integrity: PASS
- Python bytecode compile: PASS
- core/facade/v1 compatibility + v2 protocol/interop/release-integrity groups: PASS
- secure container/network/resume/KRP regression group: PASS
- image carrier/portability/fuzz-regression group: PASS
- runtime/provider/environment group: PASS
- CLI + legacy protocol regression group: PASS
- total executed tests in available environment: 221 passed
- aggregate Python coverage: 86.1% (release minimum: 82%)
- `src/ubin/protocol.py` coverage: 94.8%
- strict C11 conformance compile/run (`-Wall -Wextra -Werror`): PASS
- strict C++17 conformance compile/run (`-Wall -Wextra -Werror`): PASS
- Java conformance compile/run: PASS
- wheel build: PASS
- sdist build: PASS
- wheel metadata version: 2.0.0
- wheel import from isolated site-packages outside repository: PASS
- CLI `ubin --version` from installed wheel: PASS (`UBIN 2.0.0`)
- archive scan for `.env`, `.DS_Store`, `__pycache__`, `.pyc`, coverage artifacts: PASS

## Environment-limited checks

The local execution environment had no network access and did not contain `hypothesis`, `ruff`, `bandit`, `pip-audit`, `twine`, or `build` as installed command modules. The sdist/wheel were built directly through the installed setuptools PEP 517 backend. The Hypothesis module therefore reported one module-level skip locally. The repository's `.[dev,security]` metadata and GitHub workflows still require these tools, so the hosted CI/Security/Package workflows are the authoritative final gates.

A `pip check` performed in a venv inheriting global sandbox packages reported an unrelated global `supervisor`→`setuptools` inconsistency. UBIN itself imported and executed from the isolated wheel correctly; final GitHub Package/PyPI clean environments remain required to establish dependency consistency without sandbox contamination.

## Release rule

Do not call the public v2.0.0 release complete until CI, Security, Package, polyglot conformance, release-tag verification, Trusted PyPI publication, and a fresh no-cache public `pip install ubin==2.0.0` all pass on the exact release commit.
