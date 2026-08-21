# UBIN v2.0.0 Final Validation Contract

This document defines what must be true before UBIN v2.0.0 is called the recommended stable release.

## Required gates

- [ ] repository clean and release commit synchronized with `origin/main`
- [ ] `pyproject.toml`, `ubin.__version__`, CLI version, tag, and release all equal `2.0.0`
- [ ] complete Python regression suite passes with zero failures
- [ ] configured coverage threshold passes
- [ ] dependency consistency passes
- [ ] package bytecode compilation passes
- [ ] Ruff passes
- [ ] Bandit configured medium/high gate passes
- [ ] dependency vulnerability audit passes
- [ ] Semgrep configured gate passes
- [ ] Python 3.10–3.14 passes on Ubuntu, macOS, and Windows
- [ ] C stable envelope + canonical-value conformance passes under strict compiler warnings
- [ ] C++ stable envelope + canonical-value conformance passes under strict compiler warnings
- [ ] Java stable envelope + canonical-value conformance passes
- [ ] shared conformance vectors equal Python reference output
- [ ] wheel and sdist build successfully
- [ ] Twine validates both distributions
- [ ] wheel installs into an isolated environment
- [ ] package imports from outside the source checkout
- [ ] public CLI smoke tests pass
- [ ] release tag resolves to the verified commit and is never moved after publication
- [ ] GitHub Release triggers Trusted PyPI publication successfully
- [ ] fresh no-cache public `pip install ubin==2.0.0` succeeds

## Stability meaning

Passing these gates means no known release-blocking defect remains in the tested contract. It is not a promise that future environments or undiscovered inputs can never reveal a defect. Any post-release correction belongs in a new immutable patch release such as 2.0.1; the 2.0.0 tag must not be rewritten.
