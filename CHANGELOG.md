# Changelog

## 1.0.2

Windows portability patch release.

- Fixed malformed-PNG temporary-file cleanup on Windows.
- Close temporary file descriptors before unlinking temporary files.
- Prevent Windows PermissionError from masking UbinCarrierError.
- Added a regression test simulating Windows open-file unlink behavior.
- Validation increased to 115 automated tests.
- No intentional public API or wire-format changes.

## 1.0.1

Credibility, assurance, and release-engineering update. No intentional breaking changes to the v1 public API.

- Added multi-OS/multi-Python GitHub Actions CI (Linux, macOS, Windows; Python 3.10-3.14).
- Added coverage enforcement and Codecov upload integration.
- Added Ruff, Bandit, Semgrep CE, and pip-audit security/static-analysis workflows with machine-readable scan artifacts.
- Added Hypothesis property-based parser/KRP tests and Atheris coverage-guided fuzz harnesses.
- Isolated filesystem-backed Hypothesis examples with per-example temporary directories so property tests do not share pytest fixture state.
- Added explicit threat model and trust-boundary diagram.
- Added README architecture diagram and a clearer "Why UBIN exists" narrative.
- Added design-decision write-up covering KRP, AES-GCM, nonce uniqueness, and resume behavior.
- Added PyPI Trusted Publishing workflow and release checklist.
- Added contributing/security-reporting/community templates and Dependabot configuration.
- Added package/release validation workflow and wheel-install smoke testing.
- Added a single-file public-consumer integration example covering the major v1 API paths.

## 1.0.0

- Finalized public Python package/API
- Added lossless authenticated PNG carrier
- Added scrypt + HKDF key derivation for passphrase-based image carriers
- Added bounded file-level KRP helpers
- Added PNG structural/CRC/filter validation and fail-closed restoration
- Added `ubin` CLI
- Added local browser UI and final image demo
- Added architecture/API/security documentation
- Preserved v0.1-v0.5 behavior and regression tests
- Final supplied suite: 86 passing tests

## 0.5.0

- Keyed Reversible Permutation (KRP)

## 0.4.0

- Durable interruption-safe resumable transfer

## 0.3.0

- TLS 1.3 client/server transfer with X25519/HKDF session keys

## 0.2.0

- Local framed AES-256-GCM secure container

## 0.1.0

- Universal lazy binary core
