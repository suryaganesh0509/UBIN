## v1.0.7 — Universal Runtime Candidate

- Capability runtime, SDK, diagnostics, permissions, environment lockfiles, resources, pipelines and workflows.
- Expanded lightweight capability namespaces while keeping heavy ecosystems provider-oriented.
- UBIN 2 language-neutral canonical-value and envelope draft with Python/C/C++/Java conformance preview.
- Existing v1 binary/security/wire behavior remains the compatibility baseline.

# Changelog
## 1.0.6

- Added safe capability discovery/management CLI (`ubin list`, explicit `ubin add ... --package ...`).

Universal single-import capability foundation.
- Introduced lazy `ubin.search`, `ubin.sort`, and `ubin.ds` namespaces.
- Added capability discovery/loading with a future `ubin.capabilities` entry-point provider contract.
- Deferred the established secure implementation until first security use while preserving top-level v1 calls.
- Added search, sorting, data-structure, facade, and lazy-import regression tests.
- Added the long-term UBIN platform vision and v1.0.6 architecture document.
- No intentional cryptographic primitive, container, network wire-format, resume, KRP, or PNG-carrier format changes.

## 1.0.5

Documentation and developer-understanding patch.

- Reworked the root README as the GitHub `main` landing page.
- Added a documentation index, getting-started guide, user guide, and end-to-end
  explanation of UBIN's data flows.
- Expanded the public API documentation.
- Added explicit time/space complexity and reproducible performance-benchmark
  guidance without making machine-independent speed claims.
- Added testing/release-reproduction, troubleshooting, and FAQ documentation.
- Clarified exact-restoration semantics: UBIN correctness is byte/hash equality,
  not a prediction-style accuracy percentage.
- Updated active installation documentation now that UBIN is publicly available
  from PyPI.
- No intentional public API, cryptographic primitive, secure-container,
  network wire-format, KRP, resume, or PNG-carrier format changes from v1.0.4.


## 1.0.4

Release-integrity closure for the stable UBIN v1 line.

- Incorporated the final Windows pytest portability correction by using
  bounded explicit IDs for large binary parameter cases.
- Added a permanent collection guard preventing oversized pytest node IDs
  from reaching platform environment-variable limits.
- Synchronized package, runtime, CLI, demo, examples, tests, README, and
  release documentation on v1.0.4.
- Updated GitHub artifact upload/download actions used by package, security,
  and release workflows.
- Strengthened package CI with an uploaded-artifact download and clean-wheel
  installation round trip.
- Carries forward the Windows PNG cleanup, guarded `os.fchmod`, and dynamic
  package-version validation corrections from earlier patch releases.
- No intentional public API, cryptographic primitive, secure-container,
  network wire-format, KRP, resume, or PNG-carrier format changes.

## 1.0.3

Windows CI and release-workflow portability correction.

- Made package wheel validation version-dynamic instead of hard-coding v1.0.1.
- Guarded `os.fchmod` for Python/platform combinations where it is unavailable.
- Added a regression test for resumable state writers on platforms without `os.fchmod`.
- Retains the Windows-safe PNG temporary-file cleanup introduced in v1.0.2.
- No intentional public API or wire-format changes.

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
