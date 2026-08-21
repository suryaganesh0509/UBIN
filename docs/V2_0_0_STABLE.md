# UBIN v2.0.0 — Recommended Stable Release

UBIN 2.0.0 is the stable universal-runtime release. It promotes the polyglot protocol from a proving-ground draft to a frozen v2 wire contract while retaining the proven v1 binary and security behaviors as compatibility paths.

## Release principles

1. **Correctness before breadth.** A capability is documented as supported only when it has an implementation and tests.
2. **Exact restoration.** Protected file flows are validated by exact bytes/hash equality, not a prediction-style accuracy score.
3. **Bounded processing.** Arbitrary-size binary data remains stream-oriented; whole-file allocation is explicit rather than accidental.
4. **Fail closed.** Authentication, parsing, carrier, resume, and protocol failures do not publish partially validated output.
5. **Polyglot by protocol.** Python is the reference runtime. C, C++, and Java are first-class conformance implementations. Other languages interoperate through the same frozen bytes.
6. **Backward compatibility where safe.** Existing stable v1 secure/container/network/resume/KRP/PNG behavior is retained and regression-tested.
7. **Reproducible releases.** Version, tag, CI, package artifacts, clean-wheel install, and public PyPI install must agree before the release is declared complete.

## Stable v2 additions

- central release/protocol version constants;
- frozen UBIN Protocol 2 canonical values and 12-byte envelope;
- value-message helpers in Python;
- C canonical writer/reader primitives and envelope implementation;
- C++ canonical writer and envelope implementation;
- Java canonical value and envelope codec;
- shared cross-language conformance vectors;
- CI compilation/execution gate for C, C++, and Java interoperability;
- hardened Python protocol limits for byte size, item count, nesting, payload size, invalid fields, and non-canonical maps;
- documentation rewritten to distinguish language-neutral interoperability from language-specific APIs.

## What v2.0.0 does not claim

- It does not claim source-level API identity between unrelated languages.
- It does not promise impossible lossless compression ratios.
- It does not claim that protocol framing alone provides encryption or authentication.
- It does not promise that software can never contain a future defect; release status means there are no known release-blocking defects after the defined gates pass.
