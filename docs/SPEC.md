# UBIN v1 Semantic Specification (Language-Neutral Core)

This document describes the semantics other language implementations should preserve. The Python package is the v1 reference implementation.

## Core rules

1. **Unknown format is valid input.** Recognition is optional metadata, not an admission gate.
2. **Open must be lazy where the source permits it.** Do not read an arbitrary complete file merely to create a UBIN object.
3. **Read semantics are byte-exact.** `read_at(offset, length)` must return the same byte sequence stored at that range.
4. **Streaming uses bounded auxiliary memory.** Full-source work is O(n); no implementation should claim O(1) time for processing n bytes.
5. **Whole-source materialization must be explicit.**
6. **Verification must be exact and fail closed.**
7. **Cryptographic security must use established authenticated primitives.** KRP is never the root of trust.
8. **Final outputs are published only after required authentication/integrity checks succeed.**
9. **Resume checkpoints represent only authenticated, durable progress.**
10. **Carrier transformations must be exactly reversible.** Lossy image operations are not UBIN carrier operations.

## Recommended common API vocabulary

Language bindings should use equivalent concepts where idiomatic:

- `open`
- `read`
- `read_at`
- `stream`
- `info`
- `hash`
- `verify`
- `secure`
- `send`
- `receive` / server receive
- `to_image`
- `from_image`

## v1 reference profiles

- Core profile: filesystem/memory/seekable-stream binary access
- Local security profile: framed AES-256-GCM `.ubs`
- Network profile: TLS 1.3 + ephemeral X25519 + HKDF + AES-256-GCM
- Resume profile: authenticated opaque tickets + durable frame checkpoints
- KRP profile: keyed reversible ciphertext block mapping
- PNG carrier profile: lossless RGBA/filter-0 PNG containing an authenticated encrypted/KRP payload

Wire/container identifiers inherited from pre-1.0 milestones are intentionally retained where necessary for backward compatibility. A future cross-language wire-format standard should version compatibility independently from the user-facing package version.
