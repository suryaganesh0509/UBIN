# UBIN FAQ

## Does UBIN support every file extension?

UBIN can accept arbitrary file bytes even when it does not recognize the format. Unknown content uses a generic binary type.

That is different from claiming UBIN understands the internal semantics of every file format.

## Does UBIN modify my original file?

Core access is read-only. Secure/container/carrier operations write separate outputs.

## Does UBIN load the whole file into RAM?

Not for normal lazy filesystem access, positioned reads, streaming, or streaming hashes.

Calling `bytes()` intentionally materializes the complete object.

## Can UBIN process huge files?

The architecture uses bounded read/frame operations for the main streaming paths, so total input size does not automatically imply equivalent in-memory buffering.

Real practical limits still depend on storage, filesystem, OS, runtime, time, available disk space, and the specific operation.

## Can a 1 TB file always become a 10 MB PNG?

No.

Lossless compression cannot guarantee that arbitrary data—especially encrypted high-entropy data—shrinks to a fixed tiny size.

The PNG feature is a reversible lossless carrier, not magical compression.

## Is KRP encryption?

No.

KRP is a keyed reversible layout transform over ciphertext. Cryptographic security comes from established primitives such as AES-256-GCM and TLS 1.3.

## Why use AES-GCM?

It combines encryption with authentication/integrity, allowing corrupted or wrong-key ciphertext to be rejected.

## Why use TLS if UBIN frames are also encrypted?

TLS protects the network connection and authenticates the server certificate. UBIN's application protocol independently defines per-transfer framing, key derivation, resume behavior, and exact-restoration checks.

## What does X25519 do?

It provides ephemeral application-level key agreement inside the TLS connection.

## What does HKDF-SHA256 do?

It derives/separates cryptographic keys for different purposes so the same raw material is not reused directly across roles.

## Is the PNG passphrase stored inside the PNG?

No. Carrier metadata contains information required to interpret the encrypted representation, not the plaintext passphrase or raw derived keys.

## Can I edit the PNG?

No. Treat it as a data artifact, not a normal photo.

Editing, resizing, conversion, screenshots, or transformations can destroy exact carrier bytes and should cause restoration to fail.

## What does “accuracy” mean for UBIN?

UBIN is not an AI/prediction system. The relevant test is exact restoration:

```text
SHA256(original) == SHA256(restored)
```

## Is UBIN formally verified?

No.

The repository uses tests, CI, static/security tooling, dependency auditing, property testing and fuzzing to increase confidence. Those are not substitutes for formal verification or an independent professional security audit.

## Is UBIN post-quantum?

The stable v1 design does not claim post-quantum key establishment.

## Does UBIN require NumPy?

No. The runtime dependency is `cryptography`; NumPy is intentionally not required for core byte processing.

## Which Python versions are targeted?

The package metadata targets Python 3.10 and newer, with the release CI covering the configured supported versions.

## Can I use only `import ubin`?

For normal v1.0.5 user-facing operations, the main high-level API is already available through the top-level package.

The planned v1.0.6 goal is stronger: formalize a single-import public facade so supported public functionality does not require users to import from internal submodules.

## Is `generate_localhost_certificate()` for production?

No. It is a test/demo helper. Use proper PKI/certificate management for production deployments.
