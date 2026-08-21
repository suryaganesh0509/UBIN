# UBIN v2.0 Architecture

## Core principle

UBIN separates byte semantics, security semantics, capability semantics, and cross-language wire semantics. A source does not need a recognized extension or format to be usable.

## Layers

```text
Application / provider / another language
                │
                ├──────── UBIN Protocol 2 ──────── C / C++ / Java / other runtimes
                │
                ▼
        Python public facade: import ubin
                │
    ┌───────────┼───────────────────────┐
    ▼           ▼                       ▼
Binary core   Capability runtime     Protocol runtime
    │           │                       │
    │           ├─ lazy namespaces      ├─ canonical values
    │           ├─ provider SDK         ├─ 12-byte envelope
    │           ├─ permissions          └─ conformance vectors
    │           ├─ diagnostics
    │           └─ lock/sync
    │
    ▼
Security / transport profiles
    ├─ authenticated .ubs container
    ├─ TLS 1.3 client/server
    ├─ X25519 + HKDF session derivation
    ├─ durable resume
    ├─ KRP ciphertext layout
    └─ authenticated lossless PNG carrier
```

## Universal binary core

Filesystem paths, bytes-like buffers, and seekable binary streams expose the same bounded interface. Detection reads only bounded signatures. Streaming and hashing process data incrementally. Whole-file operations are explicit and guarded.

## Capability/runtime layer

The normal developer entry point is `import ubin`. Capability modules are loaded lazily. Provider installation is explicit rather than an implicit side effect of attribute access. Provider manifests declare compatibility and permissions; diagnostics and environment lockfiles make runtime state inspectable and reproducible.

## UBIN Protocol 2

Protocol 2 is intentionally independent of Python object memory layout. It defines canonical values and a fixed envelope in big-endian bytes. Python is the reference implementation; C, C++, and Java conformance code lives under `interop/`. Any other language can implement the same frozen specification without embedding Python.

See [`PROTOCOL_V2.md`](PROTOCOL_V2.md).

## Local secure container

The established `.ubs` format stores a public authenticated header, AES-256-GCM frames, and an authenticated final SHA-256 digest. Atomic publication uses a temporary file and rename after successful creation. v2 retains this proven compatibility path.

## Network

1. TLS 1.3 protects the connection and authenticates the configured server certificate.
2. UBIN performs an ephemeral X25519 exchange inside TLS.
3. HKDF-SHA256 derives application session material.
4. Transfer encryption and KRP keys are separately derived.
5. Frames are authenticated with AES-256-GCM.
6. Resume checkpoints only authenticated, durably written plaintext.
7. Final output is published after exact SHA-256 verification.

## KRP

KRP uses a keyed permutation over complete ciphertext blocks and does not serialize a permutation table. It changes ciphertext layout without adding payload bytes and is exactly reversible. It is not encryption and never substitutes for AES-GCM or TLS.

## PNG carrier

The authenticated image carrier uses standards-compliant, lossless PNG storage. The protected data path is:

```text
source → authenticated encrypted payload → KRP → carrier metadata/payload → RGBA PNG → exact restore
```

The carrier does not expose the passphrase, AES key, or KRP key. Re-encoding, resizing, JPEG conversion, screenshots, and other image edits are not supported transformations because they can destroy exact carrier bytes.

## Dependency discipline

NumPy and other heavy ecosystems are not mandatory runtime dependencies for byte processing. Lightweight built-ins stay small; heavy AI/data/cloud/UI ecosystems belong behind provider adapters where appropriate. This keeps installation and import costs predictable.
