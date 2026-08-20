# UBIN v1.0 Architecture

## Principle

UBIN separates byte semantics from file-format semantics. A source does not need to be recognized in order to be usable.

## Layers

```text
Application
  ↓
UBIN public API
  ↓
Universal binary core
  ├─ filesystem / memory / seekable-stream sources
  ├─ lazy read/read_at/stream
  ├─ bounded signature detection
  └─ streaming hashes
  ↓
Security / transport options
  ├─ local .ubs container
  ├─ TLS client/server
  ├─ durable resume
  ├─ KRP layout
  └─ PNG carrier
```

## Local secure container

The legacy/local `.ubs` format stores a public authenticated header, AES-256-GCM frames, and an authenticated final SHA-256 digest. It uses atomic publication: a temporary file is fsynced and renamed only after successful creation.

## Network

1. TLS 1.3 protects the connection and authenticates the server certificate.
2. UBIN performs an ephemeral X25519 exchange inside the TLS connection.
3. HKDF-SHA256 derives an application session key.
4. Per-transfer AES and KRP keys are separately derived.
5. Frames are authenticated with AES-256-GCM.
6. Resume mode checkpoints only authenticated, durably written plaintext.
7. The final file is published after exact SHA-256 verification.

## KRP

KRP uses a keyed Feistel-derived permutation over complete ciphertext blocks. It does not serialize a permutation table. It adds no payload bytes and is exactly reversible. A short final block is left in place.

KRP is not a cryptographic replacement for AES-GCM or TLS.

## PNG carrier

The v1 image carrier uses a standards-compliant non-interlaced, 8-bit RGBA PNG. UBIN uses PNG filter type 0 for every row so pixel bytes are deterministic and exactly recoverable.

```text
file
 ↓
AES-GCM .ubs payload
 ↓
file-level KRP
 ↓
UBIN carrier metadata + permuted payload
 ↓
RGBA pixel bytes
 ↓
zlib/PNG IDAT chunks
```

Public carrier metadata contains only what is needed to parse/recover the encrypted payload: version, sizes, filename, random salt/context, and ciphertext-payload hash. It does not contain the passphrase, AES key, or KRP key.

A passphrase is processed with scrypt. HKDF then creates independent encryption and permutation keys.

## Why NumPy is not required

UBIN's work is byte streaming, cryptography, file I/O and protocol framing. Those operations do not require numerical arrays. Avoiding a mandatory NumPy dependency reduces installation size and avoids unnecessary memory conversions.
