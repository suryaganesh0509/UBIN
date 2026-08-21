# How UBIN Works

This document explains the data flow in plain language.

## 1. Universal binary access

UBIN begins with a source:

```text
path
bytes
bytearray
memoryview
seekable binary stream
```

`ubin.open(source)` wraps that source with one read-oriented interface.

For filesystem sources, UBIN opens the file read-only, obtains its size, reads only a small fixed probe for type detection, then returns to the start. It does not read the complete file merely to create the object.

## 2. Why extension-independent?

Filename extensions are hints controlled by naming conventions. The bytes are the actual data.

UBIN therefore uses this rule:

```text
recognized signature  -> useful detected type
unknown signature     -> generic binary type
```

Unknown content remains usable.

## 3. Read model

UBIN supports two main patterns.

### Sequential cursor

```text
read()
seek()
tell()
```

### Positioned access

```text
read_at(offset, length)
```

Positioned reads are useful for parsers, headers, indexes, and applications that need byte ranges without intentionally disturbing a sequential cursor.

## 4. Streaming model

```text
total input size = n
block size       = b

read block b
process block
discard block
read next block
...
```

This is why large-file processing can use auxiliary memory related to the configured block/frame size rather than loading `n` bytes at once.

## 5. Hashing

```text
source
  ↓
block 0 ─┐
block 1 ─┼─► hashlib
block 2 ─┤
...      ┘
  ↓
digest
```

A full-file cryptographic hash must inspect the file, so it is O(n) in total bytes.

## 6. Local secure container

```text
source plaintext
      │
      ▼
split into frames
      │
      ▼
AES-256-GCM each frame
      │
      ├── authenticated metadata
      ├── unique per-frame nonce
      └── encrypted frame bytes
      │
      ▼
authenticated final SHA-256 record
      │
      ▼
temporary .ubin-part
      │
verify successful creation + fsync
      │
      ▼
atomic final publication
```

AES-GCM provides both confidentiality and integrity/authentication.

Restoration reverses the frame process. A frame is not accepted as valid plaintext unless authentication succeeds. The final content digest is then checked before publishing the completed output.

## 7. Secure network transfer

```text
client
  │
  ├─ TLS 1.3 connection
  │      │
  │      └─ server certificate verification
  │
  ├─ ephemeral X25519 exchange inside TLS
  │
  ├─ HKDF-SHA256 session/transfer derivation
  │
  ├─ AES-256-GCM authenticated frames
  │
  └─ final authenticated digest
                 │
                 ▼
              server
```

Why both TLS and application-level AES-GCM?

TLS protects the connection. UBIN's frame-level authenticated design also defines the application's own transfer framing, integrity rules, key separation, resume semantics, and exact-restoration checks.

## 8. Resume

A resumable transfer uses durable progress.

```text
frame authenticated
      ↓
plaintext written
      ↓
durability step
      ↓
checkpoint advances
```

The checkpoint represents authenticated progress, not merely “bytes received.”

After reconnection, UBIN derives fresh cryptographic session material and uses authenticated resume state to continue from the durable boundary.

## 9. KRP

KRP means Keyed Reversible Permutation.

```text
authenticated ciphertext blocks
          │
          ▼
keyed reversible reordering
          │
          ▼
transport/carrier representation
```

It is deliberately applied to ciphertext, not used as the root security primitive.

Important:

```text
AES-GCM / TLS = security
KRP           = reversible ciphertext layout
```

KRP is not a replacement for authenticated encryption.

## 10. PNG carrier

```text
source
  ↓
authenticated encrypted representation
  ↓
KRP
  ↓
UBIN carrier metadata + encrypted payload
  ↓
RGBA pixel bytes
  ↓
lossless PNG encoding
  ↓
one .png file
```

Restoration:

```text
PNG structural validation
  ↓
recover exact pixel bytes
  ↓
read UBIN carrier metadata
  ↓
reverse KRP
  ↓
authenticate/decrypt
  ↓
verify final content
  ↓
publish exact destination
```

The passphrase is transformed through a password-hardening/key-derivation path and independent encryption/permutation material is derived.

## 11. Why a PNG cannot magically be tiny

Encryption intentionally produces high-entropy data. High-entropy data usually compresses poorly.

Therefore:

```text
large arbitrary input
      ≠
guaranteed tiny lossless PNG
```

UBIN's image feature is a lossless carrier representation, not impossible universal compression.

## 12. Exactness

For a successful round trip:

```text
source bytes == restored bytes
```

A practical independent check is:

```text
SHA256(source) == SHA256(restored)
```

UBIN is not a prediction model, so “accuracy = 99.x%” is not the correct metric. Either the restored byte sequence verifies exactly, or the operation fails verification.
