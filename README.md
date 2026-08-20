# UBIN-PY 0.5 — Keyed Reversible Permutation (KRP)

UBIN v0.5 keeps every feature from v0.1 through v0.4 and adds an optional
**Keyed Reversible Permutation (KRP)** layout layer for authenticated encrypted
network frames.

## Version progression

```text
v0.1  Universal lazy binary access
v0.2  Local AES-256-GCM secure container
v0.3  TLS 1.3 client/server secure transfer
v0.4  Durable interruption-safe resume
v0.5  Keyed reversible ciphertext layout (KRP)
```

## Why v0.5 exists

KRP is preparation for later lossless carrier formats such as the planned PNG
carrier. It gives UBIN a deterministic, secret-derived and reversible way to
rearrange encrypted frame blocks **before** carrier integration is introduced.

KRP is **not a new cipher** and is not claimed as additional cryptographic
strength. Security continues to come from:

- TLS 1.3 transport protection and server authentication
- ephemeral X25519 session establishment
- HKDF-SHA256 key derivation
- AES-256-GCM authenticated encryption
- SHA-256 exact-restoration verification

KRP only changes ciphertext layout.

## API

The existing v0.4 resumable path is unchanged:

```python
ubin.secure("large.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
)
```

Enable v0.5 KRP explicitly:

```python
ubin.secure("large.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
    permutation=True,
)
```

KRP is optional so applications that prioritize raw throughput can retain the
v0.3/v0.4 paths without permutation overhead.

## v0.5 data flow

```text
source bytes
   ↓
frame
   ↓
AES-256-GCM
   ↓
authenticated ciphertext
   ↓
KRP using separate HKDF-derived Kperm
   ↓
permuted ciphertext layout
   ↓
TLS 1.3 transport
   ↓
receiver derives same Kperm
   ↓
reverse KRP
   ↓
original authenticated ciphertext
   ↓
AES-GCM authenticate + decrypt
   ↓
checkpoint / final SHA-256 verification
```

The AES key and KRP key are separate derived keys. Neither raw key is returned
in the network receipt.

## KRP design

The reference implementation operates on complete fixed-size ciphertext blocks
(default: 4096 bytes). A short trailing block remains in its original position.

For every frame, UBIN derives a context from:

- transfer ID
- per-connection nonce base
- frame number

A keyed 6-round Feistel permutation maps block positions. Cycle walking maps the
power-of-two Feistel domain back into the exact number of complete blocks.

Properties:

- exact reversible mapping
- no permutation table stored on disk
- no sequence table transmitted over the network
- same-length input and output (zero KRP size expansion)
- bounded frame memory
- different frame/transfer context produces a different layout
- KRP output is reversed before AES-GCM authentication

A malicious or corrupted permuted frame does not bypass authentication: after
reverse KRP, AES-GCM rejects modified ciphertext/tag bytes.

## Resume compatibility

KRP is integrated with v0.4 durable resume.

If a transfer stops after frame 3:

```text
frames 0 1 2  → authenticated, written, fsynced, checkpointed
frame 3       → connection fails
```

On reconnect, UBIN creates a fresh TLS/X25519 session and therefore fresh AES
and KRP keys for that connection. The server returns the durable frame
checkpoint and the client sends only the remaining frames. Already checkpointed
plaintext does not need the old KRP key.

KRP resume state has a distinct v0.5 profile and cannot be confused with a v0.4
resume state.

## Backward compatibility

v0.5 retains:

- `ubin.open(...)` from v0.1
- local `.ubs` containers from v0.2
- `resume=False` network transfer from v0.3
- `resume=True, permutation=False` from v0.4

The v0.5 KRP protocol is selected only by:

```python
resume=True, permutation=True
```

## Local test

```bash
pytest -q
```

Expected for this build:

```text
51 passed
```

The suite includes all v0.1-v0.4 regression tests plus v0.5 checks for:

- exact KRP round-trip across edge sizes
- zero size expansion
- deterministic mapping for identical context
- context-bound mapping differences
- tampered KRP ciphertext still failing AES-GCM
- exact KRP client/server transfer
- interruption + KRP resume
- no raw KRP key exposed
- v0.4 resume compatibility
- controlled rejection of invalid KRP API combinations

## Manual KRP/resume demo

```bash
python manual_krp_demo.py
```

Important expected lines:

```text
KRP LAYOUT: krp
FIRST ATTEMPT INTERRUPTED: True
RESUMED FROM FRAME: 3
FRAMES SENT ON RESUME: 4
TOTAL FRAMES: 7
TLS: TLSv1.3
NO MANUAL KEY: True
NO KRP KEY EXPOSED: True
MATCH: True
CLIENT RESUME STATE CLEANED: True
FINAL FILE PUBLISHED: True
```

## v0.5 scope boundary

v0.5 establishes and validates the reversible ciphertext-layout layer. It does
**not** create an image carrier yet.

The planned next step is v0.6: a lossless carrier format (initially PNG) that
uses KRP output as payload while preserving exact recovery. Carrier encoding
must not resize, blend, JPEG-compress, or otherwise mutate ciphertext bytes.
