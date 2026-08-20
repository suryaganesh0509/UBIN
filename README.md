# UBIN-PY 0.3 — Secure Client/Server Session

UBIN 0.3 keeps the v0.1 universal binary API and v0.2 local secure-container
API, then adds authenticated client/server transfer.

## Core idea

```python
import ubin

receipt = ubin.secure("anything.future").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
)
```

The normal network path does **not** require the developer to copy or pass an
AES key.

## What v0.3 adds

- TLS 1.3 minimum transport
- server certificate verification
- optional mutual TLS client certificates
- ephemeral X25519 application key agreement inside the TLS connection
- HKDF-SHA256 session-key derivation
- separate HKDF-derived per-transfer AES-256 key
- AES-256-GCM authenticated encrypted frames
- fresh transfer id and 96-bit nonce base
- bounded-memory streaming
- exact SHA-256 verification at the receiver
- authenticated success acknowledgement back to the sender
- atomic receiver publication using a temporary file + `os.replace`
- unknown/custom file extensions accepted
- no raw transfer key in `NetworkSendReceipt`

## Why both TLS and UBIN encryption?

TLS protects the network connection and authenticates the server. UBIN then
derives its own ephemeral application-layer key and encrypts the file frames.
This keeps the UBIN transfer format/session independent of manual developer
key management.

## Local v0.2 API remains available

```python
secured = ubin.secure("sample.bin")
receipt = secured.save("sample.ubs")

ubin.decrypt(
    "sample.ubs",
    "restored.bin",
    key=receipt.key,
)
```

That key-oriented API is retained only for backward-compatible local v0.2
containers. The new v0.3 network API does not require it.

## Local network demo

```bash
python manual_network_demo.py
```

Expected important lines:

```text
TLS: TLSv1.3
NO MANUAL KEY: True
MATCH: True
```

The demo generates a temporary localhost self-signed certificate solely for
local testing. Production deployments must use their normal trusted
certificate infrastructure.

## Tests

```bash
pytest -q
```

The test suite includes all v0.1/v0.2 tests plus:

- exact TLS client/server round trips
- empty/tiny/multi-megabyte transfer
- TLS 1.3 assertion
- untrusted certificate rejection
- X25519 session-key parity
- fresh sessions and transfer IDs
- no raw key exposed in network receipts

## Scope

v0.3 is intentionally a **one-connection / one-file reference transport**.
v0.4 is reserved for interruption-safe resume, authenticated checkpoints,
retry state, and long-running server operation.
