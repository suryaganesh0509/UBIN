# UBIN-PY 0.4 — Interruption-Safe Resumable Transfer

UBIN v0.4 keeps every feature from v0.1, v0.2, and v0.3, then adds
authenticated interruption recovery for large network transfers.

## Version progression

```text
v0.1  Universal binary access
v0.2  Local authenticated secure container
v0.3  TLS 1.3 client/server secure transfer
v0.4  Durable resumable secure transfer
```

## Main v0.4 API

The v0.3 one-shot path remains unchanged:

```python
ubin.secure("anything.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
)
```

Enable v0.4 resume explicitly:

```python
ubin.secure("anything.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
)
```

The developer still does not copy or pass a raw AES key.

## What happens on the first resumable attempt

```text
source
  ↓
bounded-memory SHA-256 source identity
  ↓
TLS 1.3 + server certificate verification
  ↓
ephemeral X25519 session
  ↓
HKDF-SHA256 per-transfer AES-256 key
  ↓
UBT4 resumable transfer header
  ↓
server issues opaque HMAC resume ticket
  ↓
AES-256-GCM frames
  ↓
authenticate frame
  ↓
write plaintext to hidden partial file
  ↓
fsync partial file
  ↓
atomically advance durable checkpoint
```

The checkpoint is moved forward **only after** the frame authenticates and
the plaintext is durably written.

## What happens after a disconnect

The client keeps an opaque resume ticket in its local resume state. The
server keeps only transfer metadata, its hidden partial file, and a
server-side secret used to authenticate tickets.

On reconnect:

```text
new TLS 1.3 connection
  ↓
new ephemeral X25519 session
  ↓
new AES-256 transfer key
  ↓
client presents transfer ID + opaque resume ticket
  ↓
server verifies ticket + stored metadata
  ↓
server returns last durable frame
  ↓
client starts at that frame
  ↓
only remaining frames cross the network
```

UBIN does **not** persist the old AES transfer key. Every reconnect gets a
fresh TLS/X25519 session and a fresh application transfer key.

## Source-change protection

A resumable attempt performs a bounded-memory SHA-256 pass before transfer.
That digest identifies the exact source content. If the source changes
between attempts, UBIN rejects the resume before sending more data.

This is an intentional correctness tradeoff: resume saves retransmitting
already-delivered bytes over the network, while strong source identity
requires a local hash scan.

## Resume authorization

The server generates an HMAC-SHA256 resume ticket bound to:

- transfer ID
- source SHA-256
- original size
- frame size
- frame count
- filename

The client stores the ticket as an opaque bearer credential. It is not an
AES encryption key.

Default client state location:

```text
~/.ubin/resume/
```

A custom local state directory can be supplied:

```python
ubin.secure("large.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
    state_dir="/private/state",
)
```

Client state is deleted automatically after success.

Server resume state defaults to:

```text
<output_dir>/.ubin-resume/
```

The server secret is created with restrictive file permissions where the OS
supports them. Production deployments must protect this directory like
other application secrets.

## Final publication rule

The receiver never publishes the hidden partial file merely because all
frames arrived.

Before `os.replace()` publishes the final destination, UBIN:

1. authenticates the final AES-GCM record,
2. verifies the sender's expected SHA-256,
3. re-hashes the complete partial file,
4. compares it to the source SHA-256,
5. only then atomically publishes the file.

A corrupted checkpointed prefix therefore cannot silently become a final
file.

## Server restart

Resume metadata and the server HMAC secret are persisted in the server
resume-state directory. A new `SecureServer` instance using the same output
directory can continue a previously interrupted transfer.

## Backward compatibility

v0.4 keeps:

- `ubin.open(...)`
- v0.2 local `.ubs` secure containers
- v0.3 non-resumable client/server transfer

`resume=False` remains the v0.3 behavior.

## Local demo

```bash
python manual_resume_demo.py
```

Important expected lines:

```text
FIRST ATTEMPT INTERRUPTED: True
RESUMED FROM FRAME: 3
TLS: TLSv1.3
NO MANUAL KEY: True
MATCH: True
CLIENT RESUME STATE CLEANED: True
```

## Tests

```bash
pytest -q
```

Expected:

```text
40 passed
```

The suite contains all 32 v0.1-v0.3 tests plus v0.4 tests for:

- durable interruption + resume
- exact SHA-256 after resume
- source changed between attempts
- tampered resume ticket
- corrupted checkpointed prefix
- server restart recovery
- v0.3 network compatibility
- no raw key exposed in resumable receipt

## v0.4 scope boundary

v0.4 is about correctness and durable resume.

Later versions can optimize checkpoint throughput, add multi-file sessions,
parallel lanes, congestion-aware scheduling, Merkle/chunk verification,
optional image carriers, and broader protocol hardening.
