# UBIN v1.0.5 Public API Reference

v1.0.5 documents the stable v1.0.4 runtime API. It does not intentionally add runtime behavior.

## `ubin.open(source, *, name=None)`

Create a read-only UBIN view.

Accepted sources:

- `str` / path-like filesystem path
- `bytes`
- `bytearray`
- `memoryview`
- seekable binary stream with `read`, `seek`, and `tell`

Return type depends on source kind:

- filesystem -> `UbinObject`
- bytes-like -> `UbinMemoryObject`
- stream -> `UbinStreamObject`

Common interface:

```text
name
path
size
type
closed

info()
read(length)
read_at(offset, length)
seek(offset)
tell()
stream(block_size=..., start=0)
bytes(max_bytes=...)
hash(algorithm="sha256", block_size=...)
verify(expected_digest, algorithm="sha256")
close()
```

### Example

```python
import ubin

with ubin.open("anything.bin") as obj:
    print(obj.info())
    print(obj.read_at(0, 64))
    print(obj.hash())
```

### Complexity

- creation for a filesystem source: effectively O(1) relative to total source size because the type probe is bounded
- `read(k)`: O(k)
- `read_at(..., k)`: O(k)
- full `stream()`: O(n)
- full `hash()`: O(n)

## `UbinInfo`

Immutable metadata value with:

```text
name
path
size
type
```

## `ubin.secure(source, *, key=None)`

Create a `SecureSource`.

Typical use:

```python
secured = ubin.secure("input.bin")
```

When `key` is omitted for the local container path, UBIN creates key material internally.

### `SecureSource.save(destination, *, frame_size=..., overwrite=False)`

Create a framed authenticated local secure container.

```python
receipt = ubin.secure("input.bin").save("input.ubs")
```

Receipt contains local-container metadata including the local key required by `ubin.decrypt()`.

The default secure frame size is 1 MiB. The implementation enforces a maximum frame size.

### `SecureSource.send(...)`

```python
receipt = ubin.secure("input.bin").send(
    host,
    port=9443,
    cafile="trusted-ca.pem",
    server_hostname=None,
    frame_size=1024 * 1024,
    timeout=20.0,
    certfile=None,
    keyfile=None,
    resume=False,
    permutation=False,
    state_dir=None,
)
```

Modes:

```text
resume=False, permutation=False
    one-shot secure transfer

resume=True, permutation=False
    resumable transfer

resume=True, permutation=True
    resumable transfer + KRP
```

Current v1 behavior rejects `permutation=True` without resume.

Network receipts intentionally do not expose the raw AES/KRP transfer keys.

## `ubin.decrypt(secure_source, destination, *, key, overwrite=False)`

Restore an authenticated local `.ubs` container.

```python
receipt = ubin.decrypt(
    "input.ubs",
    "restored.bin",
    key=local_receipt.key,
)
```

A wrong key, corrupted container, truncated container, inconsistent frame metadata, or invalid final digest causes failure instead of publishing a successful restored file.

## `ubin.secure_server(...)`

Create the reference UBIN receive server.

```python
server = ubin.secure_server(
    host="127.0.0.1",
    port=9443,
    certfile="server-cert.pem",
    keyfile="server-key.pem",
    output_dir="received",
    timeout=20.0,
    overwrite=False,
    client_ca=None,
    resume_state_dir=None,
)

try:
    receipt = server.serve_once()
finally:
    server.close()
```

`client_ca` enables certificate verification for client authentication when configured.

The reference server is intentionally simple. Production applications may wrap it in their own service lifecycle, concurrency model, authorization, observability, and deployment controls.

## `ubin.to_image(...)`

```python
receipt = ubin.to_image(
    "source.bin",
    "source.ubin.png",
    passphrase="long unique private passphrase",
    frame_size=1024 * 1024,
    krp_block_size=4096,
    width=1024,
    overwrite=False,
)
```

Creates a standards-compliant lossless PNG carrying an authenticated encrypted UBIN representation.

The output size is not guaranteed to be smaller than the source.

## `ubin.from_image(...)`

```python
receipt = ubin.from_image(
    "source.ubin.png",
    "restored.bin",
    passphrase="long unique private passphrase",
    krp_block_size=4096,
    overwrite=False,
)
```

If `destination` is omitted, UBIN uses the original basename stored in carrier metadata.

## Errors

Public exception hierarchy includes `UbinError` and more specific failures for categories such as:

- missing/non-file/permission problems
- invalid ranges or closed objects
- secure-container/header/authentication/corruption problems
- output collisions
- key problems
- network/protocol/handshake/TLS verification failures
- resume/ticket/source-change failures
- carrier failures

Simple applications can catch `ubin.UbinError`. Applications that need differentiated recovery can catch specific subclasses.

## CLI

```text
ubin info SOURCE
ubin hash SOURCE [--algorithm NAME]

ubin secure SOURCE OUTPUT --key-out KEYFILE [--overwrite]
ubin restore SOURCE OUTPUT --key-file KEYFILE [--overwrite]

ubin image-pack SOURCE OUTPUT [--passphrase-env NAME] [--width N] [--overwrite]
ubin image-restore SOURCE [OUTPUT] [--passphrase-env NAME] [--overwrite]

ubin demo [--port N] [--no-browser]
```

Use `ubin --help` and `ubin <command> --help` as the executable source of truth for command options.
