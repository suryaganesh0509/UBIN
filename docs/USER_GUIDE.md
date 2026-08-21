# UBIN User Guide

## 1. What counts as a UBIN source?

`ubin.open()` accepts:

- filesystem paths (`str` or path-like objects)
- `bytes`
- `bytearray`
- `memoryview`
- seekable binary streams that provide `read()`, `seek()`, and `tell()`

### Filesystem path

```python
import ubin

with ubin.open("video.mp4") as obj:
    print(obj.size)
```

### Bytes

```python
payload = b"\x00\x01\x02"
with ubin.open(payload, name="packet.bin") as obj:
    print(obj.size)
```

### Bytearray

```python
payload = bytearray(b"mutable source")
with ubin.open(payload, name="buffer.bin") as obj:
    print(obj.hash())
```

### Memoryview

```python
payload = memoryview(b"zero-copy-friendly input")
with ubin.open(payload, name="view.bin") as obj:
    print(obj.read_at(0, 4))
```

### Seekable binary stream

```python
import io
import ubin

stream = io.BytesIO(b"stream payload")

with ubin.open(stream, name="stream.bin") as obj:
    print(obj.info())

# caller owns the original stream
assert not stream.closed
stream.close()
```

## 2. Metadata and type detection

```python
with ubin.open("anything.futureXYZ") as obj:
    print(obj.name)
    print(obj.path)
    print(obj.size)
    print(obj.type)
    print(obj.info())
```

Type detection is bounded and signature-based. Recognition is useful metadata, not an admission rule. An unknown format remains usable.

## 3. Sequential reads

```python
with ubin.open("data.bin") as obj:
    first = obj.read(128)
    second = obj.read(128)
```

`read(length)` requires an explicit non-negative length. UBIN avoids a default “read the entire arbitrary file” operation.

## 4. Positioned reads

```python
with ubin.open("data.bin") as obj:
    header = obj.read_at(0, 64)
    middle = obj.read_at(4096, 512)
```

`read_at()` is designed for random access without intentionally moving the object's sequential cursor.

## 5. Seek and tell

```python
with ubin.open("data.bin") as obj:
    obj.seek(1024)
    print(obj.tell())
    print(obj.read(32))
```

## 6. Streaming

```python
with ubin.open("large.bin") as obj:
    for block in obj.stream(block_size=4 * 1024 * 1024):
        process(block)
```

For filesystem data, use streaming for large inputs instead of `bytes()`.

## 7. Whole-object materialization

```python
with ubin.open("small.bin") as obj:
    payload = obj.bytes(max_bytes=10 * 1024 * 1024)
```

`max_bytes` is a safety ceiling. If the source exceeds it, UBIN rejects the request instead of silently consuming more memory.

## 8. Hashing and verification

```python
with ubin.open("artifact.bin") as obj:
    digest = obj.hash("sha256")
    print(digest)

    if obj.verify(digest, "sha256"):
        print("exact digest match")
```

## 9. Local authenticated storage

```python
receipt = ubin.secure("artifact.bin").save(
    "artifact.ubs",
    frame_size=1024 * 1024,
)
```

The local container is framed and authenticated. Its creation path writes a temporary output and publishes the final destination after successful completion.

Restore:

```python
restored = ubin.decrypt(
    "artifact.ubs",
    "artifact-restored.bin",
    key=receipt.key,
)
```

Do not lose the local key. A wrong key must fail authentication.

## 10. Network transfer

Client:

```python
receipt = ubin.secure("large.bin").send(
    "receiver.example",
    port=9443,
    cafile="trusted-ca.pem",
)
```

With resume:

```python
receipt = ubin.secure("large.bin").send(
    "receiver.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
)
```

With resume + KRP:

```python
receipt = ubin.secure("large.bin").send(
    "receiver.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
    permutation=True,
)
```

In the current v1 implementation, KRP transfer requires `resume=True`.

Server:

```python
server = ubin.secure_server(
    host="0.0.0.0",
    port=9443,
    certfile="server-cert.pem",
    keyfile="server-key.pem",
    output_dir="received",
)

try:
    receipt = server.serve_once()
    print(receipt.output)
finally:
    server.close()
```

Use trusted production certificates in real deployments.

## 11. PNG carrier

Pack:

```python
packed = ubin.to_image(
    "source.bin",
    "source.ubin.png",
    passphrase="a long unique passphrase",
)
```

Restore:

```python
restored = ubin.from_image(
    "source.ubin.png",
    "restored.bin",
    passphrase="a long unique passphrase",
)
```

Or allow UBIN to use the basename stored in carrier metadata:

```python
ubin.from_image(
    "source.ubin.png",
    passphrase="a long unique passphrase",
)
```

## 12. Error handling

Catch the common UBIN base class when an operation should be handled uniformly:

```python
import ubin

try:
    with ubin.open("missing.bin") as obj:
        print(obj.hash())
except ubin.UbinError as exc:
    print("UBIN operation failed:", exc)
```

More specific subclasses are available when an application needs to distinguish missing files, authentication failures, corrupted data, TLS verification failures, resume failures, and related cases.

## 13. Original-source behavior

UBIN's core view is read-only. Protected-output operations write separate destinations. Do not use the same pathname for source and destination.

## 14. Which API should I choose?

| Situation | Recommended API |
|---|---|
| inspect arbitrary input | `ubin.open()` |
| read a small known section | `read_at()` |
| process a large source | `stream()` |
| compare exact content | `hash()` / `verify()` |
| authenticated local storage | `secure().save()` |
| secure one-shot transfer | `secure().send()` |
| unstable connection | `secure().send(..., resume=True)` |
| resume + ciphertext layout | `secure().send(..., resume=True, permutation=True)` |
| single lossless image artifact | `to_image()` / `from_image()` |
