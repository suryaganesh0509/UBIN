# UBIN v1.0 API

## `ubin.open(source)`

Create a lazy read-only UBIN view for a filesystem path, bytes/bytearray/memoryview, or a seekable binary stream.

Filesystem sources return `UbinObject`; memory and stream sources expose the same core methods through `UbinMemoryObject` / `UbinStreamObject`.

Important members:

- `name`, `path`, `size`, `type`, `closed`
- `info()`
- `read(length)`
- `read_at(offset, length)`
- `seek(offset)`, `tell()`
- `stream(block_size=...)`
- `bytes(max_bytes=...)`
- `hash(algorithm="sha256")`
- `verify(expected_digest, algorithm="sha256")`

## `ubin.secure(source)`

Create a `SecureSource`.

### Local container

```python
receipt = ubin.secure("x.bin").save("x.ubs")
ubin.decrypt("x.ubs", "x-restored.bin", key=receipt.key)
```

### Network

```python
ubin.secure("x.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
    permutation=True,
)
```

## `ubin.secure_server(...)`

Create the reference server. Call `serve_once()` for one incoming transfer. v1 preserves the earlier one-file reference server model; production applications can wrap it in their own lifecycle/concurrency model.

## `ubin.to_image(...)`

```python
receipt = ubin.to_image(
    "source.bin",
    "source.ubin.png",
    passphrase="long private passphrase",
    frame_size=1024 * 1024,
    krp_block_size=4096,
    width=1024,
)
```

Returns `ImageCarrierReceipt`.

## `ubin.from_image(...)`

```python
receipt = ubin.from_image(
    "source.ubin.png",
    "restored.bin",
    passphrase="long private passphrase",
)
```

If destination is omitted, UBIN uses the original basename stored in the carrier.

## CLI

Run `ubin --help` for the final command set.
