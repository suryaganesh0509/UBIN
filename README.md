# UBIN v2.0.0 — Recommended Stable Universal Runtime

> **UBIN handles the bytes. You handle the logic.**

UBIN 2.0.0 is the recommended stable release of UBIN: a Python reference runtime for arbitrary binary data plus a frozen language-neutral protocol that allows independently implemented C, C++, Java, Python, and other language components to exchange the same canonical values and framed messages.

UBIN keeps the proven v1 binary/security flows while promoting the universal runtime and polyglot protocol to a stable v2 contract.

## Install

```bash
python3 -m pip install ubin==2.0.0
```

Verify:

```bash
ubin --version
# UBIN 2.0.0
```

```python
import ubin
assert ubin.__version__ == "2.0.0"
```

Python 3.10–3.14 is the supported release matrix.

## What UBIN 2 provides

| Area | Stable capability |
|---|---|
| Universal binary input | paths, bytes, bytearray, memoryview, seekable binary streams |
| Bounded processing | positioned reads, streaming, hashing, explicit whole-file guards |
| Authenticated local storage | framed AES-256-GCM `.ubs` containers |
| Secure transfer | TLS 1.3 + X25519/HKDF + authenticated frames |
| Resumability | durable interruption-safe transfer resume |
| KRP | optional reversible ciphertext layout permutation |
| PNG carrier | authenticated lossless PNG representation and exact restoration |
| Universal facade | lazy `ubin.<capability>` namespaces from one import |
| Runtime/SDK | discovery, providers, manifests, diagnostics, permissions |
| Reproducibility | `ubin.toml`, lock, sync, runtime checks |
| Execution composition | resources, pipelines, workflows, async/parallel helpers |
| Polyglot protocol | stable canonical values + fixed UBIN 2 envelope |
| Conformance | shared Python/C/C++/Java vectors and CI compilation tests |

## 30-second Python example

```python
import ubin

with ubin.open("anything.bin") as obj:
    print(obj.info())
    print(obj.hash())
    for block in obj.stream():
        process(block)
```

Unknown filename extensions remain valid binary input; UBIN falls back to generic binary handling instead of rejecting the file.

## Stable UBIN 2 protocol

Languages communicate through bytes, not through each other's source syntax or object memory layouts.

```python
import ubin

message = ubin.protocol.encode_message({
    "language": "Python",
    "ok": True,
    "version": 2,
})

value = ubin.protocol.decode_message(message)
```

The same wire format is implemented by the conformance code under:

```text
interop/c/
interop/cpp/
interop/java/
interop/conformance/vectors.json
```

The protocol is independent of Python. Any language can interoperate by implementing [`docs/PROTOCOL_V2.md`](docs/PROTOCOL_V2.md) and passing the shared vectors.

## Binary and security examples

### Hash without reading the complete file into memory

```python
with ubin.open("large.bin") as obj:
    print(obj.hash("sha256"))
```

### Authenticated local container

```python
receipt = ubin.secure("document.pdf").save("document.ubs")
ubin.decrypt("document.ubs", "document-restored.pdf", key=receipt.key)
```

### Authenticated lossless PNG carrier

```python
packed = ubin.to_image(
    "anything.bin",
    "anything.ubin.png",
    passphrase="use a long unique passphrase",
)

restored = ubin.from_image(
    "anything.ubin.png",
    "anything-restored.bin",
    passphrase="use a long unique passphrase",
)

assert packed.sha256 == restored.sha256
```

### Secure resumable network transfer

```python
receipt = ubin.secure("large.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
    permutation=True,
)
print(receipt.sha256)
```

Production deployments must use real certificate infrastructure. Development certificates are for tests/demos only.

## Universal capability facade

```python
import ubin

index = ubin.search.linear([10, 20, 30], 20)
ordered = ubin.sort.values([3, 1, 2])
stack = ubin.ds.Stack()
```

Discover capabilities without eagerly loading every module:

```bash
ubin list
ubin list --json
ubin doctor
```

UBIN never silently installs provider packages during normal attribute access. Provider installation is explicit.

## CLI

```bash
ubin --help
ubin --version
ubin info anything.bin
ubin hash anything.bin
ubin secure input.bin input.ubs --key-out input.key
ubin restore input.ubs restored.bin --key-file input.key
ubin image-pack input.bin input.ubin.png
ubin image-restore input.ubin.png restored.bin
ubin list
ubin doctor
ubin init
ubin lock
ubin sync
ubin protocol-vector
ubin demo
```

## Correctness and limits

UBIN 2 deliberately avoids claims that software or information theory cannot guarantee:

- correctness means exact byte equality / cryptographic hash equality;
- streaming work is normally O(n) in processed bytes with bounded auxiliary memory;
- arbitrary encrypted/high-entropy data cannot be losslessly compressed to an arbitrarily small fixed target;
- KRP is not encryption and never replaces authenticated encryption;
- the UBIN protocol is framing/serialization, not authentication or confidentiality;
- malformed protected data fails closed and validated output is not published prematurely;
- a stable release means all defined gates pass and there are no known release-blocking defects, not that future defects are mathematically impossible.

## Release validation

Before v2.0.0 is published, the release gate requires:

1. full Python regression suite passes;
2. coverage meets the configured threshold;
3. Ruff/static/security checks pass;
4. C/C++ compile with strict warnings and pass conformance vectors;
5. Java compiles and passes the same vectors;
6. Python 3.10–3.14 CI passes on Linux, macOS, and Windows;
7. wheel and sdist build and pass Twine validation;
8. clean wheel install succeeds outside the repository;
9. release tag equals package version;
10. Trusted PyPI publication and fresh public installation are verified.

See [`FINAL_VALIDATION.md`](FINAL_VALIDATION.md) and [`docs/TESTING.md`](docs/TESTING.md).

## Documentation

- [`docs/V2_0_0_STABLE.md`](docs/V2_0_0_STABLE.md) — v2 stable architecture/release principles
- [`docs/PROTOCOL_V2.md`](docs/PROTOCOL_V2.md) — frozen language-neutral wire specification
- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) — installation and first operations
- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — practical usage
- [`docs/API.md`](docs/API.md) — public Python API
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture and data flows
- [`docs/CAPABILITIES.md`](docs/CAPABILITIES.md) — capability/provider model
- [`docs/SECURITY.md`](docs/SECURITY.md) — security model and trust boundaries
- [`docs/COMPLEXITY_AND_PERFORMANCE.md`](docs/COMPLEXITY_AND_PERFORMANCE.md) — complexity and benchmarking
- [`docs/TESTING.md`](docs/TESTING.md) — validation procedure
- [`docs/RELEASING.md`](docs/RELEASING.md) — release process
- [`CHANGELOG.md`](CHANGELOG.md) — version history

Historical v1 architecture documents remain in `docs/` for compatibility context.

## License

MIT. See [`LICENSE`](LICENSE).
