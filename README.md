# UBIN v1.0.6 — Universal Platform Foundation

> **UBIN handles the bytes. You handle the logic.**

UBIN is a Python reference implementation for working with arbitrary binary data through one consistent interface. It provides lazy binary access, bounded-memory streaming, hashing, authenticated local containers, TLS 1.3 transfer, interruption-safe resume, optional KRP ciphertext layout, and a lossless PNG carrier.

**v1.0.6 introduces the universal single-import foundation.** Existing binary/security behavior remains available while new capability namespaces are resolved lazily from one normal `import ubin` entry point.

## Start here

### Install

```bash
python3 -m pip install ubin
```

Verify:

```bash
ubin --version
```

Expected for this release:

```text
UBIN 1.0.6
```

Python:

```python
import ubin
print(ubin.__version__)
```

## 30-second example

```python
import ubin

with ubin.open("anything.bin") as obj:
    print(obj.info())
    print("Size:", obj.size)
    print("Type:", obj.type)
    print("SHA-256:", obj.hash())

    for block in obj.stream():
        process(block)
```

UBIN does not require a recognized filename extension. Unknown content remains valid binary input and safely falls back to a generic binary type.

## What UBIN can do

| Goal | UBIN entry point |
|---|---|
| Open a file, bytes, bytearray, memoryview, or seekable binary stream | `ubin.open(...)` |
| Read without loading an entire file | `obj.read(...)`, `obj.read_at(...)` |
| Stream with bounded memory | `obj.stream(...)` |
| Hash / verify | `obj.hash(...)`, `obj.verify(...)` |
| Create a local authenticated container | `ubin.secure(...).save(...)` |
| Restore a local authenticated container | `ubin.decrypt(...)` |
| Send securely over the network | `ubin.secure(...).send(...)` |
| Run a reference receive server | `ubin.secure_server(...)` |
| Create a lossless authenticated PNG carrier | `ubin.to_image(...)` |
| Restore a PNG carrier | `ubin.from_image(...)` |
| Linear / binary search | `ubin.search.linear(...)`, `ubin.search.binary(...)` |
| Sort values | `ubin.sort.values(...)`, `ubin.sort.merge(...)`, `ubin.sort.quick(...)` |
| Core data structures | `ubin.ds.Stack`, `ubin.ds.Queue`, `ubin.ds.BinaryTree`, `ubin.ds.Graph` |

## Mental model

```text
File / bytes / bytearray / memoryview / seekable stream
                         │
                         ▼
                     ubin.open()
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
       inspect        read/seek       stream
          │              │              │
          └──────────────┼──────────────┘
                         ▼
                     hash/verify

Optional protection paths:

source ──► AES-256-GCM local container ──► exact restore

source ──► TLS 1.3 ──► X25519/HKDF ──► AES-GCM frames
                                      └─► resume
                                      └─► optional KRP

source ──► AES-GCM ──► KRP ──► lossless RGBA PNG ──► exact restore
```

## Important guarantees and limits

- **Unknown extension does not mean unsupported input.**
- UBIN does not silently read an arbitrary file completely into memory.
- Full-file work such as hashing, encryption, transfer, KRP, and carrier creation is necessarily **O(n)** in bytes processed.
- Streaming auxiliary memory is bounded by the chosen block/frame sizes rather than by total file size.
- AES-256-GCM provides authenticated encryption.
- TLS 1.3 protects network transport and server authentication.
- X25519 + HKDF-SHA256 derive fresh application session/transfer material.
- KRP is a reversible ciphertext-layout transformation. **It is not a replacement for encryption.**
- Restored output is published only after validation succeeds in the protected flows.
- The PNG carrier is lossless. Resizing, JPEG conversion, screenshots, color conversion, or image editing are not supported carrier operations.
- UBIN cannot losslessly compress arbitrary high-entropy or encrypted multi-gigabyte data into a fixed tiny image.
- Correctness is evaluated by **exact byte equality / cryptographic hash equality**, not a prediction-style “accuracy percentage.”

## Installation choices

### Normal user

```bash
python3 -m pip install ubin
```

### Exact release

```bash
python3 -m pip install ubin==1.0.6
```

### Repository development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev,security]"
```

Windows PowerShell activation:

```powershell
.venv\Scripts\Activate.ps1
```

## Common examples

### Unknown/custom extension

```python
import ubin

with ubin.open("archive.futureXYZ") as obj:
    print(obj.name)
    print(obj.size)
    print(obj.type)
```

### Raw memory

```python
import ubin

payload = b"hello UBIN"
with ubin.open(payload, name="packet.bin") as obj:
    print(obj.hash())
```

### Exact positioned read

```python
with ubin.open("large.bin") as obj:
    header = obj.read_at(0, 64)
```

### Local authenticated container

```python
import ubin

receipt = ubin.secure("document.pdf").save("document.ubs")

ubin.decrypt(
    "document.ubs",
    "document-restored.pdf",
    key=receipt.key,
)
```

The raw key in the legacy/local container API is for the local save/restore model. Network transfer does not expose the raw transfer key in the public receipt.

### Lossless PNG carrier

```python
import ubin

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

print(packed.sha256)
print(restored.sha256)
```

### Network send with resume + KRP

```python
import ubin

receipt = ubin.secure("large.bin").send(
    "server.example",
    port=9443,
    cafile="trusted-ca.pem",
    resume=True,
    permutation=True,
)

print(receipt.sha256)
```

Production deployments must use real certificate infrastructure. UBIN's localhost certificate helper is for tests/demos only.

## CLI

```bash
ubin --help
ubin info anything.bin
ubin hash anything.bin

ubin secure input.bin input.ubs --key-out input.key
ubin restore input.ubs restored.bin --key-file input.key

ubin image-pack input.bin input.ubin.png
ubin image-restore input.ubin.png restored.bin

ubin demo
```

For image-carrier automation without writing a passphrase directly in shell history:

```bash
export UBIN_PASS='your long unique passphrase'
ubin image-pack input.bin input.ubin.png --passphrase-env UBIN_PASS
ubin image-restore input.ubin.png restored.bin --passphrase-env UBIN_PASS
```

## Documentation map

- [`docs/README.md`](docs/README.md) — choose the right documentation path
- [`docs/UBIN_VISION.md`](docs/UBIN_VISION.md) — long-term universal-platform direction
- [`docs/V1_0_6_UNIVERSAL_FACADE.md`](docs/V1_0_6_UNIVERSAL_FACADE.md) — v1.0.6 facade/capability architecture
- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) — first installation and first successful operations
- [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) — practical usage patterns
- [`docs/HOW_UBIN_WORKS.md`](docs/HOW_UBIN_WORKS.md) — end-to-end explanation
- [`docs/API.md`](docs/API.md) — public Python API reference
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture and data flows
- [`docs/COMPLEXITY_AND_PERFORMANCE.md`](docs/COMPLEXITY_AND_PERFORMANCE.md) — time/space complexity and benchmarking
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model and security boundaries
- [`docs/TESTING.md`](docs/TESTING.md) — reproduce the release validation
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — common failures and fixes
- [`docs/FAQ.md`](docs/FAQ.md) — quick answers
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — important design trade-offs
- [`docs/RELEASING.md`](docs/RELEASING.md) — release process
- [`CHANGELOG.md`](CHANGELOG.md) — version history

## Validation baseline

The v1.0.4 runtime baseline that v1.0.5 documents was independently validated with:

- 116 pytest cases passing
- coverage above the enforced 82% threshold
- 46/46 public-consumer integration checks
- Ruff clean
- Bandit with no medium/high findings at the configured gate
- `pip-audit` with no known dependency vulnerabilities at validation time
- Linux, macOS, and Windows GitHub CI
- clean wheel/sdist build and installation
- successful public PyPI installation

These results increase confidence but are not a formal proof, independent security audit, or performance guarantee on every machine.

## Performance

UBIN intentionally does **not** publish a universal “X MB/s” claim because throughput depends on CPU, storage, network, cryptography version, frame size, Python version, and workload.

See [`docs/COMPLEXITY_AND_PERFORMANCE.md`](docs/COMPLEXITY_AND_PERFORMANCE.md) for:

- operation-by-operation complexity
- bounded-memory expectations
- reproducible benchmark commands
- how to report throughput honestly

## Version roadmap

```text
v1.0.4  release-integrity stable baseline
v1.0.5  documentation & developer-understanding patch
v1.0.6  universal single-import capability foundation
```

The v1.0.6 foundation makes the normal developer entry point:

```python
import ubin
```

and should not need to import user-facing functionality from internal UBIN modules.

## License

MIT. See [`LICENSE`](LICENSE).

## Capability management

Inspect the universal capability layer without importing heavy providers:

```bash
ubin list
ubin list --json
```

Future provider packages can be added explicitly:

```bash
ubin add <capability> --package <trusted-provider-package>
```

Normal application execution never silently installs packages.
