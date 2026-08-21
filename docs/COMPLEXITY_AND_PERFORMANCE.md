# UBIN Complexity and Performance

## Why complexity and benchmark speed are different

Complexity describes how work grows as the input grows.

Benchmark speed describes what happened on a particular machine, Python version, storage device, network, and configuration.

UBIN documents both concepts separately.

Let:

- `n` = total source size in bytes
- `k` = requested read length
- `b` = stream block size
- `f` = secure/network frame size

## Time complexity

| Operation | Time complexity | Reason |
|---|---:|---|
| open/stat a filesystem source | effectively O(1) vs total `n` | fixed metadata + bounded type probe |
| type detection | O(1) vs total `n` | fixed-size prefix probe |
| `read(k)` | O(k) | returns up to k bytes |
| `read_at(offset, k)` | O(k) | reads requested range |
| `seek()` / `tell()` | approximately O(1) API operation | filesystem/runtime dependent |
| full `stream()` | O(n) | all bytes must be visited |
| `bytes()` | O(n) | all bytes materialized |
| full cryptographic hash | O(n) | all bytes hashed |
| local encryption | O(n) | all plaintext encrypted/authenticated |
| local restore | O(n) | all ciphertext authenticated/decrypted |
| network send/receive | O(n) | all payload bytes transferred |
| KRP | O(n) data movement | ciphertext blocks are visited/reordered |
| PNG carrier creation | O(n) overall | payload must be protected, represented, and encoded |
| PNG carrier restore | O(n) overall | representation must be decoded, validated, reversed, decrypted |

No implementation can compute an exact full-file hash, encrypt the entire file, or transmit the entire file in true O(1) time independent of `n`.

## Auxiliary memory

For streaming-oriented filesystem operations, UBIN aims for memory governed primarily by block/frame sizes rather than total file size.

Typical model:

```text
streaming                 O(b)
hashing                   O(b)
framed encryption         O(f) plus bounded crypto/I/O buffers
framed transfer           O(f) plus bounded protocol buffers
resume                    bounded per active frame/state metadata
```

`bytes()` is intentionally different: it materializes the complete object, so the returned value itself is O(n) memory.

Memory-backed sources already exist in memory before UBIN wraps them.

PNG carrier creation/restore includes image-encoding/decoding stages, so peak memory can be larger than a simple streaming hash. Do not assume its peak memory equals the basic stream block size.

## Startup behavior

Opening a regular file does not intentionally scale with the total file size. UBIN reads a fixed type-detection probe rather than scanning the whole source.

This is useful for huge files: metadata inspection can remain quick even when a full hash or encryption would necessarily take much longer.

## What determines real speed?

Real throughput depends on:

- CPU and cryptographic acceleration
- disk/SSD speed
- filesystem and OS cache state
- Python version and interpreter build
- `cryptography` version/backend
- frame/block sizes
- source/destination storage
- TLS/network bandwidth and latency
- PNG compression behavior
- competing system workload

Therefore UBIN must not claim one universal throughput number.

## Reproducible local benchmark

Create a temporary benchmark file:

```bash
python - <<'PY'
from pathlib import Path
import os

size = 256 * 1024 * 1024
path = Path("ubin-benchmark-256MiB.bin")

with path.open("wb") as f:
    remaining = size
    block = 1024 * 1024
    while remaining:
        chunk = os.urandom(min(block, remaining))
        f.write(chunk)
        remaining -= len(chunk)

print(path, path.stat().st_size)
PY
```

### Hash throughput

```bash
python - <<'PY'
import time
import ubin

path = "ubin-benchmark-256MiB.bin"

with ubin.open(path) as obj:
    start = time.perf_counter()
    digest = obj.hash()
    elapsed = time.perf_counter() - start

mib = obj.size / (1024 * 1024)
print("SHA-256:", digest)
print(f"Time: {elapsed:.3f} s")
print(f"Throughput: {mib / elapsed:.2f} MiB/s")
PY
```

### Stream throughput

```bash
python - <<'PY'
import time
import ubin

path = "ubin-benchmark-256MiB.bin"

with ubin.open(path) as obj:
    start = time.perf_counter()
    total = 0
    for block in obj.stream():
        total += len(block)
    elapsed = time.perf_counter() - start

mib = total / (1024 * 1024)
print(f"Bytes: {total}")
print(f"Time: {elapsed:.3f} s")
print(f"Throughput: {mib / elapsed:.2f} MiB/s")
PY
```

## Better benchmark methodology

For publishable numbers:

1. Record hardware, OS, Python, UBIN and `cryptography` versions.
2. Test multiple sizes such as 1 MiB, 10 MiB, 100 MiB, and 1 GiB when practical.
3. Run each case multiple times.
4. Report median and range, not one lucky result.
5. Distinguish warm filesystem-cache results from cold I/O.
6. For network tests, report both endpoints and network conditions.
7. Report frame/block sizes.
8. Benchmark secure, restore, image pack, and image restore separately.
9. Measure peak memory with an appropriate profiling tool.
10. Never generalize one machine's number into a universal guarantee.

## Correctness / “accuracy”

UBIN does not produce probabilistic predictions.

The relevant requirement is exactness:

```text
source bytes == restored bytes
```

and/or:

```text
SHA256(source) == SHA256(restored)
```

A successful authenticated restore should be exact. If authentication/integrity fails, UBIN should reject the operation rather than report an approximate result.
