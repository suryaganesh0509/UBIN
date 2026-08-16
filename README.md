# UBIN-PY 0.2 — Core + Secure Local Prototype

UBIN 0.2 builds on the tested UBIN 0.1 lazy binary access layer.

## UBIN Core

```python
import ubin

with ubin.open("anything.unknown") as x:
    print(x.info())
    print(x.read_at(0, 64))
    print(x.hash())
```

Unknown extensions remain valid UBIN inputs.

## UBIN Secure 0.2

Phase 0.2 deliberately proves local authenticated encryption before networking,
KRP pixel permutation, or PNG carriers are added.

```python
import ubin

secured = ubin.secure("sample.surya123")
receipt = secured.save("sample.ubs")

print("Key:", receipt.key.hex())
print("SHA-256:", receipt.sha256)

restore = ubin.decrypt(
    "sample.ubs",
    "sample_restored.surya123",
    key=receipt.key,
)

print("Restored SHA-256:", restore.sha256)
```

### Security properties in 0.2

- AES-256-GCM per frame
- fresh random 96-bit nonce base per container
- deterministic unique 96-bit nonce derivation per frame
- random 128-bit session ID
- header and frame metadata authenticated as AAD
- SHA-256 final digest encrypted/authenticated as a final record
- fixed/bounded streaming memory
- wrong keys rejected
- modified ciphertext rejected
- malformed/truncated containers rejected
- trailing unauthenticated data rejected
- output created through same-directory temporary file + `os.replace`
- existing outputs are not overwritten unless explicitly requested
- encryption key is **not stored inside the secure container**

### Important

0.2 exposes `receipt.key` only because this is a local cryptographic
round-trip prototype. Do not transmit that key beside the `.ubs` file.

UBIN 0.3 will introduce authenticated client/server session key establishment
so the developer does not manually pass raw keys.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest -q
```

## Manual test

Create `test_secure_ubin.py`:

```python
import ubin

secured = ubin.secure("sample.surya123")
receipt = secured.save("sample.ubs")

print("Secure file:", receipt.output)
print("Frames:", receipt.frame_count)
print("Original SHA-256:", receipt.sha256)
print("Temporary phase-0.2 key:", receipt.key.hex())

restored = ubin.decrypt(
    "sample.ubs",
    "sample_restored.surya123",
    key=receipt.key,
)

print("Restored:", restored.output)
print("Restored SHA-256:", restored.sha256)
print("MATCH:", restored.sha256 == receipt.sha256)
```

Run:

```bash
python test_secure_ubin.py
```

Expected final line:

```text
MATCH: True
```
