# UBIN-PY 0.1 Core

UBIN-PY 0.1 is the first reference implementation of UBIN.

Its job is deliberately small:

- one path in -> one `UbinObject`
- arbitrary/unknown file extension accepted
- extension-independent bounded signature probe
- lazy reads
- positioned reads
- bounded-memory streaming
- SHA-256 verification
- controlled UBIN exceptions
- no source modification

## Install for development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Run tests

```bash
pytest -q
```

## Try it

```python
import ubin

with ubin.open("anything.bin") as x:
    print(x.info())
    print(x.read(64))
    print(x.read_at(1024, 64))
    print(x.hash())
```

## Design rule

`ubin.open()` must not silently materialize an entire large object in RAM.

`bytes()` is therefore explicit and supports a `max_bytes` safety ceiling.

## Next phase

`UBIN Secure 0.2` will add:

- secure frame format
- per-frame authenticated encryption
- exact reconstruction
- atomic output
- corruption/tamper tests

Networking and PNG/KRP come only after the local secure container passes.
