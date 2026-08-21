# Getting Started with UBIN v1.0.5

This guide assumes no prior UBIN setup.

## Requirements

- Python 3.10 or newer
- `pip`
- a supported operating system capable of installing the `cryptography` dependency

## 1. Create an isolated environment

macOS/Linux:

```bash
mkdir ubin-quickstart
cd ubin-quickstart

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

Windows PowerShell:

```powershell
mkdir ubin-quickstart
cd ubin-quickstart

py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

## 2. Install UBIN

```bash
python -m pip install ubin==1.0.5
```

Verify:

```bash
ubin --version
```

Expected:

```text
UBIN 1.0.5
```

## 3. Open your first file

Create a test file:

```bash
printf 'Hello UBIN\n' > hello.custom
```

Run:

```python
import ubin

with ubin.open("hello.custom") as obj:
    print(obj.info())
    print(obj.read_at(0, 5))
    print(obj.hash())
```

The extension `.custom` does not need to be registered. UBIN accepts arbitrary bytes and uses a generic binary type when its bounded signature detector does not recognize the content.

## 4. Stream instead of loading everything

```python
import ubin

with ubin.open("large.bin") as obj:
    for block in obj.stream(block_size=1024 * 1024):
        # process one block at a time
        print(len(block))
```

The total file can be much larger than one block. The stream does not intentionally materialize the complete file.

## 5. Verify exact content

```python
with ubin.open("large.bin") as obj:
    digest = obj.hash("sha256")
    assert obj.verify(digest)
```

`verify()` checks the cryptographic digest. UBIN correctness is about exact bytes, not approximate similarity.

## 6. Create and restore a local secure container

```python
import ubin

secured = ubin.secure("hello.custom").save("hello.ubs")

ubin.decrypt(
    "hello.ubs",
    "hello-restored.custom",
    key=secured.key,
)
```

Compare:

```bash
cmp hello.custom hello-restored.custom
```

No output from `cmp` means the files are byte-identical.

## 7. Create and restore a PNG carrier

```python
import ubin

ubin.to_image(
    "hello.custom",
    "hello.ubin.png",
    passphrase="use-a-long-unique-private-passphrase",
)

ubin.from_image(
    "hello.ubin.png",
    "hello-from-image.custom",
    passphrase="use-a-long-unique-private-passphrase",
)
```

Do not edit, resize, screenshot, recolor, or convert the PNG to JPEG. The carrier depends on exact pixel bytes.

## 8. CLI equivalents

```bash
ubin info hello.custom
ubin hash hello.custom

ubin secure hello.custom hello.ubs --key-out hello.key
ubin restore hello.ubs hello-restored.custom --key-file hello.key

ubin image-pack hello.custom hello.ubin.png
ubin image-restore hello.ubin.png hello-image-restored.custom
```

The image commands prompt for the passphrase by default so it does not need to appear directly in shell history.

## 9. Next reading

- [`USER_GUIDE.md`](USER_GUIDE.md) for practical patterns
- [`HOW_UBIN_WORKS.md`](HOW_UBIN_WORKS.md) for internals
- [`API.md`](API.md) for the public interface
- [`TESTING.md`](TESTING.md) if you cloned the repository
