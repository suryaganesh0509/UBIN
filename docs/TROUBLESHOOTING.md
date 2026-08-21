# UBIN Troubleshooting

## `ModuleNotFoundError: No module named 'ubin'`

Check which interpreter is active:

```bash
python -c "import sys; print(sys.executable)"
python -m pip show ubin
```

Install into the same interpreter:

```bash
python -m pip install ubin
```

## `ubin: command not found`

The console script is installed inside the active Python environment.

Activate your environment and check:

```bash
python -m pip show ubin
python -m ubin.cli --version
```

If `python -m ubin.cli --version` works but `ubin --version` does not, inspect your environment's `bin`/`Scripts` path.

## Wrong local key

A `.ubs` local container requires its matching key.

Expected behavior:

- authentication fails
- restored output is not accepted as successful

Do not attempt to “repair” encrypted data by bypassing authentication.

## Wrong image passphrase

Use the same passphrase used during `to_image()` / `image-pack`.

Expected behavior is rejection, not partial restoration.

## PNG carrier stopped working after editing

UBIN PNG carriers require exact lossless pixel bytes.

Unsupported transformations include:

- resizing
- JPEG conversion
- screenshots
- color-space transformations
- image-editor save operations that alter pixel bytes

Use the original `.ubin.png` artifact.

## Destination already exists

UBIN fails safely instead of silently overwriting output by default.

If replacement is intentional, use the appropriate `overwrite=True` API argument or CLI `--overwrite` switch.

## Unknown extension shows `application/octet-stream`

That is expected.

UBIN accepts unknown binary formats. Type recognition is metadata, not a requirement for use.

## Large file seems slow

Full-file hashing, encryption, transfer, KRP and PNG-carrier operations are O(n). They must process the bytes.

Check:

- storage throughput
- network throughput
- CPU load
- block/frame size
- Python/cryptography versions

See [`COMPLEXITY_AND_PERFORMANCE.md`](COMPLEXITY_AND_PERFORMANCE.md).

## Memory usage

Prefer:

```python
for block in obj.stream():
    ...
```

instead of:

```python
data = obj.bytes()
```

for large inputs.

`bytes()` intentionally returns the complete object and therefore requires memory proportional to the returned data.

## TLS certificate verification failure

Common causes:

- wrong CA file
- hostname mismatch
- expired certificate
- self-signed/untrusted certificate
- incorrect server certificate

Do not disable certificate verification as a production “fix.” Configure correct trust material.

## Resume does not continue

Resume is tied to authenticated state and the original source identity/metadata.

Possible causes include:

- source changed after interruption
- state directory removed
- resume ticket corrupted
- server resume state unavailable/corrupted
- incompatible parameters

These conditions should fail rather than silently resume from unsafe state.

## `permutation=True` fails without resume

Current stable v1 behavior requires:

```python
resume=True,
permutation=True,
```

KRP transfer is integrated with the resumable transfer path.

## PyPI version confusion

Check:

```bash
python -m pip index versions ubin
python -m pip show ubin
python -c "import ubin; print(ubin.__version__)"
```

If testing a new release, use a clean virtual environment to avoid confusing an editable checkout with the installed PyPI wheel.

## Editable install vs PyPI install

An editable install:

```bash
python -m pip install -e .
```

loads code from your checkout.

A normal public install:

```bash
python -m pip install ubin
```

loads the installed distribution.

Use separate environments for independent release validation.

## Need more diagnosis?

Collect:

```bash
python --version
python -m pip --version
python -m pip show ubin
ubin --version
uname -a
```

On Windows use:

```powershell
Get-ComputerInfo
```

Do not paste private keys, passphrases, tokens, or sensitive user data into public issues.
