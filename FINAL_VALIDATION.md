# UBIN v1.0.0 Final Validation

This file records the release-candidate validation performed before packaging.

## Reference environment used for validation

- Python: 3.13.5
- cryptography: 46.0.4
- Platform: Linux x86_64 validation container

The project declares Python `>=3.10` and `cryptography>=42`. The user should rerun the supplied suite on the target Mac before creating the Git v1.0.0 tag.

## Source-tree regression suite

```text
86 passed
```

Coverage categories include:

- filesystem, memory and seekable-stream binary sources
- unknown/extensionless input
- bounded streaming/read_at/hash behavior
- local AES-256-GCM secure containers
- wrong-key/tamper/truncation rejection
- TLS 1.3 client/server transfer
- X25519 + HKDF session derivation
- untrusted certificate rejection
- durable resume and server restart recovery
- changed-source and tampered-ticket rejection
- KRP exact reversal, context binding and network resume
- PNG image-carrier round trips across edge sizes
- wrong-passphrase rejection
- PNG CRC/tamper/truncation/filter transformation rejection
- carrier randomization
- CLI version/info/hash/image pack/image restore
- public v1 API symbols and dependency checks

## Manual demonstrations

All of the following were executed successfully:

```text
manual_secure_demo.py   -> MATCH: True
manual_network_demo.py  -> TLSv1.3, NO MANUAL KEY: True, MATCH: True
manual_resume_demo.py   -> resumed from frame 3, MATCH: True
manual_krp_demo.py      -> KRP, resume, NO KRP KEY EXPOSED: True, MATCH: True
manual_image_demo.py    -> PNG signature valid, krp+png, MATCH: True
```

## Browser demo

The local end-user UI was started and its home page was successfully fetched from `127.0.0.1:5055`.

## Dependency audit

Static import inspection found exactly one non-standard-library runtime dependency:

```text
cryptography
```

NumPy, Pillow, Flask and other optional frameworks are not required by the UBIN runtime.

## Wheel smoke test

The final wheel was installed into a fresh virtual environment (with the validation environment's cryptography available) and passed:

```text
IMPORT_OK 1.0.0
PUBLIC True
WHEEL_PNG True
WHEEL_MATCH True True
UBIN 1.0.0
```

## Scope of the claim

These checks validate the supplied implementation and test matrix; they are not a proof that every possible input, operating-system failure, cryptographic misuse by an application, or future dependency/runtime bug is impossible. UBIN is designed to fail closed and exposes tests so downstream users can rerun validation in their own environments.
