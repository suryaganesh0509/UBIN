# Migrating from UBIN 1.x to UBIN 2.0.0

UBIN 2 is intentionally conservative about proven file/security behavior. Most normal Python users can upgrade without changing established binary, hashing, secure-container, transfer, resume, KRP, or image-carrier calls.

## Normal upgrade

```bash
python3 -m pip install --upgrade "ubin==2.0.0"
ubin --version
```

## Preserved public patterns

These established patterns remain supported and regression-tested:

```python
import ubin

ubin.open(...)
ubin.secure(...)
ubin.decrypt(...)
ubin.secure_server(...)
ubin.to_image(...)
ubin.from_image(...)
ubin.search
ubin.sort
ubin.ds
```

## New stable protocol surface

The v1.0.7 protocol was explicitly a draft. v2.0.0 freezes it as Protocol 2 and adds message helpers:

```python
payload = ubin.protocol.encode_value(value)
value = ubin.protocol.decode_value(payload)

message = ubin.protocol.encode_message(value)
value = ubin.protocol.decode_message(message)
```

Do not treat v1.0.7 draft bytes as a separately versioned production ABI; the v2 conformance vectors are the stable source of truth.

## Capability providers

Provider authors must test their provider against UBIN 2.0.0 and declare an appropriate compatibility range. The capability API identifier remains explicit in the manifest. A provider should not claim v2 compatibility simply because it imports successfully.

## Cross-language applications

C, C++, Java, and other languages do not need to call into Python. Implement `docs/PROTOCOL_V2.md`, consume `interop/conformance/vectors.json`, and pass the equivalent malformed-input tests for the host language.

## Release immutability

Once v2.0.0 is published, its tag and artifacts are immutable. Any correction belongs in 2.0.1 or later rather than rewriting 2.0.0.
