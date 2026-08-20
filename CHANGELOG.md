# Changelog

## 1.0.0

- Finalized public Python package/API
- Added lossless authenticated PNG carrier
- Added scrypt + HKDF key derivation for passphrase-based image carriers
- Added bounded file-level KRP helpers
- Added PNG structural/CRC/filter validation and fail-closed restoration
- Added `ubin` CLI
- Added local browser UI and final image demo
- Added architecture/API/security documentation
- Preserved v0.1-v0.5 behavior and regression tests
- Final supplied suite: 86 passing tests

## 0.5.0

- Keyed Reversible Permutation (KRP)

## 0.4.0

- Durable interruption-safe resumable transfer

## 0.3.0

- TLS 1.3 client/server transfer with X25519/HKDF session keys

## 0.2.0

- Local framed AES-256-GCM secure container

## 0.1.0

- Universal lazy binary core
