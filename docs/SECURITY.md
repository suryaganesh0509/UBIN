# UBIN v1.0 Security Notes

## Security primitives

UBIN v1 relies on established building blocks:

- TLS 1.3 for transport protection and server certificate authentication
- X25519 for ephemeral application key agreement
- HKDF-SHA256 for key separation
- AES-256-GCM for authenticated encryption
- SHA-256 for exact-restoration verification
- scrypt for passphrase-to-master-key derivation in the PNG carrier

KRP is only a reversible ciphertext-layout transform. It is not advertised as extra cryptographic strength.

## Fail-closed behavior

UBIN is designed so that malformed/tampered input raises controlled errors and does not publish a successful destination. Important flows use temporary files and atomic replacement.

## PNG carrier

The carrier is lossless only when the PNG file itself is preserved byte/pixel-equivalently. Resizing, image optimization that changes pixels, color conversion, re-encoding with PNG filters other than the UBIN format, JPEG conversion, screenshots, or editing are not supported carrier operations.

A wrong passphrase must fail authentication. The passphrase is never stored in the PNG.

## Password/passphrase quality

scrypt slows guessing but cannot make a weak passphrase strong. Use a long, unique passphrase and protect it separately from the carrier.

## TLS certificates

`generate_localhost_certificate()` is a demo/test helper. Real deployments should use their organization/platform PKI and certificate lifecycle.

## Resume state

A durable checkpoint is advanced only after a frame authenticates and its plaintext is durably written. Source identity and resume tickets are checked before continuation.

## Non-goals / limitations

- UBIN does not claim mathematical impossibility of crashes from OS termination, storage failure, hardware failure, or interpreter/runtime bugs.
- v1 does not claim post-quantum key establishment.
- v1 does not claim arbitrary large input can be compressed to a fixed tiny image.
- The Python package is the reference implementation; a cross-language UBIN specification can be frozen separately for other languages.
