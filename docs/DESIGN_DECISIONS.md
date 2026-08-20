# UBIN design decisions: why the layers exist

This note documents the decisions that are easiest to misunderstand when reading the code quickly.

## 1. Why AES-GCM remains the security boundary

UBIN deliberately avoids inventing a cipher. AES-256-GCM gives authenticated encryption: a modified frame is rejected before its plaintext is accepted. This matters more than making ciphertext "look random" because confidentiality without integrity would allow silent corruption or active manipulation.

KRP therefore runs **after** authenticated encryption. It changes layout, not trust.

```text
plaintext -> AES-256-GCM -> authenticated ciphertext -> optional KRP -> transport/carrier
```

On restore the order is reversed:

```text
transport/carrier -> reverse KRP -> AES-GCM authenticate/decrypt -> plaintext
```

If reverse KRP is wrong, AES-GCM authentication fails. KRP is never allowed to make unauthenticated bytes look valid.

## 2. Why have KRP at all if GCM is already secure?

KRP exists for a different engineering purpose: a deterministic, key-derived, reversible mapping of ciphertext blocks without serializing a permutation table. That is useful for experimenting with carrier layouts while keeping the encrypted payload exact and recoverable.

It does **not** increase the cryptographic security claim. Removing KRP should not reduce AES-GCM's confidentiality/authenticity guarantees.

That separation is important: security-critical reasoning stays attached to standardized primitives, while carrier/layout experimentation remains replaceable.

## 3. Why per-frame nonces are derived instead of randomizing every frame independently

AES-GCM requires nonce uniqueness for a given key. UBIN uses a fresh random 96-bit nonce base for a secure transfer/container and derives the per-frame nonce from the base plus frame number. This gives two useful properties:

1. within one transfer, different frame numbers map to different nonces;
2. the receiver can derive the correct nonce without storing a nonce table for every frame.

The nonce is not secret. Uniqueness is the critical property.

## 4. What changes when a resumable transfer reconnects?

Resume is intentionally designed around **durable plaintext progress**, not preservation of an old encryption key.

A checkpoint advances only after:

1. frame metadata is structurally valid;
2. AES-GCM authentication succeeds;
3. plaintext is written to the partial destination;
4. the write is flushed/synchronized;
5. authenticated resume state is updated.

If the connection dies, a new TLS/X25519 session creates fresh session key material. The receiver reports the authenticated durable frame position, and the client starts from that source offset using the new session/transfer cryptographic context.

This avoids treating a raw session key as persistent resume state.

## 5. Why SHA-256 when AES-GCM already authenticates frames?

Per-frame AEAD answers "was this encrypted frame authentic?". The final SHA-256 check answers the system-level question "did the reconstructed file exactly match the sender's full source byte sequence?".

The hash is therefore an end-to-end reconstruction invariant and an easy observable for tests/demos. It is not a replacement for AES-GCM authentication.

## 6. Why the PNG codec is intentionally restrictive

A general PNG decoder accepts many legal encodings (different filters, ancillary chunks, interlacing). UBIN's carrier profile is intentionally narrower: non-interlaced 8-bit RGBA with filter type 0 scanlines. Restricting accepted syntax reduces parser ambiguity and makes pixel-to-byte reconstruction easier to reason about.

A normal image editor is allowed to create a visually identical PNG while changing pixel bytes/encoding. UBIN treats such transformations as unsupported because the PNG is a binary carrier, not a photograph.

## 7. Why v1.0.1 adds fuzzing instead of just more example tests

Hand-written unit tests mostly exercise cases developers already imagined. Property-based and coverage-guided fuzzing search a larger input space and are particularly useful around parsers, lengths, block boundaries, truncation, and state-machine assumptions.

The goal is not to claim "fuzzed = secure". The goal is to continuously create opportunities for malformed inputs to find assumptions that ordinary regression tests missed.

## 8. What would justify changing these decisions?

A future UBIN version should only replace these layers when measurements or external review show a concrete improvement in at least one of:

- security margin
- correctness
- interoperability
- runtime/memory cost
- resumability/recovery behavior
- implementation simplicity

Novelty alone is not enough.
