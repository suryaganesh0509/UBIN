from __future__ import annotations

import hashlib
import secrets
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..errors import UbinHandshakeError

HELLO_MAGIC = b"UBH3"
SESSION_MAJOR = 0
SESSION_MINOR = 3
HELLO = struct.Struct(">4sBB32s16s")
SESSION_KEY_SIZE = 32


def _raw_public_bytes(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def create_hello() -> tuple[X25519PrivateKey, bytes]:
    private_key = X25519PrivateKey.generate()
    hello = HELLO.pack(
        HELLO_MAGIC,
        SESSION_MAJOR,
        SESSION_MINOR,
        _raw_public_bytes(private_key),
        secrets.token_bytes(16),
    )
    return private_key, hello


def parse_hello(raw: bytes) -> X25519PublicKey:
    if len(raw) != HELLO.size:
        raise UbinHandshakeError("incorrect UBIN handshake length")

    magic, major, minor, public_bytes, _random = HELLO.unpack(raw)
    if magic != HELLO_MAGIC:
        raise UbinHandshakeError("invalid UBIN handshake magic")
    if (major, minor) != (SESSION_MAJOR, SESSION_MINOR):
        raise UbinHandshakeError(
            f"unsupported UBIN network version {major}.{minor}"
        )

    try:
        return X25519PublicKey.from_public_bytes(public_bytes)
    except ValueError as exc:
        raise UbinHandshakeError("invalid X25519 peer public key") from exc


def derive_session_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    client_hello: bytes,
    server_hello: bytes,
) -> bytes:
    """
    Derive an application-layer UBIN session key.

    TLS authenticates/protects the transport. The ephemeral X25519 exchange
    gives UBIN its own per-connection secret without requiring the developer
    to copy a raw AES key between client and server.
    """
    shared_secret = private_key.exchange(peer_public_key)
    transcript_hash = hashlib.sha256(client_hello + server_hello).digest()

    return HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_SIZE,
        salt=transcript_hash,
        info=b"UBIN-Secure-v0.3/session-key",
    ).derive(shared_secret)


def derive_transfer_key(session_key: bytes, transfer_id: bytes) -> bytes:
    if len(session_key) != SESSION_KEY_SIZE:
        raise UbinHandshakeError("invalid UBIN session key length")
    if len(transfer_id) != 16:
        raise UbinHandshakeError("invalid UBIN transfer id length")

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=transfer_id,
        info=b"UBIN-Secure-v0.3/file-transfer-key",
    ).derive(session_key)
