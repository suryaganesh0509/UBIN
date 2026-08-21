from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    capability: str
    package: str
    version: str
    sha256: str
    trusted: bool = False


def load(path: str | Path) -> tuple[CatalogEntry, ...]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = []
    for item in data.get("entries", []):
        entries.append(CatalogEntry(**item))
    return tuple(entries)


def resolve(entries: tuple[CatalogEntry, ...], capability: str) -> CatalogEntry:
    matches = [item for item in entries if item.capability == capability and item.trusted]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one trusted provider for {capability!r}, found {len(matches)}")
    return matches[0]


def verify_file(path: str | Path, expected_sha256: str) -> bool:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().lower() == expected_sha256.lower()


def verify_signature(payload: bytes, signature: bytes, public_key: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)
    except (InvalidSignature, ValueError):
        return False
    return True


__all__ = ["CatalogEntry", "load", "resolve", "verify_file", "verify_signature"]
