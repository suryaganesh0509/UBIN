from __future__ import annotations

import hashlib
from ._resource import Resource


def digest(source, algorithm="sha256", *, block_size=1024 * 1024) -> str:
    h = hashlib.new(algorithm)
    with Resource(source) as resource:
        for chunk in resource.stream(block_size=block_size):
            h.update(chunk)
    return h.hexdigest()


def verify(source, expected: str, algorithm="sha256") -> bool:
    return digest(source, algorithm).lower() == expected.lower()

__all__ = ["digest", "verify"]
