#!/usr/bin/env python3
"""Coverage-guided Atheris harness for UBIN KRP round-trip invariants."""
from __future__ import annotations

import hashlib
import sys

import atheris

with atheris.instrument_imports():
    from ubin.secure.krp import permute_blocks, restore_blocks


def TestOneInput(data: bytes) -> None:
    if not data:
        return

    key = hashlib.sha256(b"UBIN-fuzz-key" + data[:64]).digest()
    context = hashlib.sha256(b"UBIN-fuzz-context" + data[-64:]).digest()
    payload = data[1:]
    block_size = 1 + data[0] % 64

    transformed = permute_blocks(
        payload,
        key,
        context=context,
        block_size=block_size,
    )
    restored = restore_blocks(
        transformed,
        key,
        context=context,
        block_size=block_size,
    )

    if len(transformed) != len(payload):
        raise RuntimeError("KRP changed payload length")
    if restored != payload:
        raise RuntimeError("KRP round trip changed bytes")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
