from __future__ import annotations

def decode(data, encoding="utf-8", errors="strict"):
    return bytes(data).decode(encoding, errors)

def encode(text: str, encoding="utf-8", errors="strict") -> bytes:
    return text.encode(encoding, errors)

def find(text: str, needle: str, start: int = 0) -> int:
    return text.find(needle, start)

def replace(text: str, old: str, new: str, count: int = -1) -> str:
    return text.replace(old, new, count)

__all__ = ["decode", "encode", "find", "replace"]
