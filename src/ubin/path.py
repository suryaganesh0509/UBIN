from __future__ import annotations

from pathlib import Path


def exists(path) -> bool:
    return Path(path).exists()


def is_file(path) -> bool:
    return Path(path).is_file()


def size(path) -> int:
    return Path(path).stat().st_size


def walk(path):
    root = Path(path)
    return tuple(sorted(item for item in root.rglob("*") if item.is_file()))


def join(*parts) -> Path:
    return Path(parts[0]).joinpath(*parts[1:])

__all__ = ["exists", "is_file", "size", "walk", "join"]
