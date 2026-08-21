from __future__ import annotations

import os
from typing import Any

from .core import UbinMemoryObject, UbinObject, UbinStreamObject


class Resource:
    """Uniform facade over the existing UBIN file/memory/stream objects."""

    def __init__(self, source: Any, *, name: str | None = None):
        if isinstance(source, (str, os.PathLike)):
            self._object = UbinObject(source)
        elif isinstance(source, (bytes, bytearray, memoryview)):
            self._object = UbinMemoryObject(source, name=name or "memory.bin")
        elif all(hasattr(source, attr) for attr in ("read", "seek", "tell")):
            self._object = UbinStreamObject(source, name=name or getattr(source, "name", "stream.bin"))
        else:
            raise TypeError("UBIN resource must be a path, bytes-like buffer, or seekable binary stream")

    def __enter__(self) -> "Resource":
        self._object.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        return self._object.__exit__(exc_type, exc, tb)

    @property
    def name(self):
        return self._object.name

    @property
    def size(self):
        return self._object.size

    @property
    def type(self):
        return self._object.type

    def info(self):
        return self._object.info()

    def read(self, *args, **kwargs):
        return self._object.read(*args, **kwargs)

    def read_at(self, *args, **kwargs):
        return self._object.read_at(*args, **kwargs)

    def stream(self, *args, **kwargs):
        return self._object.stream(*args, **kwargs)

    def hash(self, *args, **kwargs):
        return self._object.hash(*args, **kwargs)

    def verify(self, *args, **kwargs):
        return self._object.verify(*args, **kwargs)

    def close(self):
        return self._object.close()


def open_resource(source: Any, *, name: str | None = None) -> Resource:
    return Resource(source, name=name)


__all__ = ["Resource", "open_resource"]
