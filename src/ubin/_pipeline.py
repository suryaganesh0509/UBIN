from __future__ import annotations

from collections.abc import Callable
import hashlib
import os
from pathlib import Path
import tempfile
from typing import Any

from ._resource import Resource

ByteStage = Callable[[bytes], bytes]


class Pipeline:
    """Bounded-memory byte pipeline. Stages operate independently on each chunk."""

    def __init__(self, source: Any, *, block_size: int = 1024 * 1024):
        if block_size <= 0:
            raise ValueError("block_size must be positive")
        self.source = source
        self.block_size = block_size
        self._stages: list[ByteStage] = []

    def map_bytes(self, stage: ByteStage) -> "Pipeline":
        if not callable(stage):
            raise TypeError("stage must be callable")
        self._stages.append(stage)
        return self

    def chunks(self):
        with Resource(self.source) as resource:
            for chunk in resource.stream(block_size=self.block_size):
                value = bytes(chunk)
                for stage in self._stages:
                    value = stage(value)
                    if not isinstance(value, bytes):
                        raise TypeError("pipeline byte stages must return bytes")
                yield value

    def digest(self, algorithm: str = "sha256") -> str:
        digest = hashlib.new(algorithm)
        for chunk in self.chunks():
            digest.update(chunk)
        return digest.hexdigest()

    def write(self, destination: str | os.PathLike[str], *, overwrite: bool = False) -> Path:
        destination = Path(destination)
        if destination.exists() and not overwrite:
            raise FileExistsError(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".ubin-part", dir=destination.parent)
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                for chunk in self.chunks():
                    handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())
            if destination.exists() and not overwrite:
                raise FileExistsError(destination)
            os.replace(temp, destination)
            return destination
        except Exception:
            temp.unlink(missing_ok=True)
            raise


def pipeline(source: Any, *, block_size: int = 1024 * 1024) -> Pipeline:
    return Pipeline(source, block_size=block_size)


__all__ = ["Pipeline", "pipeline"]
