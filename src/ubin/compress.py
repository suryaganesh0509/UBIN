from __future__ import annotations

import gzip
import os
from pathlib import Path
import tempfile


def gzip_bytes(data, *, compresslevel=9) -> bytes:
    return gzip.compress(bytes(data), compresslevel=compresslevel, mtime=0)


def gunzip_bytes(data) -> bytes:
    return gzip.decompress(bytes(data))


def gzip_file(source, destination, *, compresslevel=9, overwrite=False, block_size=1024 * 1024) -> Path:
    source = Path(source)
    destination = Path(destination)
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".ubin-part", dir=destination.parent)
    os.close(fd)
    temp = Path(temp_name)
    try:
        with source.open("rb") as src, temp.open("wb") as raw_dst:
            with gzip.GzipFile(fileobj=raw_dst, mode="wb", compresslevel=compresslevel, mtime=0) as dst:
                for chunk in iter(lambda: src.read(block_size), b""):
                    dst.write(chunk)
        if destination.exists() and not overwrite:
            raise FileExistsError(destination)
        os.replace(temp, destination)
        return destination
    except Exception:
        temp.unlink(missing_ok=True)
        raise

__all__ = ["gzip_bytes", "gunzip_bytes", "gzip_file"]
