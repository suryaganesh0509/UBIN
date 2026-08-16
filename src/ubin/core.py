from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import threading
from typing import Iterator

from .detect import detect_type
from .errors import (
    UbinClosed,
    UbinInvalidRange,
    UbinNotAFile,
    UbinNotFound,
    UbinPermissionDenied,
)


DEFAULT_BLOCK_SIZE = 1024 * 1024       # 1 MiB
PROBE_SIZE = 64                       # fixed/bounded type probe


@dataclass(frozen=True, slots=True)
class UbinInfo:
    name: str
    path: str
    size: int
    type: str


class UbinObject:
    """
    Lazy, read-only universal binary view over a regular filesystem file.

    UBIN 0.1 deliberately does not load the full source into memory.
    """

    __slots__ = (
        "_path",
        "_file",
        "_fd",
        "_size",
        "_type",
        "_closed",
        "_cursor_lock",
    )

    def __init__(self, source: str | os.PathLike[str]):
        path = Path(source).expanduser()

        if not path.exists():
            raise UbinNotFound(str(path))
        if not path.is_file():
            raise UbinNotAFile(str(path))

        try:
            file_obj = path.open("rb", buffering=0)
        except PermissionError as exc:
            raise UbinPermissionDenied(str(path)) from exc

        try:
            stat = path.stat()
            prefix = file_obj.read(PROBE_SIZE)
            file_obj.seek(0)
        except Exception:
            file_obj.close()
            raise

        self._path = path
        self._file = file_obj
        self._fd = file_obj.fileno()
        self._size = stat.st_size
        self._type = detect_type(prefix)
        self._closed = False
        self._cursor_lock = threading.RLock()

    def _ensure_open(self) -> None:
        if self._closed:
            raise UbinClosed(f"UBIN source is closed: {self._path}")

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def path(self) -> Path:
        return self._path

    @property
    def size(self) -> int:
        return self._size

    @property
    def type(self) -> str:
        return self._type

    @property
    def closed(self) -> bool:
        return self._closed

    def info(self) -> UbinInfo:
        self._ensure_open()
        return UbinInfo(
            name=self.name,
            path=str(self._path),
            size=self._size,
            type=self._type,
        )

    def read(self, length: int) -> bytes:
        """
        Read at most `length` bytes from the object's sequential cursor.

        Requiring an explicit length is intentional: UBIN does not silently
        load an arbitrarily large file into memory.
        """
        self._ensure_open()
        if length < 0:
            raise UbinInvalidRange("length must be >= 0")
        with self._cursor_lock:
            return self._file.read(length)

    def seek(self, offset: int) -> int:
        self._ensure_open()
        if offset < 0:
            raise UbinInvalidRange("offset must be >= 0")
        with self._cursor_lock:
            return self._file.seek(offset)

    def tell(self) -> int:
        self._ensure_open()
        with self._cursor_lock:
            return self._file.tell()

    def read_at(self, offset: int, length: int) -> bytes:
        """
        Positioned read that does not intentionally change the sequential cursor.

        Uses os.pread where the platform provides it; otherwise uses a
        lock-protected seek/read/restore fallback.
        """
        self._ensure_open()
        if offset < 0 or length < 0:
            raise UbinInvalidRange("offset and length must be >= 0")
        if length == 0 or offset >= self._size:
            return b""

        if hasattr(os, "pread"):
            return os.pread(self._fd, length, offset)

        with self._cursor_lock:
            current = self._file.tell()
            try:
                self._file.seek(offset)
                return self._file.read(length)
            finally:
                self._file.seek(current)

    def stream(
        self,
        block_size: int = DEFAULT_BLOCK_SIZE,
        *,
        start: int = 0,
    ) -> Iterator[bytes]:
        """
        Stream from `start` to EOF with bounded memory.
        """
        self._ensure_open()
        if block_size <= 0:
            raise UbinInvalidRange("block_size must be > 0")
        if start < 0:
            raise UbinInvalidRange("start must be >= 0")

        offset = start
        while offset < self._size:
            block = self.read_at(offset, min(block_size, self._size - offset))
            if not block:
                break
            yield block
            offset += len(block)

    def bytes(self, *, max_bytes: int | None = None) -> bytes:
        """
        Explicit whole-object materialization.

        `max_bytes` can be used as a safety ceiling.
        """
        self._ensure_open()
        if max_bytes is not None:
            if max_bytes < 0:
                raise UbinInvalidRange("max_bytes must be >= 0")
            if self._size > max_bytes:
                raise UbinInvalidRange(
                    f"source is {self._size} bytes; exceeds max_bytes={max_bytes}"
                )
        return b"".join(self.stream())

    def hash(
        self,
        algorithm: str = "sha256",
        *,
        block_size: int = DEFAULT_BLOCK_SIZE,
    ) -> str:
        """
        Hash in one bounded-memory streaming pass.
        """
        self._ensure_open()
        if block_size <= 0:
            raise UbinInvalidRange("block_size must be > 0")

        try:
            digest = hashlib.new(algorithm)
        except ValueError as exc:
            raise ValueError(f"unsupported hash algorithm: {algorithm}") from exc

        for block in self.stream(block_size):
            digest.update(block)
        return digest.hexdigest()

    def verify(self, expected_hex_digest: str, algorithm: str = "sha256") -> bool:
        actual = self.hash(algorithm)
        return hmac.compare_digest(
            actual.lower(),
            expected_hex_digest.strip().lower(),
        )

    def close(self) -> None:
        if not self._closed:
            self._file.close()
            self._closed = True

    def __enter__(self) -> "UbinObject":
        self._ensure_open()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
