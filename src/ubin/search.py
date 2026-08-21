from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any, TypeVar

T = TypeVar("T")


def linear(values: Iterable[T], target: Any, *, key: Callable[[T], Any] | None = None) -> int:
    """Return the first matching index, or -1 when *target* is not present.

    With ``key``, ``target`` is compared against ``key(value)``.
    The iterable is consumed once and is never materialized by UBIN.
    """
    if key is None:
        for index, value in enumerate(values):
            if value == target:
                return index
    else:
        for index, value in enumerate(values):
            if key(value) == target:
                return index
    return -1


def binary(
    values: Sequence[T],
    target: Any,
    *,
    key: Callable[[T], Any] | None = None,
    lo: int = 0,
    hi: int | None = None,
) -> int:
    """Binary-search a sorted sequence and return a matching index or -1.

    ``hi`` is exclusive, matching Python slicing conventions. With ``key``,
    ``target`` is interpreted in the key's comparison space.
    """
    length = len(values)
    if hi is None:
        hi = length
    if lo < 0 or hi < lo or hi > length:
        raise ValueError("binary-search bounds must satisfy 0 <= lo <= hi <= len(values)")

    while lo < hi:
        mid = lo + (hi - lo) // 2
        value = values[mid]
        probe = value if key is None else key(value)
        if probe < target:
            lo = mid + 1
        elif probe > target:
            hi = mid
        else:
            return mid
    return -1


__all__ = ["linear", "binary"]
