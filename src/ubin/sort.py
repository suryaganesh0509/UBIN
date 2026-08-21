from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, TypeVar

T = TypeVar("T")


def values(items: Iterable[T], *, key: Callable[[T], Any] | None = None, reverse: bool = False) -> list[T]:
    """Production-default ordering using Python's optimized stable sort."""
    return sorted(items, key=key, reverse=reverse)


def merge(items: Iterable[T], *, key: Callable[[T], Any] | None = None, reverse: bool = False) -> list[T]:
    """Stable bottom-up merge sort returning a new list.

    Time: O(n log n). Auxiliary memory: O(n). No recursion is used.
    """
    data = list(items)
    count = len(data)
    if count < 2:
        return data

    keys = [item if key is None else key(item) for item in data]
    out = data.copy()
    out_keys = keys.copy()
    width = 1

    def right_precedes(left_key: Any, right_key: Any) -> bool:
        return left_key < right_key if reverse else right_key < left_key

    while width < count:
        start = 0
        while start < count:
            middle = min(start + width, count)
            end = min(start + 2 * width, count)
            left = start
            right = middle
            write = start

            while left < middle and right < end:
                if right_precedes(keys[left], keys[right]):
                    out[write] = data[right]
                    out_keys[write] = keys[right]
                    right += 1
                else:
                    out[write] = data[left]
                    out_keys[write] = keys[left]
                    left += 1
                write += 1

            while left < middle:
                out[write] = data[left]
                out_keys[write] = keys[left]
                left += 1
                write += 1

            while right < end:
                out[write] = data[right]
                out_keys[write] = keys[right]
                right += 1
                write += 1

            start += 2 * width

        data, out = out, data
        keys, out_keys = out_keys, keys
        width *= 2

    return data


def quick(items: Iterable[T], *, key: Callable[[T], Any] | None = None, reverse: bool = False) -> list[T]:
    """Iterative quicksort returning a new list.

    Average time: O(n log n); worst case: O(n^2). The implementation uses an
    explicit stack rather than recursion so large inputs do not consume Python's
    recursion limit. For general production sorting, prefer ``ubin.sort.values``.
    """
    data = list(items)
    if len(data) < 2:
        return data

    keys = [item if key is None else key(item) for item in data]

    def before(a: Any, b: Any) -> bool:
        return a > b if reverse else a < b

    stack: list[tuple[int, int]] = [(0, len(data) - 1)]
    while stack:
        lo, hi = stack.pop()
        while lo < hi:
            i = lo
            j = hi
            pivot = keys[lo + (hi - lo) // 2]

            while i <= j:
                while i <= hi and before(keys[i], pivot):
                    i += 1
                while j >= lo and before(pivot, keys[j]):
                    j -= 1
                if i <= j:
                    data[i], data[j] = data[j], data[i]
                    keys[i], keys[j] = keys[j], keys[i]
                    i += 1
                    j -= 1

            # Continue with the smaller partition and stack the larger one.
            # This bounds normal stack growth even on awkward input shapes.
            left_size = j - lo
            right_size = hi - i
            if left_size < right_size:
                if i < hi:
                    stack.append((i, hi))
                hi = j
            else:
                if lo < j:
                    stack.append((lo, j))
                lo = i

    return data


__all__ = ["values", "merge", "quick"]
