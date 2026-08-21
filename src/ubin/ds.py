from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Generic, Hashable, Iterator, TypeVar

T = TypeVar("T")
H = TypeVar("H", bound=Hashable)


class Stack(Generic[T]):
    """Small list-backed LIFO stack."""

    __slots__ = ("_items",)

    def __init__(self, values=()):
        self._items = list(values)

    def push(self, value: T) -> None:
        self._items.append(value)

    def pop(self) -> T:
        if not self._items:
            raise IndexError("pop from empty UBIN Stack")
        return self._items.pop()

    def peek(self) -> T:
        if not self._items:
            raise IndexError("peek from empty UBIN Stack")
        return self._items[-1]

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return bool(self._items)

    def __iter__(self) -> Iterator[T]:
        return iter(self._items)


class Queue(Generic[T]):
    """Deque-backed FIFO queue with O(1) endpoint operations."""

    __slots__ = ("_items",)

    def __init__(self, values=()):
        self._items = deque(values)

    def enqueue(self, value: T) -> None:
        self._items.append(value)

    def dequeue(self) -> T:
        if not self._items:
            raise IndexError("dequeue from empty UBIN Queue")
        return self._items.popleft()

    def peek(self) -> T:
        if not self._items:
            raise IndexError("peek from empty UBIN Queue")
        return self._items[0]

    def __len__(self) -> int:
        return len(self._items)

    def __bool__(self) -> bool:
        return bool(self._items)

    def __iter__(self) -> Iterator[T]:
        return iter(self._items)


@dataclass(slots=True)
class _BSTNode(Generic[T]):
    value: T
    left: "_BSTNode[T] | None" = None
    right: "_BSTNode[T] | None" = None


class BinarySearchTree(Generic[T]):
    """Unbalanced binary-search tree with iterative insert/search/traversal."""

    __slots__ = ("_root", "_size")

    def __init__(self, values=()):
        self._root: _BSTNode[T] | None = None
        self._size = 0
        for value in values:
            self.insert(value)

    def insert(self, value: T) -> None:
        node = _BSTNode(value)
        if self._root is None:
            self._root = node
            self._size = 1
            return

        current = self._root
        while True:
            if value < current.value:
                if current.left is None:
                    current.left = node
                    break
                current = current.left
            else:
                if current.right is None:
                    current.right = node
                    break
                current = current.right
        self._size += 1

    def __contains__(self, value: object) -> bool:
        current = self._root
        while current is not None:
            if value == current.value:
                return True
            try:
                current = current.left if value < current.value else current.right  # type: ignore[operator]
            except TypeError:
                return False
        return False

    def inorder(self) -> list[T]:
        result: list[T] = []
        stack: list[_BSTNode[T]] = []
        current = self._root
        while current is not None or stack:
            while current is not None:
                stack.append(current)
                current = current.left
            current = stack.pop()
            result.append(current.value)
            current = current.right
        return result

    def __len__(self) -> int:
        return self._size


BinaryTree = BinarySearchTree


class Graph(Generic[H]):
    """Deterministic adjacency-list graph using insertion-ordered dictionaries."""

    __slots__ = ("directed", "_adj")

    def __init__(self, *, directed: bool = False):
        self.directed = directed
        self._adj: dict[H, dict[H, None]] = {}

    def add_node(self, node: H) -> None:
        self._adj.setdefault(node, {})

    def add_edge(self, source: H, target: H) -> None:
        self.add_node(source)
        self.add_node(target)
        self._adj[source][target] = None
        if not self.directed:
            self._adj[target][source] = None

    def neighbors(self, node: H) -> tuple[H, ...]:
        if node not in self._adj:
            raise KeyError(node)
        return tuple(self._adj[node])

    def bfs(self, start: H) -> list[H]:
        if start not in self._adj:
            raise KeyError(start)
        seen = {start}
        order: list[H] = []
        pending = deque([start])
        while pending:
            node = pending.popleft()
            order.append(node)
            for neighbor in self._adj[node]:
                if neighbor not in seen:
                    seen.add(neighbor)
                    pending.append(neighbor)
        return order

    def dfs(self, start: H) -> list[H]:
        if start not in self._adj:
            raise KeyError(start)
        seen: set[H] = set()
        order: list[H] = []
        pending = [start]
        while pending:
            node = pending.pop()
            if node in seen:
                continue
            seen.add(node)
            order.append(node)
            pending.extend(reversed(tuple(self._adj[node])))
        return order

    def __contains__(self, node: object) -> bool:
        return node in self._adj

    def __len__(self) -> int:
        return len(self._adj)


__all__ = ["Stack", "Queue", "BinarySearchTree", "BinaryTree", "Graph"]
