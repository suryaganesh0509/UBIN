from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Any


@dataclass(frozen=True)
class Table:
    rows: tuple[dict[str, Any], ...]

    @classmethod
    def from_rows(cls, rows: Iterable[Mapping[str, Any]]) -> "Table":
        return cls(tuple(dict(row) for row in rows))

    def select(self, *columns: str) -> "Table":
        return Table(tuple({name: row.get(name) for name in columns} for row in self.rows))

    def where(self, predicate: Callable[[Mapping[str, Any]], bool]) -> "Table":
        return Table(tuple(row for row in self.rows if predicate(row)))

    def column(self, name: str) -> list[Any]:
        return [row.get(name) for row in self.rows]

    def __len__(self) -> int:
        return len(self.rows)


def table(rows: Iterable[Mapping[str, Any]]) -> Table:
    return Table.from_rows(rows)


def read_csv(path) -> Table:
    from .csv import read_rows
    return Table.from_rows(read_rows(path))

__all__ = ["Table", "table", "read_csv"]
