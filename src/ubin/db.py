from __future__ import annotations

import sqlite3
from pathlib import Path


def connect(path="ubindata.sqlite3"):
    return sqlite3.connect(Path(path))


def query(connection, sql: str, parameters=()):
    cursor = connection.execute(sql, parameters)
    return cursor.fetchall()


def execute(connection, sql: str, parameters=()):
    cursor = connection.execute(sql, parameters)
    connection.commit()
    return cursor.rowcount

__all__ = ["connect", "query", "execute"]
