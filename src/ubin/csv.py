from __future__ import annotations

import csv as _csv
import os
from pathlib import Path
import tempfile


def read_rows(path, *, encoding="utf-8") -> list[dict[str, str]]:
    with Path(path).open("r", encoding=encoding, newline="") as handle:
        return list(_csv.DictReader(handle))


def write_rows(path, rows, *, fieldnames=None, encoding="utf-8", overwrite=False) -> Path:
    rows = list(rows)
    if fieldnames is None:
        fieldnames = list(rows[0]) if rows else []
    target = Path(path)
    if target.exists() and not overwrite:
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".ubin-part", dir=target.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            writer = _csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() and not overwrite:
            raise FileExistsError(target)
        os.replace(temp, target)
        return target
    except Exception:
        temp.unlink(missing_ok=True)
        raise

__all__ = ["read_rows", "write_rows"]
