from __future__ import annotations

import json as _json
import os
from pathlib import Path
import tempfile


def loads(value: str | bytes | bytearray):
    return _json.loads(value)


def dumps(value, *, pretty: bool = False, sort_keys: bool = True) -> str:
    return _json.dumps(value, indent=2 if pretty else None, sort_keys=sort_keys, separators=None if pretty else (",", ":"))


def read(path):
    return _json.loads(Path(path).read_text(encoding="utf-8"))


def write(path, value, *, pretty: bool = True, overwrite: bool = False) -> Path:
    target = Path(path)
    if target.exists() and not overwrite:
        raise FileExistsError(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".ubin-part", dir=target.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(dumps(value, pretty=pretty))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if target.exists() and not overwrite:
            raise FileExistsError(target)
        os.replace(temp, target)
        return target
    except Exception:
        temp.unlink(missing_ok=True)
        raise

__all__ = ["loads", "dumps", "read", "write"]
