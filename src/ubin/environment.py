from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import tempfile
from typing import Any

from .version import VERSION

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".ubin-part", dir=path.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except Exception:
        temp.unlink(missing_ok=True)
        raise


def init(path: str | os.PathLike[str] = "ubin.toml", *, overwrite: bool = False) -> Path:
    target = Path(path)
    if target.exists() and not overwrite:
        raise FileExistsError(target)
    text = f'[ubin]\nversion = "{VERSION}"\n\n[capabilities]\nsearch = "builtin"\nsort = "builtin"\nds = "builtin"\nsecure = "builtin"\n'
    _atomic_text(target, text)
    return target


def read_config(path: str | os.PathLike[str] = "ubin.toml") -> dict[str, Any]:
    with Path(path).open("rb") as handle:
        return tomllib.load(handle)


def lock(config_path: str | os.PathLike[str] = "ubin.toml", lock_path: str | os.PathLike[str] = "ubin.lock") -> Path:
    import ubin

    config = read_config(config_path)
    requested = config.get("capabilities", {})
    known = {item.name: item for item in ubin.capabilities()}
    missing = sorted(name for name in requested if name not in known)
    if missing:
        raise ValueError(f"capabilities are not available: {missing!r}")
    payload = {
        "schema": 1,
        "ubin": ubin.__version__,
        "python": platform.python_version(),
        "platform": platform.system(),
        "capabilities": {
            name: {
                "kind": known[name].kind,
                "provider": known[name].provider,
            }
            for name in sorted(requested)
        },
    }
    _atomic_text(Path(lock_path), json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return Path(lock_path)


def sync(lock_path: str | os.PathLike[str] = "ubin.lock") -> dict[str, Any]:
    import ubin

    payload = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    known = {item.name: item for item in ubin.capabilities()}
    expected = payload.get("capabilities", {})
    missing = sorted(name for name in expected if name not in known)
    changed = sorted(
        name for name, value in expected.items()
        if name in known and value.get("provider") != known[name].provider
    )
    return {"ok": not missing and not changed, "missing": missing, "changed": changed}


__all__ = ["init", "read_config", "lock", "sync"]
