from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Any


@dataclass(frozen=True, slots=True)
class PermissionManifest:
    filesystem_read: bool = False
    filesystem_write: bool = False
    network: bool = False
    subprocess: bool = False
    environment: bool = False

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | None) -> "PermissionManifest":
        if value is None:
            return cls()
        allowed = {
            "filesystem_read",
            "filesystem_write",
            "network",
            "subprocess",
            "environment",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValueError(f"unknown UBIN permission keys: {sorted(unknown)!r}")
        return cls(**{key: bool(value.get(key, False)) for key in allowed})

    def granted(self) -> tuple[str, ...]:
        return tuple(
            name
            for name in (
                "filesystem_read",
                "filesystem_write",
                "network",
                "subprocess",
                "environment",
            )
            if getattr(self, name)
        )


NONE = PermissionManifest()
READ_ONLY = PermissionManifest(filesystem_read=True)

_BUILTIN_PERMISSIONS = {
    "secure": PermissionManifest(filesystem_read=True, filesystem_write=True, network=True),
    "csv": PermissionManifest(filesystem_read=True, filesystem_write=True),
    "hash": PermissionManifest(filesystem_read=True),
    "compress": PermissionManifest(filesystem_read=True, filesystem_write=True),
    "path": PermissionManifest(filesystem_read=True),
    "db": PermissionManifest(filesystem_read=True, filesystem_write=True),
    "net": PermissionManifest(network=True),
    "web": PermissionManifest(network=True),
    "environment": PermissionManifest(filesystem_read=True, filesystem_write=True),
    "catalog": PermissionManifest(filesystem_read=True),
    "process": PermissionManifest(subprocess=True),
    "cloud": PermissionManifest(network=True, environment=True),
    "ai": PermissionManifest(network=True, environment=True),
}

def for_capability(name: str) -> PermissionManifest:
    return _BUILTIN_PERMISSIONS.get(name.strip().lower(), NONE)

__all__ = ["PermissionManifest", "NONE", "READ_ONLY", "for_capability"]
