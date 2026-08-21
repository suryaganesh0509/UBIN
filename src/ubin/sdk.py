from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Protocol, runtime_checkable

from .permissions import PermissionManifest

_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$")


def _version_tuple(value: str) -> tuple[int, int, int]:
    core = value.split("-", 1)[0].split("+", 1)[0]
    parts = core.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid UBIN version: {value!r}")
    return tuple(int(part) for part in parts)  # type: ignore[return-value]


@dataclass(frozen=True, slots=True)
class CapabilityManifest:
    name: str
    version: str
    description: str = ""
    api_version: str = "1"
    min_ubin: str = "2.0.0"
    max_ubin_exclusive: str = "3.0.0"
    permissions: PermissionManifest = PermissionManifest()

    def validate(self) -> "CapabilityManifest":
        if not _NAME_RE.fullmatch(self.name):
            raise ValueError(f"invalid UBIN capability name: {self.name!r}")
        if not _VERSION_RE.fullmatch(self.version):
            raise ValueError(f"invalid capability version: {self.version!r}")
        if self.api_version != "1":
            raise ValueError(f"unsupported UBIN capability API version: {self.api_version!r}")
        low = _version_tuple(self.min_ubin)
        high = _version_tuple(self.max_ubin_exclusive)
        if low >= high:
            raise ValueError("min_ubin must be lower than max_ubin_exclusive")
        return self

    def supports(self, ubin_version: str) -> bool:
        current = _version_tuple(ubin_version)
        return _version_tuple(self.min_ubin) <= current < _version_tuple(self.max_ubin_exclusive)


@runtime_checkable
class CapabilityProvider(Protocol):
    UBIN_CAPABILITY: CapabilityManifest


def manifest_from_provider(provider: Any) -> CapabilityManifest:
    manifest = getattr(provider, "UBIN_CAPABILITY", None)
    if not isinstance(manifest, CapabilityManifest):
        raise TypeError("provider must expose UBIN_CAPABILITY as CapabilityManifest")
    return manifest.validate()


__all__ = ["CapabilityManifest", "CapabilityProvider", "manifest_from_provider"]
