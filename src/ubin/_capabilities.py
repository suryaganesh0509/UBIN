from __future__ import annotations

from dataclasses import dataclass
from importlib import import_module, metadata
import re
import sys
from typing import Any

from .errors import UbinError

ENTRY_POINT_GROUP = "ubin.capabilities"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class UbinCapabilityError(UbinError):
    """Base error for UBIN capability discovery/loading."""


class UbinCapabilityNotFound(UbinCapabilityError):
    """Requested capability is neither built in nor provided by an installed plugin."""


class UbinCapabilityConflict(UbinCapabilityError):
    """More than one installed plugin claims the same UBIN capability name."""


@dataclass(frozen=True, slots=True)
class CapabilityInfo:
    name: str
    kind: str
    provider: str
    loaded: bool
    description: str


_BUILTINS: dict[str, tuple[str, str]] = {
    "ai": ('ubin.ai', 'Provider gateway for AI capability implementations'),
    "catalog": ('ubin.catalog', 'Trusted provider catalog primitives and integrity verification'),
    "cloud": ('ubin.cloud', 'Provider gateway for cloud capability implementations'),
    "compress": ('ubin.compress', 'Streaming and in-memory compression helpers'),
    "csv": ('ubin.csv', 'CSV row IO helpers'),
    "data": ('ubin.data', 'Lightweight table operations'),
    "db": ('ubin.db', 'Lightweight SQLite database helpers'),
    "ds": ('ubin.ds', 'Core data structures'),
    "environment": ('ubin.environment', 'Reproducible UBIN project configuration and lockfiles'),
    "hash": ('ubin.hash', 'Streaming digest and verification helpers'),
    "json": ('ubin.json', 'JSON encoding and atomic file IO'),
    "math": ('ubin.math', 'Lightweight mathematical helpers'),
    "net": ('ubin.net', 'Low-level network helpers'),
    "path": ('ubin.path', 'Filesystem path helpers'),
    "permissions": ('ubin.permissions', 'Capability permission metadata'),
    "plot": ('ubin.plot', 'Dependency-free SVG line plotting plus future provider adapters'),
    "process": ('ubin.process', 'Provider-gated process execution capability'),
    "protocol": ('ubin.protocol', 'UBIN v2 draft canonical values and wire envelope'),
    "providers": ('ubin.providers', 'Provider gateway helpers and explicit provider-required errors'),
    "run": ('ubin.run', 'Parallel and asynchronous execution helpers'),
    "runtime": ('ubin.runtime', 'Capability runtime inspection and verification'),
    "sdk": ('ubin.sdk', 'Capability provider SDK and manifest contract'),
    "search": ('ubin.search', 'Search algorithms'),
    "secure": ('ubin.secure', 'Authenticated security, transport, resume, KRP, and PNG carriers'),
    "sort": ('ubin.sort', 'Sorting helpers and explicit algorithms'),
    "stats": ('ubin.stats', 'Statistical helpers'),
    "system": ('ubin.system', 'Portable system information'),
    "text": ('ubin.text', 'Text encoding and transformation helpers'),
    "ui": ('ubin.ui', 'Provider gateway for UI capability implementations'),
    "web": ('ubin.web', 'Provider-gated web capability'),
}


def _load_builtin_module(name: str) -> Any:
    # Explicit literal allowlist for bundled capabilities.
    if name == "ds":
        return import_module("ubin.ds")
    if name == "search":
        return import_module("ubin.search")
    if name == "secure":
        return import_module("ubin.secure")
    if name == "sort":
        return import_module("ubin.sort")
    if name == "ai":
        return import_module("ubin.ai")
    if name == "catalog":
        return import_module("ubin.catalog")
    if name == "cloud":
        return import_module("ubin.cloud")
    if name == "compress":
        return import_module("ubin.compress")
    if name == "csv":
        return import_module("ubin.csv")
    if name == "data":
        return import_module("ubin.data")
    if name == "db":
        return import_module("ubin.db")
    if name == "environment":
        return import_module("ubin.environment")
    if name == "hash":
        return import_module("ubin.hash")
    if name == "json":
        return import_module("ubin.json")
    if name == "math":
        return import_module("ubin.math")
    if name == "net":
        return import_module("ubin.net")
    if name == "path":
        return import_module("ubin.path")
    if name == "permissions":
        return import_module("ubin.permissions")
    if name == "plot":
        return import_module("ubin.plot")
    if name == "process":
        return import_module("ubin.process")
    if name == "protocol":
        return import_module("ubin.protocol")
    if name == "providers":
        return import_module("ubin.providers")
    if name == "run":
        return import_module("ubin.run")
    if name == "runtime":
        return import_module("ubin.runtime")
    if name == "sdk":
        return import_module("ubin.sdk")
    if name == "stats":
        return import_module("ubin.stats")
    if name == "system":
        return import_module("ubin.system")
    if name == "text":
        return import_module("ubin.text")
    if name == "ui":
        return import_module("ubin.ui")
    if name == "web":
        return import_module("ubin.web")
    raise UbinCapabilityNotFound(f"unknown bundled UBIN capability: {name!r}")


def _validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise TypeError("UBIN capability name must be a string")
    normalized = name.strip().lower()
    if not _NAME_RE.fullmatch(normalized):
        raise UbinCapabilityNotFound(f"invalid UBIN capability name: {name!r}")
    return normalized


def _entry_points_for(name: str | None = None):
    if name is None:
        return tuple(metadata.entry_points(group=ENTRY_POINT_GROUP))
    return tuple(metadata.entry_points(group=ENTRY_POINT_GROUP, name=name))


def _builtin_info(name: str) -> CapabilityInfo | None:
    builtin = _BUILTINS.get(name)
    if builtin is None:
        return None
    module_name, description = builtin
    return CapabilityInfo(
        name=name,
        kind="builtin",
        provider=module_name,
        loaded=module_name in sys.modules,
        description=description,
    )


def list_capabilities(*, include_plugins: bool = True) -> tuple[CapabilityInfo, ...]:
    items = [
        info
        for name in sorted(_BUILTINS)
        if (info := _builtin_info(name)) is not None
    ]

    if include_plugins:
        seen: set[str] = set(_BUILTINS)
        for entry_point in sorted(_entry_points_for(), key=lambda ep: (ep.name, ep.value)):
            name = entry_point.name.strip().lower()
            if not _NAME_RE.fullmatch(name) or name in seen:
                continue
            seen.add(name)
            dist_name = getattr(getattr(entry_point, "dist", None), "name", None)
            items.append(
                CapabilityInfo(
                    name=name,
                    kind="plugin",
                    provider=dist_name or entry_point.value,
                    loaded=False,
                    description=f"Installed UBIN capability plugin: {entry_point.value}",
                )
            )

    return tuple(items)


def get_capability_info(name: str) -> CapabilityInfo:
    """Describe one bundled or installed capability without loading provider code."""
    normalized = _validate_name(name)

    builtin = _builtin_info(normalized)
    if builtin is not None:
        return builtin

    matches = _entry_points_for(normalized)
    if not matches:
        raise UbinCapabilityNotFound(
            f"UBIN capability {normalized!r} is not built in and no installed provider registered it"
        )
    if len(matches) > 1:
        providers = ", ".join(sorted(ep.value for ep in matches))
        raise UbinCapabilityConflict(
            f"multiple installed providers claim UBIN capability {normalized!r}: {providers}"
        )

    entry_point = matches[0]
    dist_name = getattr(getattr(entry_point, "dist", None), "name", None)
    return CapabilityInfo(
        name=normalized,
        kind="plugin",
        provider=dist_name or entry_point.value,
        loaded=False,
        description=f"Installed UBIN capability plugin: {entry_point.value}",
    )


def load_capability(name: str) -> Any:
    normalized = _validate_name(name)
    if normalized in _BUILTINS:
        return _load_builtin_module(normalized)

    matches = _entry_points_for(normalized)
    if not matches:
        raise UbinCapabilityNotFound(
            f"UBIN capability {normalized!r} is not built in and no installed provider registered it"
        )
    if len(matches) > 1:
        providers = ", ".join(sorted(ep.value for ep in matches))
        raise UbinCapabilityConflict(
            f"multiple installed providers claim UBIN capability {normalized!r}: {providers}"
        )
    return matches[0].load()


__all__ = [
    "CapabilityInfo",
    "UbinCapabilityError",
    "UbinCapabilityNotFound",
    "UbinCapabilityConflict",
    "get_capability_info",
    "list_capabilities",
    "load_capability",
]
