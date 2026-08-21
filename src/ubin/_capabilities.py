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
    "ds": ("ubin.ds", "Core data structures"),
    "search": ("ubin.search", "Search algorithms"),
    "secure": ("ubin.secure", "Authenticated security, transport, resume, KRP, and PNG carriers"),
    "sort": ("ubin.sort", "Sorting helpers and explicit algorithms"),
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
