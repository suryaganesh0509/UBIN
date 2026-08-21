from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
import re

ENTRY_POINT_GROUP = "ubin.providers"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")


class ProviderError(RuntimeError):
    pass


class ProviderRequired(ProviderError):
    pass


class ProviderConflict(ProviderError):
    pass


@dataclass(frozen=True, slots=True)
class ProviderInfo:
    family: str
    name: str
    entry_point: str
    distribution: str | None


def _validate(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not _NAME_RE.fullmatch(normalized):
        raise ValueError(f"invalid UBIN provider {label}: {value!r}")
    return normalized


def list(family: str | None = None) -> tuple[ProviderInfo, ...]:
    wanted = _validate(family, "family") if family is not None else None
    items: list[ProviderInfo] = []
    for entry_point in metadata.entry_points(group=ENTRY_POINT_GROUP):
        raw_name = entry_point.name.strip().lower()
        if "." not in raw_name:
            continue
        provider_family, provider_name = raw_name.split(".", 1)
        if not _NAME_RE.fullmatch(provider_family) or not _NAME_RE.fullmatch(provider_name):
            continue
        if wanted is not None and provider_family != wanted:
            continue
        distribution = getattr(getattr(entry_point, "dist", None), "name", None)
        items.append(ProviderInfo(provider_family, provider_name, entry_point.value, distribution))
    return tuple(sorted(items, key=lambda item: (item.family, item.name, item.entry_point)))


def load(family: str, name: str):
    provider_family = _validate(family, "family")
    provider_name = _validate(name, "name")
    entry_name = f"{provider_family}.{provider_name}"
    matches = tuple(metadata.entry_points(group=ENTRY_POINT_GROUP, name=entry_name))
    if not matches:
        raise ProviderRequired(
            f"no UBIN backend provider is installed for {entry_name!r}; "
            f"install an explicitly trusted provider that registers group {ENTRY_POINT_GROUP!r}"
        )
    if len(matches) > 1:
        values = ", ".join(sorted(entry.value for entry in matches))
        raise ProviderConflict(f"multiple UBIN backend providers claim {entry_name!r}: {values}")
    return matches[0].load()


__all__ = [
    "ENTRY_POINT_GROUP",
    "ProviderError",
    "ProviderRequired",
    "ProviderConflict",
    "ProviderInfo",
    "list",
    "load",
]
