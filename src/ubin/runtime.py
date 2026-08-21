from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import _capabilities
from .sdk import CapabilityManifest, manifest_from_provider


@dataclass(frozen=True, slots=True)
class VerificationResult:
    name: str
    ok: bool
    kind: str
    provider: str
    message: str
    manifest: CapabilityManifest | None = None


class Runtime:
    def capabilities(self, *, include_plugins: bool = True):
        return _capabilities.list_capabilities(include_plugins=include_plugins)

    def info(self, name: str):
        return _capabilities.get_capability_info(name)

    def load(self, name: str) -> Any:
        return _capabilities.load_capability(name)

    def verify(self, name: str, *, load_provider: bool = False) -> VerificationResult:
        info = self.info(name)
        if info.kind == "builtin":
            return VerificationResult(
                name=info.name,
                ok=True,
                kind=info.kind,
                provider=info.provider,
                message="bundled UBIN capability is available",
            )
        if not load_provider:
            return VerificationResult(
                name=info.name,
                ok=True,
                kind=info.kind,
                provider=info.provider,
                message="provider entry point is discoverable; use load_provider=True for manifest validation",
            )
        provider = self.load(name)
        try:
            manifest = manifest_from_provider(provider)
        except (TypeError, ValueError) as exc:
            return VerificationResult(info.name, False, info.kind, info.provider, str(exc))
        import ubin

        if manifest.name != info.name:
            return VerificationResult(
                info.name,
                False,
                info.kind,
                info.provider,
                f"provider manifest name {manifest.name!r} does not match entry point {info.name!r}",
                manifest,
            )
        if not manifest.supports(ubin.__version__):
            return VerificationResult(
                info.name,
                False,
                info.kind,
                info.provider,
                f"provider does not support UBIN {ubin.__version__}",
                manifest,
            )
        return VerificationResult(
            info.name,
            True,
            info.kind,
            info.provider,
            "provider manifest is valid and compatible",
            manifest,
        )


runtime = Runtime()

__all__ = ["Runtime", "VerificationResult", "runtime"]
