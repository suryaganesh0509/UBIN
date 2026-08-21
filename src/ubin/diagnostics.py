from __future__ import annotations

from dataclasses import asdict, dataclass
from importlib.util import find_spec
import platform
from typing import Any

from .runtime import Runtime


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True, slots=True)
class DiagnosticReport:
    ubin_version: str
    python_version: str
    platform: str
    checks: tuple[DiagnosticCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.ok for check in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ubin_version": self.ubin_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "healthy": self.healthy,
            "checks": [asdict(check) for check in self.checks],
        }


def doctor(*, deep: bool = False) -> DiagnosticReport:
    import ubin

    runtime = Runtime()
    checks: list[DiagnosticCheck] = []
    try:
        caps = runtime.capabilities()
        checks.append(DiagnosticCheck("capability_registry", True, f"{len(caps)} capabilities discoverable"))
    except Exception as exc:
        checks.append(DiagnosticCheck("capability_registry", False, f"{type(exc).__name__}: {exc}"))
        caps = ()

    checks.append(
        DiagnosticCheck(
            "security_dependency",
            find_spec("cryptography") is not None,
            "cryptography available" if find_spec("cryptography") is not None else "cryptography is not installed",
        )
    )

    if deep:
        for info in caps:
            try:
                result = runtime.verify(info.name, load_provider=info.kind != "builtin")
                checks.append(DiagnosticCheck(f"capability:{info.name}", result.ok, result.message))
            except Exception as exc:
                checks.append(DiagnosticCheck(f"capability:{info.name}", False, f"{type(exc).__name__}: {exc}"))

    return DiagnosticReport(
        ubin_version=ubin.__version__,
        python_version=platform.python_version(),
        platform=platform.platform(),
        checks=tuple(checks),
    )


__all__ = ["DiagnosticCheck", "DiagnosticReport", "doctor"]
