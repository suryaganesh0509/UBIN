from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

from .core import UbinInfo, UbinMemoryObject, UbinObject, UbinStreamObject
from .version import VERSION as __version__, VERSION_INFO as version_info
from .errors import (
    UbinAuthenticationError,
    UbinCarrierError,
    UbinClosed,
    UbinCorruptionError,
    UbinError,
    UbinHandshakeError,
    UbinInvalidHeader,
    UbinInvalidRange,
    UbinKeyError,
    UbinNetworkError,
    UbinNotAFile,
    UbinNotFound,
    UbinOutputExists,
    UbinPermissionDenied,
    UbinProtocolError,
    UbinResumeError,
    UbinResumeTicketError,
    UbinSecureError,
    UbinSourceChanged,
    UbinTLSVerificationError,
)

# Bundled universal capability namespaces. These modules are intentionally not
# imported during bare ``import ubin``.
_BUILTIN_CAPABILITY_MODULES = {
    "search": ".search",
    "sort": ".sort",
    "ds": ".ds",
    "ai": ".ai",
    "catalog": ".catalog",
    "cloud": ".cloud",
    "compress": ".compress",
    "csv": ".csv",
    "data": ".data",
    "db": ".db",
    "environment": ".environment",
    "hash": ".hash",
    "json": ".json",
    "math": ".math",
    "net": ".net",
    "path": ".path",
    "permissions": ".permissions",
    "plot": ".plot",
    "process": ".process",
    "providers": ".providers",
    "protocol": ".protocol",
    "run": ".run",
    "runtime": ".runtime",
    "sdk": ".sdk",
    "stats": ".stats",
    "system": ".system",
    "text": ".text",
    "ui": ".ui",
    "web": ".web",
}


def _load_builtin_capability(name: str):
    # Explicit literal allowlist; kept SAST-verifiable.
    if name == "search":
        return import_module(".search", __name__)
    if name == "sort":
        return import_module(".sort", __name__)
    if name == "ds":
        return import_module(".ds", __name__)
    if name == "ai":
        return import_module(".ai", __name__)
    if name == "catalog":
        return import_module(".catalog", __name__)
    if name == "cloud":
        return import_module(".cloud", __name__)
    if name == "compress":
        return import_module(".compress", __name__)
    if name == "csv":
        return import_module(".csv", __name__)
    if name == "data":
        return import_module(".data", __name__)
    if name == "db":
        return import_module(".db", __name__)
    if name == "environment":
        return import_module(".environment", __name__)
    if name == "hash":
        return import_module(".hash", __name__)
    if name == "json":
        return import_module(".json", __name__)
    if name == "math":
        return import_module(".math", __name__)
    if name == "net":
        return import_module(".net", __name__)
    if name == "path":
        return import_module(".path", __name__)
    if name == "permissions":
        return import_module(".permissions", __name__)
    if name == "plot":
        return import_module(".plot", __name__)
    if name == "process":
        return import_module(".process", __name__)
    if name == "providers":
        return import_module(".providers", __name__)
    if name == "protocol":
        return import_module(".protocol", __name__)
    if name == "run":
        return import_module(".run", __name__)
    if name == "runtime":
        return import_module(".runtime", __name__)
    if name == "sdk":
        return import_module(".sdk", __name__)
    if name == "stats":
        return import_module(".stats", __name__)
    if name == "system":
        return import_module(".system", __name__)
    if name == "text":
        return import_module(".text", __name__)
    if name == "ui":
        return import_module(".ui", __name__)
    if name == "web":
        return import_module(".web", __name__)
    raise KeyError(name)

# Names that existed at the top level in v1.0.5 because ``ubin.secure`` was
# eagerly imported. Keep them source-compatible while loading security only on
# first use.
_SECURE_LAZY_ATTRS = {
    "SecureSource",
    "SecureServer",
    "ImageCarrierReceipt",
    "ImageRestoreReceipt",
    "create_image_carrier",
    "decrypt_file",
    "restore_image_carrier",
}


def open(source, *, name=None):
    """
    Public UBIN entry point for paths, bytes-like buffers, or seekable binary streams.

    Examples:
        ubin.open("anything.bin")
        ubin.open(b"raw bytes", name="packet.bin")
        ubin.open(io.BytesIO(b"stream bytes"), name="stream.bin")
    """
    import os

    if isinstance(source, (str, os.PathLike)):
        return UbinObject(source)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return UbinMemoryObject(source, name=name or "memory.bin")
    if all(hasattr(source, attr) for attr in ("read", "seek", "tell")):
        return UbinStreamObject(source, name=name or getattr(source, "name", "stream.bin"))
    raise TypeError("UBIN source must be a path, bytes-like buffer, or seekable binary stream")


def _load_secure_attr(name: str):
    module = import_module(".secure", __name__)
    # v1.0.6 makes the secure package itself callable. Once loaded, Python may
    # replace the initial lightweight ``secure`` function with that module, but
    # ``ubin.secure(...)`` remains valid and direct legacy submodule imports also
    # keep working.
    value = getattr(module, name)
    globals()[name] = value
    return value


def _secure_call(source, *, key=None):
    """
    Create a UBIN Secure source.

    Security implementation loading is deferred until this call is used.
    Existing v1 local/network/resume/KRP behavior remains behind the same API.
    """
    secure_source = _load_secure_attr("SecureSource")
    return secure_source(source, key=key)


# Public compatibility name before the secure namespace has been loaded. After
# first security use, the callable ``ubin.secure`` module becomes this attribute.
secure = _secure_call


def decrypt(secure_source, destination, *, key, overwrite=False):
    """Restore an authenticated UBIN Secure container."""
    decrypt_file = _load_secure_attr("decrypt_file")
    return decrypt_file(
        secure_source,
        destination,
        key=key,
        overwrite=overwrite,
    )


def secure_server(
    *,
    host="127.0.0.1",
    port=0,
    certfile,
    keyfile,
    output_dir,
    timeout=20.0,
    overwrite=False,
    client_ca=None,
    resume_state_dir=None,
):
    """Create a UBIN Secure server supporting the existing v1 transfer modes."""
    secure_server_type = _load_secure_attr("SecureServer")
    return secure_server_type(
        host=host,
        port=port,
        certfile=certfile,
        keyfile=keyfile,
        output_dir=output_dir,
        timeout=timeout,
        overwrite=overwrite,
        client_ca=client_ca,
        resume_state_dir=resume_state_dir,
    )


def to_image(
    source,
    destination,
    *,
    passphrase,
    frame_size=1024 * 1024,
    krp_block_size=4096,
    width=1024,
    overwrite=False,
):
    """Create a lossless authenticated UBIN v1 PNG carrier."""
    create_image_carrier = _load_secure_attr("create_image_carrier")
    return create_image_carrier(
        source,
        destination,
        passphrase=passphrase,
        frame_size=frame_size,
        krp_block_size=krp_block_size,
        width=width,
        overwrite=overwrite,
    )


def from_image(
    carrier,
    destination=None,
    *,
    passphrase,
    krp_block_size=4096,
    overwrite=False,
):
    """Restore a file from a lossless authenticated UBIN v1 PNG carrier."""
    restore_image_carrier = _load_secure_attr("restore_image_carrier")
    return restore_image_carrier(
        carrier,
        destination,
        passphrase=passphrase,
        krp_block_size=krp_block_size,
        overwrite=overwrite,
    )


def resource(source, *, name=None):
    """Open a universal UBIN resource facade without changing the stable v1 open API."""
    from ._resource import open_resource

    return open_resource(source, name=name)


def pipeline(source, *, block_size=1024 * 1024):
    """Create a bounded-memory byte pipeline."""
    from ._pipeline import pipeline as make_pipeline

    return make_pipeline(source, block_size=block_size)


def flow():
    """Create a UBIN workflow DAG."""
    from ._workflow import flow as make_flow

    return make_flow()


def doctor(*, deep=False):
    """Return a UBIN runtime diagnostic report."""
    from .diagnostics import doctor as run_doctor

    return run_doctor(deep=deep)


def capability_info(name: str):
    from ._capabilities import get_capability_info

    return get_capability_info(name)


def verify_capability(name: str, *, load_provider=False):
    from .runtime import runtime as _runtime

    return _runtime.verify(name, load_provider=load_provider)


def capabilities(*, include_plugins: bool = True):
    """Return discoverable UBIN capabilities without loading provider code."""
    from ._capabilities import list_capabilities

    return list_capabilities(include_plugins=include_plugins)


def load(name: str):
    """Explicitly resolve and cache a built-in or installed UBIN capability."""
    if name in _BUILTIN_CAPABILITY_MODULES:
        module = _load_builtin_capability(name)
        globals()[name] = module
        return module

    from ._capabilities import load_capability

    capability = load_capability(name)
    globals()[name] = capability
    return capability


def __getattr__(name: str):
    if name in _BUILTIN_CAPABILITY_MODULES:
        module = _load_builtin_capability(name)
        globals()[name] = module
        return module

    if name in _SECURE_LAZY_ATTRS:
        return _load_secure_attr(name)

    # Unknown public attributes get one chance to resolve through installed
    # UBIN capability entry points. Typos still surface as AttributeError.
    try:
        from ._capabilities import UbinCapabilityNotFound, load_capability

        capability = load_capability(name)
    except UbinCapabilityNotFound as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc

    globals()[name] = capability
    return capability


def __dir__():
    names = set(globals()) | set(__all__) | set(_BUILTIN_CAPABILITY_MODULES)
    try:
        names.update(item.name for item in capabilities())
    except Exception:
        # ``dir(ubin)`` must remain useful even if third-party package metadata
        # is malformed. Actual capability loading still reports the real error.
        pass
    return sorted(names)


if TYPE_CHECKING:
    from . import ds as ds
    from . import search as search
    from . import sort as sort
    from .secure import ImageCarrierReceipt as ImageCarrierReceipt
    from .secure import ImageRestoreReceipt as ImageRestoreReceipt
    from .secure import SecureServer as SecureServer
    from .secure import SecureSource as SecureSource


__all__ = [
    "__version__",
    "version_info",
    "open",
    "secure",
    "decrypt",
    "secure_server",
    "to_image",
    "from_image",
    "capabilities",
    "load",
    "resource",
    "pipeline",
    "flow",
    "doctor",
    "capability_info",
    "verify_capability",
    "search",
    "sort",
    "ds",
    "ai",
    "catalog",
    "cloud",
    "compress",
    "csv",
    "data",
    "db",
    "environment",
    "hash",
    "json",
    "math",
    "net",
    "path",
    "permissions",
    "plot",
    "process",
    "protocol",
    "providers",
    "run",
    "runtime",
    "sdk",
    "stats",
    "system",
    "text",
    "ui",
    "web",
    "UbinObject",
    "UbinMemoryObject",
    "UbinStreamObject",
    "UbinInfo",
    "SecureSource",
    "SecureServer",
    "ImageCarrierReceipt",
    "ImageRestoreReceipt",
    "UbinError",
    "UbinNotFound",
    "UbinNotAFile",
    "UbinPermissionDenied",
    "UbinClosed",
    "UbinInvalidRange",
    "UbinSecureError",
    "UbinInvalidHeader",
    "UbinAuthenticationError",
    "UbinCorruptionError",
    "UbinOutputExists",
    "UbinKeyError",
    "UbinNetworkError",
    "UbinProtocolError",
    "UbinHandshakeError",
    "UbinTLSVerificationError",
    "UbinResumeError",
    "UbinResumeTicketError",
    "UbinSourceChanged",
    "UbinCarrierError",
]
