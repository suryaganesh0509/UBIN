from __future__ import annotations

from .core import UbinInfo, UbinObject
from .errors import (
    UbinClosed,
    UbinError,
    UbinInvalidRange,
    UbinNotAFile,
    UbinNotFound,
    UbinPermissionDenied,
)

__version__ = "0.2.0"


def open(source) -> UbinObject:
    """
    Public UBIN entry point.

    Example:
        import ubin
        with ubin.open("anything.bin") as x:
            print(x.info())
    """
    return UbinObject(source)


__all__ = [
    "open",
    "UbinObject",
    "UbinInfo",
    "UbinError",
    "UbinNotFound",
    "UbinNotAFile",
    "UbinPermissionDenied",
    "UbinClosed",
    "UbinInvalidRange",
]


from .secure import SecureSource, decrypt_file


def secure(source, *, key=None) -> SecureSource:
    """
    Create a UBIN Secure source.

    Phase 0.2 is local-only:
        receipt = ubin.secure("file.bin").save("file.ubs")
        ubin.decrypt("file.ubs", "restored.bin", key=receipt.key)

    Phase 0.3 will replace manual key handoff with a secure client/server session.
    """
    return SecureSource(source, key=key)


def decrypt(secure_source, destination, *, key, overwrite=False):
    """Restore an authenticated UBIN Secure 0.2 container."""
    return decrypt_file(
        secure_source,
        destination,
        key=key,
        overwrite=overwrite,
    )
