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

__version__ = "0.5.0"


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

    Local v0.2 container:
        receipt = ubin.secure("file.bin").save("file.ubs")
        ubin.decrypt("file.ubs", "restored.bin", key=receipt.key)

    Network v0.3:
        ubin.secure("file.bin").send(...)

    Resumable network v0.4:
        ubin.secure("file.bin").send(..., resume=True)

    KRP layout v0.5:
        ubin.secure("file.bin").send(..., resume=True, permutation=True)
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


from .secure import SecureServer


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
    """Create a UBIN Secure server supporting v0.3-v0.5 transfer modes."""
    return SecureServer(
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
